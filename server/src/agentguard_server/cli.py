from __future__ import annotations

import argparse
from datetime import datetime
import sys

from sqlalchemy import select

from agentguard_server.config import get_settings
from agentguard_server.db.session import get_session_factory
from agentguard_server.provenance import build_metadata, read_version
from agentguard_server.models import ApiKey, ArchiveRecord, ArchiveReplica, EvaluationRun, EvaluationSuite, IntegrityArchiveSegment, IntegrityCheckpoint, ReplaySession, Tenant, Trace
from agentguard_server.services.auth import SCOPES, create_api_key, create_tenant, revoke_api_key
from agentguard_server.services.integrity import verify_trace_integrity
from agentguard_server.services.replay import ReplayRefused, build_replay_plan, persist_blocked_replay, persist_replay
from agentguard_server.services.analysis import AnalysisRefused, AnalysisResourceLimit, analyze_trace, persist_analysis, persist_refused_analysis
from agentguard_server.services.evaluation import EvaluationValidationError, compare_runs
from agentguard_server.services.identity import IdentityValidationError, bootstrap_admin
from agentguard_server.services.archive import verify_stored_archive, ArchiveKeyring
from agentguard_server.services.retention import configured_archive_store, retention_status
from agentguard_server.services.replicas import list_replicas, logical_archive_health, repair_missing_replica, scrub_replica, verify_replica
from agentguard_server.services.archive_store import archive_store_registry
from agentguard_server.services.integrity_segments import (
    IntegritySegmentEligibilityError, archive_integrity_segment,
    authorize_integrity_compaction, compact_integrity_segment,
    create_integrity_segment_candidate, resolve_integrity_records,
)
from agentguard_server.services.anchoring import HttpSignedWitnessProvider
from agentguard_server.models import CheckpointQuorumEvaluation, Witness, WitnessQuorumPolicy
from agentguard_server.services.quorum import evaluate_checkpoint_quorum


def _pepper() -> str:
    settings = get_settings()
    value = (settings.key_pepper or "").strip()
    if settings.auth_enabled and (not value or value.lower().startswith(("change-me", "replace-", "generate-", "<")) or value.lower() in {"insecure", "development"}):
        raise SystemExit("AGENTGUARD_KEY_PEPPER must be configured before managing API keys")
    return value


def _parse_expiry(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"invalid --expires-at value: {value}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentguard-server", description="AgentGuard tenant and API key administration")
    parser.add_argument("--version", action="version", version=read_version())
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version", help="show safe build provenance")
    witness = commands.add_parser("witness", help="inspect V20 witness quorum state")
    witness_commands = witness.add_subparsers(dest="witness_command", required=True)
    witness_commands.add_parser("status")
    witness_commands.add_parser("quorum")
    witness_verify = witness_commands.add_parser("verify")
    witness_verify.add_argument("--checkpoint", required=True)
    tenant = commands.add_parser("tenant")
    tenant_commands = tenant.add_subparsers(dest="tenant_command", required=True)
    create_tenant_parser = tenant_commands.add_parser("create")
    create_tenant_parser.add_argument("--slug", required=True)
    create_tenant_parser.add_argument("--name", required=True)
    tenant_commands.add_parser("list")
    keys = commands.add_parser("key")
    key_commands = keys.add_subparsers(dest="key_command", required=True)
    create_key = key_commands.add_parser("create")
    create_key.add_argument("--tenant", required=True, help="tenant slug")
    create_key.add_argument("--name", required=True)
    create_key.add_argument("--scopes", required=True, help=f"comma-separated scopes: {','.join(sorted(SCOPES))}")
    create_key.add_argument("--expires-at")
    list_keys = key_commands.add_parser("list")
    list_keys.add_argument("--tenant", required=True, help="tenant slug")
    revoke = key_commands.add_parser("revoke")
    revoke.add_argument("--public-id", required=True)
    integrity = commands.add_parser("integrity")
    integrity_commands = integrity.add_subparsers(dest="integrity_command", required=True)
    verify = integrity_commands.add_parser("verify")
    verify.add_argument("--tenant", required=True, help="tenant slug")
    verify.add_argument("--trace-id", required=True)
    segments = integrity_commands.add_parser("segments")
    segment_commands = segments.add_subparsers(dest="segment_command", required=True)
    segment_list = segment_commands.add_parser("list")
    segment_list.add_argument("--tenant", required=True)
    segment_plan = segment_commands.add_parser("plan")
    segment_plan.add_argument("--tenant", required=True)
    segment_plan.add_argument("--trace-id", required=True)
    segment_verify = segment_commands.add_parser("verify")
    segment_verify.add_argument("--tenant", required=True)
    segment_verify.add_argument("--segment-id", required=True)
    segment_compact = segment_commands.add_parser("compact")
    segment_compact.add_argument("--tenant", required=True)
    segment_compact.add_argument("--segment-id", required=True)
    segment_compact.add_argument("--execute", action="store_true")
    replay = commands.add_parser("replay")
    replay_commands = replay.add_subparsers(dest="replay_command", required=True)
    replay_run = replay_commands.add_parser("run", help="run a safe dry-run replay")
    replay_run.add_argument("--tenant", required=True, help="tenant slug")
    replay_run.add_argument("--trace-id", required=True)
    analysis = commands.add_parser("analysis")
    analysis_commands = analysis.add_subparsers(dest="analysis_command", required=True)
    analysis_run = analysis_commands.add_parser("run", help="run deterministic-first failure analysis")
    analysis_run.add_argument("--tenant", required=True, help="tenant slug")
    analysis_run.add_argument("--trace-id", required=True)
    analysis_run.add_argument("--mode", choices=("deterministic", "ai_assisted"), default="deterministic")
    evaluation = commands.add_parser("eval", help="run an offline regression comparison")
    evaluation_commands = evaluation.add_subparsers(dest="evaluation_command", required=True)
    evaluation_compare = evaluation_commands.add_parser("compare", help="compare paired baseline and candidate runs")
    evaluation_compare.add_argument("--tenant", required=True, help="tenant slug")
    evaluation_compare.add_argument("--suite", required=True, help="evaluation suite UUID")
    evaluation_compare.add_argument("--baseline-run", required=True, help="baseline run UUID")
    evaluation_compare.add_argument("--candidate-run", required=True, help="candidate run UUID")
    identity = commands.add_parser("identity", help="trusted human identity bootstrap")
    identity_commands = identity.add_subparsers(dest="identity_command", required=True)
    bootstrap = identity_commands.add_parser("bootstrap-admin", help="create the first organization ADMIN once")
    bootstrap.add_argument("--tenant", required=True, help="existing tenant slug")
    bootstrap.add_argument("--subject", required=True, help="immutable OIDC subject")
    bootstrap.add_argument("--display-name")
    bootstrap.add_argument("--email")
    archive = commands.add_parser("archive", help="inspect and operate cold trace archives")
    archive_commands = archive.add_subparsers(dest="archive_command", required=True)
    archive_status = archive_commands.add_parser("status")
    archive_status.add_argument("--tenant", required=True, help="tenant slug")
    archive_stores = archive_commands.add_parser("stores")
    archive_stores.add_argument("--tenant", required=True, help="tenant slug (used only for command consistency)")
    archive_run = archive_commands.add_parser("run", help="archive eligible traces")
    archive_run.add_argument("--tenant", required=True, help="tenant slug")
    archive_run.add_argument("--execute", action="store_true", help="perform uploads; default is dry-run")
    archive_verify = archive_commands.add_parser("verify")
    archive_verify.add_argument("--tenant", required=True, help="tenant slug")
    archive_verify.add_argument("--archive-id", required=True)
    archive_fetch = archive_commands.add_parser("fetch")
    archive_fetch.add_argument("--tenant", required=True, help="tenant slug")
    archive_fetch.add_argument("--archive-id", required=True)
    archive_replicas = archive_commands.add_parser("replicas")
    archive_replicas.add_argument("--tenant", required=True, help="tenant slug")
    archive_replicas.add_argument("--archive-id")
    archive_scrub = archive_commands.add_parser("scrub")
    archive_scrub.add_argument("--tenant", required=True, help="tenant slug")
    archive_scrub.add_argument("--replica-id", required=True)
    archive_repair = archive_commands.add_parser("repair")
    archive_repair.add_argument("--tenant", required=True, help="tenant slug")
    archive_repair.add_argument("--archive-id", required=True)
    archive_repair.add_argument("--target-store-id", required=True)
    archive_repair.add_argument("--execute", action="store_true", help="queue a safe missing-replica repair")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "version":
        for key, value in build_metadata().items():
            print(f"{key}={value}")
        return 0
    factory = get_session_factory()
    with factory() as db:
        if args.command == "witness" and args.witness_command == "status":
            for row in db.scalars(select(Witness).order_by(Witness.witness_id)):
                print(f"witness_id={row.witness_id} key_id={row.verification_key_id} enabled={row.enabled} endpoint_ref={row.endpoint_config_ref}")
            return 0
        if args.command == "witness" and args.witness_command in {"quorum", "verify"}:
            checkpoint = (db.get(IntegrityCheckpoint, args.checkpoint) if args.witness_command == "verify" else
                          db.scalar(select(IntegrityCheckpoint).order_by(IntegrityCheckpoint.checkpoint_sequence.desc()).limit(1)))
            if checkpoint is None:
                raise SystemExit("checkpoint not found")
            result = evaluate_checkpoint_quorum(db, checkpoint.id)
            for key, value in result.as_dict().items():
                print(f"{key}={value}")
            return 0 if result.destructive_allowed else 1
        if args.command == "tenant" and args.tenant_command == "create":
            tenant = create_tenant(db, args.slug, args.name)
            print(f"tenant_id={tenant.id} slug={tenant.slug}")
            return 0
        if args.command == "tenant" and args.tenant_command == "list":
            for tenant in db.scalars(select(Tenant).order_by(Tenant.slug)):
                state = "disabled" if tenant.disabled_at else "active"
                print(f"tenant_id={tenant.id} slug={tenant.slug} name={tenant.name!r} state={state}")
            return 0
        if args.command == "identity" and args.identity_command == "bootstrap-admin":
            settings = get_settings()
            issuer = (settings.oidc_issuer or "").rstrip("/")
            if not issuer:
                raise SystemExit("AGENTGUARD_OIDC_ISSUER must be configured")
            tenant = db.scalar(select(Tenant).where(Tenant.slug == args.tenant.strip().lower()))
            if tenant is None:
                raise SystemExit(f"unknown tenant: {args.tenant}")
            try:
                membership = bootstrap_admin(db, tenant, issuer, args.subject, args.display_name, args.email)
            except IdentityValidationError as exc:
                raise SystemExit(str(exc)) from exc
            print(f"bootstrap_admin=created tenant_id={tenant.id} membership_id={membership.id}")
            return 0
        if args.command == "key" and args.key_command == "create":
            pepper = _pepper()
            tenant = db.scalar(select(Tenant).where(Tenant.slug == args.tenant.strip().lower()))
            if tenant is None:
                raise SystemExit(f"unknown tenant: {args.tenant}")
            scopes = [scope.strip() for scope in args.scopes.split(",") if scope.strip()]
            try:
                api_key, plaintext = create_api_key(db, tenant, scopes, args.name, pepper, _parse_expiry(args.expires_at))
            except ValueError as exc:
                raise SystemExit(str(exc)) from exc
            print(f"key_id={api_key.id} public_id={api_key.public_id} tenant={tenant.slug} scopes={','.join(api_key.scopes)}")
            print(f"api_key={plaintext}")
            print("warning=save this API key now; the secret cannot be recovered")
            return 0
        if args.command == "key" and args.key_command == "list":
            tenant = db.scalar(select(Tenant).where(Tenant.slug == args.tenant.strip().lower()))
            if tenant is None:
                raise SystemExit(f"unknown tenant: {args.tenant}")
            for key in db.scalars(select(ApiKey).where(ApiKey.tenant_id == tenant.id).order_by(ApiKey.created_at)):
                state = "revoked" if key.revoked_at else "expired" if key.expires_at and key.expires_at <= datetime.now(key.expires_at.tzinfo) else "active"
                print(f"key_id={key.id} public_id={key.public_id} name={key.name!r} scopes={','.join(key.scopes)} state={state}")
            return 0
        if args.command == "key" and args.key_command == "revoke":
            if not revoke_api_key(db, args.public_id):
                raise SystemExit(f"unknown public id: {args.public_id}")
            print(f"revoked_public_id={args.public_id}")
            return 0
        if args.command == "archive":
            tenant = db.scalar(select(Tenant).where(Tenant.slug == args.tenant.strip().lower()))
            if tenant is None:
                raise SystemExit(f"unknown tenant: {args.tenant}")
            if args.archive_command == "status":
                for key, value in retention_status(db, tenant_id=tenant.id).items():
                    print(f"{key}={value}")
                return 0
            if args.archive_command == "stores":
                for store_id, binding in sorted(archive_store_registry().items(), key=lambda item: (item[1].priority, item[0])):
                    print(f"store_id={store_id} read_enabled={binding.read_enabled} write_enabled={binding.write_enabled} replication_enabled={binding.replication_enabled} scrub_enabled={binding.scrub_enabled}")
                return 0
            if args.archive_command == "replicas":
                import uuid
                archive_id = uuid.UUID(args.archive_id) if args.archive_id else None
                for row in list_replicas(db, tenant_id=tenant.id, logical_archive_id=archive_id):
                    print(f"replica_id={row.id} archive_id={row.logical_archive_id} store_id={row.store_id} state={row.state} verified_at={row.verified_at} last_scrubbed_at={row.last_scrubbed_at}")
                return 0
            if args.archive_command == "scrub":
                import uuid
                row = db.get(ArchiveReplica, uuid.UUID(args.replica_id))
                if row is None or row.tenant_id != tenant.id:
                    raise SystemExit("archive replica not found")
                result = scrub_replica(db, row.id)
                print(f"replica_id={row.id} result={result.result} verification_depth={result.verification_depth}")
                return 0 if result.result == "VALID" else 1
            if args.archive_command == "repair":
                import uuid
                result = repair_missing_replica(db, tenant_id=tenant.id, logical_archive_type="TRACE_ARCHIVE", logical_archive_id=uuid.UUID(args.archive_id), target_store_id=args.target_store_id, dry_run=not args.execute)
                for key, value in result.items():
                    print(f"{key}={value}")
                return 0 if result["would_repair"] else 1
            if args.archive_command == "run":
                from agentguard_server.services.archive import check_archive_eligibility
                from agentguard_server.services.retention import archive_trace
                rows = list(db.scalars(select(Trace).where(Trace.tenant_id == tenant.id)))
                eligible = 0
                eligible_rows = []
                blocked = 0
                for row in rows:
                    try:
                        check_archive_eligibility(db, tenant.id, row.trace_id)
                        eligible += 1
                        eligible_rows.append(row)
                    except Exception:
                        blocked += 1
                if args.execute:
                    completed = 0
                    archive_failures = 0
                    for row in eligible_rows:
                        try:
                            archive_trace(db, tenant_id=tenant.id, trace_id=row.trace_id)
                            completed += 1
                        except Exception:
                            archive_failures += 1
                    print(f"dry_run=false eligible={eligible} archived={completed} failed={archive_failures}")
                else:
                    print(f"dry_run=true eligible={eligible} blocked={blocked}")
                return 0
            try:
                import uuid
                archive_id = uuid.UUID(args.archive_id)
            except ValueError as exc:
                raise SystemExit("invalid archive UUID") from exc
            row = db.scalar(select(ArchiveRecord).where(ArchiveRecord.id == archive_id, ArchiveRecord.tenant_id == tenant.id))
            if row is None:
                raise SystemExit("archive not found")
            try:
                payload = verify_stored_archive(db, row, configured_archive_store(), ArchiveKeyring.from_settings())
            except Exception as exc:
                print(f"archive_id={archive_id} status={type(exc).__name__}")
                return 1
            print(f"archive_id={archive_id} status=VALID")
            if args.archive_command == "fetch":
                import json
                print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "integrity" and args.integrity_command == "verify":
            tenant = db.scalar(select(Tenant).where(Tenant.slug == args.tenant.strip().lower()))
            if tenant is None:
                raise SystemExit(f"unknown tenant: {args.tenant}")
            result = verify_trace_integrity(db, tenant.id, args.trace_id)
            print(f"trace_id={args.trace_id} status={result.status} events_checked={result.events_checked} chain_valid={result.chain_valid} projection_consistent={result.projection_consistent}")
            if result.first_failure:
                print(f"first_failure={result.first_failure}")
            return 0 if result.status == "valid" else 1
        if args.command == "integrity" and args.integrity_command == "segments":
            tenant = db.scalar(select(Tenant).where(Tenant.slug == args.tenant.strip().lower()))
            if tenant is None:
                raise SystemExit(f"unknown tenant: {args.tenant}")
            if args.segment_command == "list":
                rows = db.scalars(select(IntegrityArchiveSegment).where(IntegrityArchiveSegment.tenant_id == tenant.id).order_by(IntegrityArchiveSegment.segment_sequence))
                for row in rows:
                    print(f"segment_id={row.id} trace_id={row.trace_id} range={row.source_start_sequence}-{row.source_end_sequence} records={row.record_count} state={row.state} logical_digest={row.logical_segment_digest}")
                return 0
            import uuid
            try:
                segment_id = uuid.UUID(args.segment_id) if hasattr(args, "segment_id") else None
            except ValueError as exc:
                raise SystemExit("invalid segment UUID") from exc
            if args.segment_command == "plan":
                try:
                    row = create_integrity_segment_candidate(db, tenant_id=tenant.id, trace_id=args.trace_id)
                except IntegritySegmentEligibilityError as exc:
                    raise SystemExit(exc.reason) from exc
                print(f"segment_id={row.id} trace_id={row.trace_id} state={row.state} range={row.source_start_sequence}-{row.source_end_sequence}")
                return 0
            row = db.scalar(select(IntegrityArchiveSegment).where(IntegrityArchiveSegment.id == segment_id, IntegrityArchiveSegment.tenant_id == tenant.id))
            if row is None:
                raise SystemExit("integrity segment not found")
            if args.segment_command == "verify":
                results = []
                for replica in list_replicas(db, tenant_id=tenant.id, logical_archive_type="INTEGRITY_SEGMENT", logical_archive_id=row.id):
                    results.append(verify_replica(db, replica.id).status)
                print(f"segment_id={row.id} state={row.state} replica_results={','.join(results) if results else 'NO_REPLICAS'}")
                return 0 if results and all(item == "VALID" for item in results) else 1
            if not args.execute:
                print(f"segment_id={row.id} state={row.state} dry_run=true would_compact={row.state == 'READY_TO_COMPACT'}")
                return 0 if row.state == "READY_TO_COMPACT" else 1
            try:
                deleted = compact_integrity_segment(db, row.id)
            except Exception as exc:
                raise SystemExit(str(exc)) from exc
            print(f"segment_id={row.id} state=COMPACTED records={deleted}")
            return 0
        if args.command == "replay" and args.replay_command == "run":
            tenant = db.scalar(select(Tenant).where(Tenant.slug == args.tenant.strip().lower()))
            if tenant is None:
                raise SystemExit(f"unknown tenant: {args.tenant}")
            try:
                plan = build_replay_plan(db, tenant.id, args.trace_id)
                session = persist_replay(db, tenant_id=tenant.id, plan=plan)
            except ReplayRefused as exc:
                session = persist_blocked_replay(db, tenant_id=tenant.id, trace_id=args.trace_id,
                                                 reason=exc.reason, integrity_status=exc.integrity_status)
                print(f"replay_id={session.id} status=blocked reason={exc.reason}")
                return 1
            print(f"replay_id={session.id} status={session.status} mode={session.mode} steps={len(session.steps)}")
            return 0
        if args.command == "analysis" and args.analysis_command == "run":
            tenant = db.scalar(select(Tenant).where(Tenant.slug == args.tenant.strip().lower()))
            if tenant is None:
                raise SystemExit(f"unknown tenant: {args.tenant}")
            try:
                report, _ = analyze_trace(db, tenant.id, args.trace_id, mode=args.mode)
                run = persist_analysis(db, tenant_id=tenant.id, report=report, mode=args.mode)
            except AnalysisRefused as exc:
                run = persist_refused_analysis(db, tenant_id=tenant.id, trace_id=args.trace_id, reason=exc.reason)
                print(f"analysis_id={run.id} status=blocked reason={exc.reason}")
                return 1
            except AnalysisResourceLimit as exc:
                raise SystemExit(str(exc)) from exc
            print(f"analysis_id={run.id} status={run.status} deterministic_status={run.deterministic_status} ai_status={run.ai_status} findings={len(run.findings)}")
            return 0
        if args.command == "eval" and args.evaluation_command == "compare":
            tenant = db.scalar(select(Tenant).where(Tenant.slug == args.tenant.strip().lower()))
            if tenant is None:
                raise SystemExit(f"unknown tenant: {args.tenant}")
            try:
                import uuid
                suite_id = uuid.UUID(args.suite)
                baseline_id = uuid.UUID(args.baseline_run)
                candidate_id = uuid.UUID(args.candidate_run)
            except ValueError as exc:
                raise SystemExit("invalid evaluation UUID") from exc
            suite = db.scalar(select(EvaluationSuite).where(EvaluationSuite.id == suite_id, EvaluationSuite.tenant_id == tenant.id))
            baseline = db.scalar(select(EvaluationRun).where(EvaluationRun.id == baseline_id, EvaluationRun.tenant_id == tenant.id))
            candidate = db.scalar(select(EvaluationRun).where(EvaluationRun.id == candidate_id, EvaluationRun.tenant_id == tenant.id))
            if suite is None or baseline is None or candidate is None:
                raise SystemExit("evaluation input not found")
            if baseline.suite_id != suite.id or candidate.suite_id != suite.id or baseline.variant != "baseline" or candidate.variant != "candidate":
                raise SystemExit("evaluation runs do not match suite variants")
            try:
                comparison = compare_runs(db, tenant.id, suite=suite, baseline_run=baseline, candidate_run=candidate)
            except EvaluationValidationError as exc:
                raise SystemExit(str(exc)) from exc
            matched = comparison.metrics.get("matched_cases", 0)
            print(f"comparison_id={comparison.id} decision={comparison.status} matched_cases={matched} reasons={len(comparison.reasons or [])}")
            if comparison.status == "PASS":
                return 0
            if comparison.status == "FAIL":
                return 2
            if comparison.status == "INSUFFICIENT_DATA":
                return 3
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
