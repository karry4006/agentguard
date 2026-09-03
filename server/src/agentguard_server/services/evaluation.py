"""Deterministic, offline baseline/candidate regression evaluation.

The public seam is ``evaluate_population``. It accepts already-derived case
metrics and returns a bounded advisory decision. It has no deployment, replay,
shell, or arbitrary evaluator adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
from statistics import mean
from typing import Any, Iterable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentguard_server.models import EventLog, ReplaySession, ReplayStep, Span, Trace
from agentguard_server.services.analysis import analyze_trace
from agentguard_server.services.integrity import verify_trace_integrity
from agentguard_server.services.sanitize import sanitize


EVALUATION_ENGINE_VERSION = "v1"
EVALUATOR_VERSION = "deterministic-v1"
TAXONOMY_VERSION = "v1"
MAX_CASES = 1000
MAX_RULES = 64
MAX_AFFECTED_CASES = 100
ALLOWED_OPERATORS = frozenset({">=", ">", "<=", "<", "=="})
FAILURE_CATEGORIES = (
    "TIMEOUT", "AUTHENTICATION", "AUTHORIZATION", "RATE_LIMIT", "TOOL_EXECUTION",
    "LOOP_OR_REPETITION", "GUARDRAIL_FAILURE", "HANDOFF_FAILURE",
)


class EvaluationValidationError(ValueError):
    pass


@dataclass(frozen=True)
class CaseMetrics:
    case_id: str
    trace_id: str
    integrity_status: str
    success: bool | None
    failure_categories: tuple[str, ...] = ()
    tool_calls: int = 0
    model_calls: int = 0
    span_count: int = 0
    duration_seconds: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    replay_mismatch: bool | None = None
    status: str = "eligible"
    provider: str | None = None
    model: str | None = None
    source_ingestion_type: str | None = None


@dataclass(frozen=True)
class EvaluationResult:
    decision: str
    metrics: dict[str, Any]
    reasons: tuple[dict[str, Any], ...] = ()
    case_diffs: tuple[dict[str, Any], ...] = ()
    rule_results: tuple[dict[str, Any], ...] = ()
    evaluator_version: str = EVALUATOR_VERSION
    engine_version: str = EVALUATION_ENGINE_VERSION
    taxonomy_version: str = TAXONOMY_VERSION


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise EvaluationValidationError(f"{name} must be a finite number")
    return float(value)


def validate_policy(configuration: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(configuration, dict) or len(configuration) > 128:
        raise EvaluationValidationError("evaluation policy must be a bounded object")
    minimum_cases = int(configuration.get("minimum_cases", 1))
    if minimum_cases < 1 or minimum_cases > MAX_CASES:
        raise EvaluationValidationError("minimum_cases is out of range")
    coverage = _number(configuration.get("minimum_pair_coverage", 1.0), "minimum_pair_coverage")
    if not 0 <= coverage <= 1:
        raise EvaluationValidationError("minimum_pair_coverage must be between 0 and 1")
    missing_policy = str(configuration.get("missing_case_policy", "INSUFFICIENT_DATA"))
    if missing_policy not in {"FAIL", "IGNORE", "INSUFFICIENT_DATA"}:
        raise EvaluationValidationError("missing_case_policy is invalid")
    rules = configuration.get("rules", [])
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise EvaluationValidationError("rules must be a bounded list")
    allowed_metrics = _allowed_metrics()
    normalized_rules: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict) or len(rule) > 8:
            raise EvaluationValidationError("gate rule is invalid")
        metric = str(rule.get("metric", ""))
        operator = str(rule.get("operator", ""))
        if metric not in allowed_metrics or operator not in ALLOWED_OPERATORS:
            raise EvaluationValidationError("gate rule metric or operator is invalid")
        normalized: dict[str, Any] = {"metric": metric, "operator": operator}
        if "value" in rule:
            normalized["value"] = _number(rule["value"], "rule value")
        elif "baseline_metric" in rule:
            baseline_metric = str(rule["baseline_metric"])
            if baseline_metric not in allowed_metrics or not baseline_metric.startswith("baseline_"):
                raise EvaluationValidationError("baseline_metric is invalid")
            normalized["baseline_metric"] = baseline_metric
            normalized["offset"] = _number(rule.get("offset", 0), "rule offset")
        else:
            raise EvaluationValidationError("gate rule requires value or baseline_metric")
        normalized_rules.append(normalized)
    return {
        "minimum_cases": minimum_cases, "minimum_pair_coverage": coverage,
        "missing_case_policy": missing_policy, "rules": normalized_rules,
    }


def _allowed_metrics() -> set[str]:
    names = {
        "success_rate", "timeout_rate", "authentication_rate", "authorization_rate", "rate_limit_rate",
        "tool_execution_rate", "loop_rate", "guardrail_rate", "handoff_rate", "tool_calls_mean",
        "model_calls_mean", "spans_mean", "p50_latency_seconds", "p95_latency_seconds",
        "input_tokens_mean", "output_tokens_mean", "input_tokens_p95", "output_tokens_p95",
        "tokens_per_successful_case", "replay_mismatch_rate",
    }
    return {f"{prefix}_{name}" for prefix in ("baseline", "candidate") for name in names} | {
        f"{name}_delta" for name in names if name not in {"input_tokens_mean", "output_tokens_mean", "input_tokens_p95", "output_tokens_p95"}
    }


def _percentile(values: Iterable[float], percentile: float) -> float | None:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return None
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _rate(cases: list[CaseMetrics], predicate) -> float | None:
    if not cases:
        return None
    return sum(1 for case in cases if predicate(case)) / len(cases)


def _aggregate(prefix: str, cases: list[CaseMetrics]) -> dict[str, Any]:
    durations = [case.duration_seconds for case in cases if case.duration_seconds is not None]
    input_tokens = [case.input_tokens for case in cases if case.input_tokens is not None]
    output_tokens = [case.output_tokens for case in cases if case.output_tokens is not None]
    successful_input = [case.input_tokens for case in cases if case.success is True and case.input_tokens is not None]
    successful_output = [case.output_tokens for case in cases if case.success is True and case.output_tokens is not None]
    result: dict[str, Any] = {
        f"{prefix}_success_rate": _rate(cases, lambda c: c.success is True),
        f"{prefix}_timeout_rate": _rate(cases, lambda c: "TIMEOUT" in c.failure_categories),
        f"{prefix}_authentication_rate": _rate(cases, lambda c: "AUTHENTICATION" in c.failure_categories),
        f"{prefix}_authorization_rate": _rate(cases, lambda c: "AUTHORIZATION" in c.failure_categories),
        f"{prefix}_rate_limit_rate": _rate(cases, lambda c: "RATE_LIMIT" in c.failure_categories),
        f"{prefix}_tool_execution_rate": _rate(cases, lambda c: "TOOL_EXECUTION" in c.failure_categories),
        f"{prefix}_loop_rate": _rate(cases, lambda c: "LOOP_OR_REPETITION" in c.failure_categories),
        f"{prefix}_guardrail_rate": _rate(cases, lambda c: "GUARDRAIL_FAILURE" in c.failure_categories),
        f"{prefix}_handoff_rate": _rate(cases, lambda c: "HANDOFF_FAILURE" in c.failure_categories),
        f"{prefix}_tool_calls_mean": mean([c.tool_calls for c in cases]) if cases else None,
        f"{prefix}_model_calls_mean": mean([c.model_calls for c in cases]) if cases else None,
        f"{prefix}_spans_mean": mean([c.span_count for c in cases]) if cases else None,
        f"{prefix}_p50_latency_seconds": _percentile(durations, .50),
        f"{prefix}_p95_latency_seconds": _percentile(durations, .95),
        f"{prefix}_input_tokens_mean": mean(input_tokens) if input_tokens else None,
        f"{prefix}_output_tokens_mean": mean(output_tokens) if output_tokens else None,
        f"{prefix}_input_tokens_p95": _percentile(input_tokens, .95),
        f"{prefix}_output_tokens_p95": _percentile(output_tokens, .95),
        f"{prefix}_tokens_per_successful_case": (
            (sum(successful_input) + sum(successful_output)) / len(cases)
            if cases and (successful_input or successful_output) else None
        ),
        f"{prefix}_replay_mismatch_rate": _rate(cases, lambda c: c.replay_mismatch is True),
    }
    return result


def _reason_name(metric: str) -> str:
    names = {
        "success_rate": "success_rate_regression", "timeout_rate": "timeout_rate_regression",
        "p95_latency_seconds": "latency_regression", "tool_calls_mean": "tool_call_regression",
        "model_calls_mean": "model_call_regression", "loop_rate": "loop_rate_regression",
    }
    for suffix, reason in names.items():
        if metric.endswith(suffix):
            return reason
    return f"{metric.removeprefix('candidate_')}_regression"


def _compare(left: float, operator: str, right: float) -> bool:
    return {">=": left >= right, ">": left > right, "<=": left <= right, "<": left < right, "==": math.isclose(left, right)}[operator]


def evaluate_population(baseline: Iterable[CaseMetrics], candidate: Iterable[CaseMetrics], configuration: dict[str, Any]) -> EvaluationResult:
    policy = validate_policy(configuration)
    baseline_all = list(baseline)
    candidate_all = list(candidate)
    if len(baseline_all) > MAX_CASES or len(candidate_all) > MAX_CASES:
        raise EvaluationValidationError("evaluation case limit exceeded")
    baseline_by_case = {case.case_id: case for case in baseline_all if case.integrity_status == "valid" and case.status == "eligible"}
    candidate_by_case = {case.case_id: case for case in candidate_all if case.integrity_status == "valid" and case.status == "eligible"}
    baseline_ids = set(baseline_by_case)
    candidate_ids = set(candidate_by_case)
    matched_ids = sorted(baseline_ids & candidate_ids)
    missing_baseline = sorted(candidate_ids - baseline_ids)
    missing_candidate = sorted(baseline_ids - candidate_ids)
    matched_baseline = [baseline_by_case[item] for item in matched_ids]
    matched_candidate = [candidate_by_case[item] for item in matched_ids]
    metrics = _aggregate("baseline", matched_baseline)
    metrics.update(_aggregate("candidate", matched_candidate))
    for name in ("success_rate", "timeout_rate", "authentication_rate", "authorization_rate", "rate_limit_rate",
                 "tool_execution_rate", "loop_rate", "guardrail_rate", "handoff_rate", "tool_calls_mean",
                 "model_calls_mean", "spans_mean", "p50_latency_seconds", "p95_latency_seconds",
                 "tokens_per_successful_case", "replay_mismatch_rate"):
        left, right = metrics.get(f"candidate_{name}"), metrics.get(f"baseline_{name}")
        metrics[f"{name}_delta"] = left - right if left is not None and right is not None else None
    metrics.update({
        "baseline_cases": len(baseline_ids), "candidate_cases": len(candidate_ids), "matched_cases": len(matched_ids),
        "missing_baseline_cases": missing_baseline[:MAX_AFFECTED_CASES],
        "missing_candidate_cases": missing_candidate[:MAX_AFFECTED_CASES],
        "coverage_ratio": len(matched_ids) / max(len(baseline_ids), 1),
        "baseline_invalid_cases": len(baseline_all) - len(baseline_ids),
        "candidate_invalid_cases": len(candidate_all) - len(candidate_ids),
    })
    reasons: list[dict[str, Any]] = []
    if len(matched_ids) < policy["minimum_cases"] or metrics["coverage_ratio"] < policy["minimum_pair_coverage"]:
        reasons.append({"reason": "minimum_sample_or_pair_coverage", "matched_cases": len(matched_ids),
                        "minimum_cases": policy["minimum_cases"], "coverage_ratio": metrics["coverage_ratio"],
                        "minimum_pair_coverage": policy["minimum_pair_coverage"]})
    if missing_candidate or missing_baseline:
        if policy["missing_case_policy"] != "IGNORE":
            reasons.append({"reason": "missing_paired_cases", "missing_baseline_cases": missing_baseline[:MAX_AFFECTED_CASES],
                            "missing_candidate_cases": missing_candidate[:MAX_AFFECTED_CASES]})
    rule_results: list[dict[str, Any]] = []
    for rule in policy["rules"]:
        actual = metrics.get(rule["metric"])
        if actual is None:
            rule_results.append({**rule, "result": "INSUFFICIENT_DATA"})
            reasons.append({"reason": "metric_unavailable", "metric": rule["metric"]})
            continue
        if "value" in rule:
            expected = rule["value"]
        else:
            expected = (metrics.get(rule["baseline_metric"]) or 0) + rule["offset"]
        passed = _compare(float(actual), rule["operator"], float(expected))
        rule_results.append({**rule, "actual": actual, "expected": expected, "result": "PASS" if passed else "FAIL"})
        if not passed:
            reasons.append({"reason": _reason_name(rule["metric"]), "rule": rule, "baseline": metrics.get(rule.get("baseline_metric", "")),
                            "candidate": actual, "expected": expected,
                            "affected_case_ids": [case.case_id for case in matched_candidate[:MAX_AFFECTED_CASES]]})
    case_diffs = tuple({
        "case_id": case_id, "baseline_trace_id": matched_baseline[index].trace_id,
        "candidate_trace_id": matched_candidate[index].trace_id,
        "baseline_success": matched_baseline[index].success, "candidate_success": matched_candidate[index].success,
        "baseline_failure_categories": list(matched_baseline[index].failure_categories),
        "candidate_failure_categories": list(matched_candidate[index].failure_categories),
        "additional_tool_calls": matched_candidate[index].tool_calls - matched_baseline[index].tool_calls,
        "additional_model_calls": matched_candidate[index].model_calls - matched_baseline[index].model_calls,
        "additional_spans": matched_candidate[index].span_count - matched_baseline[index].span_count,
        "duration_delta_seconds": ((matched_candidate[index].duration_seconds - matched_baseline[index].duration_seconds)
                                   if matched_candidate[index].duration_seconds is not None and matched_baseline[index].duration_seconds is not None else None),
        "token_data_available": matched_candidate[index].input_tokens is not None or matched_candidate[index].output_tokens is not None,
        "replay_mismatch": matched_candidate[index].replay_mismatch,
    } for index, case_id in enumerate(matched_ids))
    insufficient = bool(reasons and any(item["reason"] in {"minimum_sample_or_pair_coverage", "missing_paired_cases", "metric_unavailable"} for item in reasons))
    if insufficient and policy["missing_case_policy"] != "FAIL":
        decision = "INSUFFICIENT_DATA"
    elif insufficient and policy["missing_case_policy"] == "FAIL":
        decision = "FAIL"
    elif any(item.get("result") == "FAIL" for item in rule_results):
        decision = "FAIL"
    else:
        decision = "PASS"
    return EvaluationResult(decision=decision, metrics=metrics, reasons=tuple(reasons), case_diffs=case_diffs, rule_results=tuple(rule_results))


def _token(attrs: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = attrs.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def metrics_for_trace(db: Session, tenant_id: UUID, trace_id: str, case_id: str) -> CaseMetrics:
    verification = verify_trace_integrity(db, tenant_id, trace_id)
    if verification.status != "valid":
        return CaseMetrics(case_id=case_id, trace_id=trace_id, integrity_status=verification.status, success=None, status="rejected")
    trace = db.scalar(select(Trace).where(Trace.tenant_id == tenant_id, Trace.trace_id == trace_id))
    spans = list(db.scalars(select(Span).where(Span.tenant_id == tenant_id, Span.trace_id == trace_id)))
    if trace is None:
        return CaseMetrics(case_id=case_id, trace_id=trace_id, integrity_status="missing", success=None, status="rejected")
    report, _ = analyze_trace(db, tenant_id, trace_id, mode="deterministic")
    categories = tuple(sorted({finding.category.value for finding in report.findings}))
    attrs = [span.attributes or {} for span in spans]
    durations = [span.duration_ms for span in spans if span.duration_ms is not None]
    started = trace.started_at
    ended = trace.ended_at
    duration = ((ended - started).total_seconds() if started and ended else (max(durations) / 1000 if durations else None))
    failed_status = trace.status.lower() in {"error", "failed", "failure", "timeout"} or any(span.status.lower() in {"error", "timeout", "failed"} for span in spans)
    success = not failed_status and not categories
    replay_mismatch = db.scalar(select(ReplayStep.id).join(ReplaySession, ReplayStep.replay_session_id == ReplaySession.id).where(
        ReplaySession.tenant_id == tenant_id, ReplaySession.source_trace_id == trace_id, ReplayStep.comparison_status == "MISMATCH"
    ).limit(1)) is not None
    event_ids = list(db.scalars(select(EventLog.event_id).where(EventLog.tenant_id == tenant_id, EventLog.trace_id == trace_id).order_by(EventLog.id).limit(2)))
    source = "otlp" if any(str(event_id).startswith("otlp-") for event_id in event_ids) else "agentguard"
    input_tokens = next((value for value in (_token(item, ("gen_ai.usage.input_tokens", "input_tokens")) for item in attrs) if value is not None), None)
    output_tokens = next((value for value in (_token(item, ("gen_ai.usage.output_tokens", "output_tokens")) for item in attrs) if value is not None), None)
    model = next((str(item[key]) for item in attrs for key in ("gen_ai.request.model", "model") if key in item), None)
    return CaseMetrics(case_id=case_id, trace_id=trace_id, integrity_status="valid", success=success,
                       failure_categories=categories, tool_calls=sum(span.span_type in {"tool", "function", "plugin", "mcp"} for span in spans),
                       model_calls=sum(span.span_type in {"llm", "model"} for span in spans), span_count=len(spans),
                       duration_seconds=duration, input_tokens=input_tokens, output_tokens=output_tokens,
                       replay_mismatch=replay_mismatch, provider=trace.provider, model=model, source_ingestion_type=source)


def metrics_to_dict(case: CaseMetrics) -> dict[str, Any]:
    return {
        "success": case.success, "failure_categories": list(case.failure_categories),
        "tool_calls": case.tool_calls, "model_calls": case.model_calls, "span_count": case.span_count,
        "duration_seconds": case.duration_seconds, "input_tokens": case.input_tokens,
        "output_tokens": case.output_tokens, "replay_mismatch": case.replay_mismatch,
        "provider": case.provider, "model": case.model, "source_ingestion_type": case.source_ingestion_type,
        "evaluator_type": "deterministic", "evaluator_version": EVALUATOR_VERSION,
        "taxonomy_version": TAXONOMY_VERSION,
    }


def case_from_row(row: Any) -> CaseMetrics:
    metrics = row.metrics or {}
    return CaseMetrics(
        case_id=row.case_id, trace_id=row.trace_id, integrity_status=row.integrity_status,
        success=metrics.get("success"), failure_categories=tuple(metrics.get("failure_categories") or ()),
        tool_calls=int(metrics.get("tool_calls", 0)), model_calls=int(metrics.get("model_calls", 0)),
        span_count=int(metrics.get("span_count", 0)), duration_seconds=metrics.get("duration_seconds"),
        input_tokens=metrics.get("input_tokens"), output_tokens=metrics.get("output_tokens"),
        replay_mismatch=metrics.get("replay_mismatch"), status=row.status,
        provider=metrics.get("provider"), model=metrics.get("model"), source_ingestion_type=metrics.get("source_ingestion_type"),
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_suite(db: Session, tenant_id: UUID, name: str, version: str, configuration: dict[str, Any]):
    from agentguard_server.models import EvaluationSuite
    if not isinstance(name, str) or not name.strip() or len(name) > 255 or not isinstance(version, str) or not version.strip() or len(version) > 64:
        raise EvaluationValidationError("suite name/version is invalid")
    policy = validate_policy(configuration)
    suite = EvaluationSuite(tenant_id=tenant_id, name=name.strip(), version=version.strip(), created_at=_now(), configuration=policy)
    db.add(suite)
    db.commit()
    db.refresh(suite)
    return suite


def create_run(db: Session, tenant_id: UUID, *, suite: Any, variant: str, agent_version: str,
               prompt_version: str | None, model: str | None, environment: dict[str, Any], cases: list[dict[str, str]],
               idempotency_key: str | None = None, max_cases: int = MAX_CASES):
    from agentguard_server.models import EvaluationCaseResult, EvaluationRun
    if variant not in {"baseline", "candidate"} or not agent_version or len(agent_version) > 128:
        raise EvaluationValidationError("evaluation run metadata is invalid")
    if len(cases) < 1 or len(cases) > max_cases:
        raise EvaluationValidationError("evaluation run case count is invalid")
    if len({item["case_id"] for item in cases}) != len(cases):
        raise EvaluationValidationError("evaluation case IDs must be unique")
    safe_environment = sanitize(environment if isinstance(environment, dict) else {}, capture_content=False)
    run = EvaluationRun(tenant_id=tenant_id, suite_id=suite.id, variant=variant, agent_version=agent_version,
                        prompt_version=prompt_version, model=model, environment=safe_environment,
                        status="completed", created_at=_now(), completed_at=_now(), idempotency_key=idempotency_key)
    db.add(run)
    db.flush()
    for item in cases:
        case_id, trace_id = str(item["case_id"]).strip(), str(item["trace_id"]).strip()
        if not case_id or len(case_id) > 255 or not trace_id or len(trace_id) > 255:
            raise EvaluationValidationError("evaluation case metadata is invalid")
        metrics = metrics_for_trace(db, tenant_id, trace_id, case_id)
        db.add(EvaluationCaseResult(tenant_id=tenant_id, run_id=run.id, case_id=case_id, trace_id=trace_id,
                                    status=metrics.status, integrity_status=metrics.integrity_status,
                                    metrics=metrics_to_dict(metrics), created_at=_now()))
    db.commit()
    db.refresh(run)
    return run


def compare_runs(db: Session, tenant_id: UUID, *, suite: Any, baseline_run: Any, candidate_run: Any,
                 idempotency_key: str | None = None):
    from agentguard_server.models import EvaluationComparison, ReleaseGateResult
    baseline = [case_from_row(row) for row in baseline_run.cases]
    candidate = [case_from_row(row) for row in candidate_run.cases]
    result = evaluate_population(baseline, candidate, suite.configuration)
    comparison = EvaluationComparison(
        tenant_id=tenant_id, suite_id=suite.id, baseline_run_id=baseline_run.id, candidate_run_id=candidate_run.id,
        status=result.decision, metrics=result.metrics, reasons=list(result.reasons), case_diffs=list(result.case_diffs),
        rule_results=list(result.rule_results), engine_version=result.engine_version,
        evaluator_version=result.evaluator_version, taxonomy_version=result.taxonomy_version,
        created_at=_now(), idempotency_key=idempotency_key,
    )
    db.add(comparison)
    db.flush()
    db.add(ReleaseGateResult(comparison_id=comparison.id, decision=result.decision, reasons=list(result.reasons), created_at=_now()))
    db.commit()
    db.refresh(comparison)
    return comparison
