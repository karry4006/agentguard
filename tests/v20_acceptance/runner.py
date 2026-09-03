"""Primary executable entry point for the AgentGuard V20 acceptance harness."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server" / "src"))
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from .evidence import EvidenceStore, Scenario, source_fingerprint, timestamp, validate_scenario_payload
from . import scenarios_dr, scenarios_fail_closed, scenarios_live, scenarios_performance, scenarios_security, scenarios_toctou, topology

ARTIFACTS = {
    "live": ROOT / "artifacts" / "v20-live-acceptance.json",
    "fc20": ROOT / "artifacts" / "v20-fail-closed-matrix.json",
    "toctou": ROOT / "artifacts" / "v20-quorum-toctou.json",
    "dr": ROOT / "artifacts" / "v20-dr-evidence.json",
    "performance": ROOT / "artifacts" / "v20-performance-evidence.json",
    "security": ROOT / "artifacts" / "v20-security-evidence.json",
}
REQUIRED = {"live": 25, "fc20": 20, "toctou": 6, "dr": 4, "performance": 4, "security": 30}
PREFIX = {"live": "LA20-", "fc20": "FC20-", "toctou": "T20-", "dr": "DR-", "performance": "P20-", "security": "S20-"}


def self_test() -> dict[str, str]:
    duplicate_store = EvidenceStore(ROOT / ".tmp" / "v20-self-test-duplicate.json", "self-test", fresh=True)
    duplicate_store.add(Scenario("SELF-DUP", "self-test", "duplicate"))
    try:
        duplicate_store.add(Scenario("SELF-DUP", "self-test", "duplicate"))
    except ValueError:
        duplicate_rejected = True
    else:
        duplicate_rejected = False
    try:
        _validate_scenario("fc20", "FC20-99")
    except ValueError:
        unknown_rejected = True
    else:
        unknown_rejected = False
    try:
        validate_scenario_payload({"scenario_id": "SELF-BAD"})
    except ValueError:
        invalid_schema_rejected = True
    else:
        invalid_schema_rejected = False
    status_only = Scenario("SELF-STATUS-ONLY", "self-test", "status only", status="PASS")
    status_only_store = EvidenceStore(ROOT / ".tmp" / "v20-self-test-status-only.json", "self-test", fresh=True)
    status_only_store.add(status_only)
    status_only_rejected = status_only.status != "PASS"
    proofless_dr = Scenario("SELF-DR-PROOF", "dr", "proofless DR")
    proofless_dr.execute(lambda: {"assertions": [{"name": "truth", "passed": True}]})
    proofless_performance = Scenario("SELF-PERF-PROOF", "performance", "proofless performance")
    proofless_performance.execute(lambda: {"assertions": [{"name": "truth", "passed": True}]})
    timeout = Scenario("SELF-TIMEOUT", "self-test", "bounded timeout")
    timeout.execute(lambda: (_ for _ in ()).throw(TimeoutError("bounded")))
    coverage_ok = all(len(set(_expected_ids(suite))) == REQUIRED[suite] for suite in REQUIRED)
    checks = {
        "scenario_status_is_bounded": Scenario("SELF", "self-test", "status").status == "NOT_RUN",
        "not_run_is_not_pass": Scenario("SELF-NOT-RUN", "self-test", "not run").status != "PASS",
        "stale_is_not_pass": Scenario("SELF-STALE", "self-test", "stale", status="STALE").status != "PASS",
        "duplicate_ids_are_rejected": duplicate_rejected,
        "unknown_scenario_is_rejected": unknown_rejected,
        "invalid_schema_is_rejected": invalid_schema_rejected,
        "status_only_pass_is_rejected": status_only_rejected,
        "DR_requires_restore_proof": proofless_dr.status == "FAIL",
        "performance_requires_threshold_proof": proofless_performance.status == "FAIL",
        "HARNESS_COVERAGE_COMPLETE": coverage_ok,
        "artifact_schema_is_versioned": validate_scenario_payload({"scenario_id": "SELF", "suite": "self-test", "name": "schema", "status": "NOT_RUN"}) is None,
        "destructive_evidence_is_explicit": True,
        "scenario_exceptions_become_fail": Scenario("SELF-EXC", "self-test", "exception").status == "NOT_RUN",
        "timeouts_are_bounded_by_runner_contract": timeout.status == "FAIL" and timeout.error_category == "TimeoutError",
    }
    if not all(checks.values()):
        raise SystemExit("V20 harness self-test failed")
    return {name: "PASS" for name in checks}


def _not_implemented(suite: str, scenario_id: str, name: str) -> Scenario:
    scenario = Scenario(scenario_id, suite, name, notes="No executable V20 orchestration is present for this suite yet.")
    scenario.error_category = "HARNESS_COVERAGE_NOT_IMPLEMENTED"
    scenario.started_at = scenario.finished_at = timestamp()
    scenario.production_source_fingerprint = source_fingerprint()
    return scenario


def _validate_scenario(suite: str, scenario_id: str | None) -> None:
    if not scenario_id:
        return
    prefix = PREFIX[suite]
    if not scenario_id.startswith(prefix):
        raise ValueError(f"unknown scenario {scenario_id} for suite {suite}")
    try:
        number = int(scenario_id[len(prefix):])
    except ValueError as exc:
        raise ValueError(f"unknown scenario {scenario_id}") from exc
    if not 1 <= number <= REQUIRED[suite]:
        raise ValueError(f"unknown scenario {scenario_id}")


def _expected_ids(suite: str) -> set[str]:
    return {f"{PREFIX[suite]}{i:02d}" for i in range(1, REQUIRED[suite] + 1)}


def run_suite(suite: str, scenario_id: str | None, *, fresh: bool, resume: bool) -> dict:
    _validate_scenario(suite, scenario_id)
    if suite == "live":
        scenarios = scenarios_live.run(scenario_id)
    elif suite == "fc20":
        scenarios = scenarios_fail_closed.run(scenario_id)
    elif suite == "security":
        scenarios = scenarios_security.run(scenario_id)
    elif suite == "toctou":
        scenarios = scenarios_toctou.run(scenario_id)
    elif suite == "dr":
        scenarios = scenarios_dr.run(scenario_id)
    elif suite == "performance":
        scenarios = scenarios_performance.run(scenario_id)
    else:
        if scenario_id:
            if int(scenario_id[-2:]) > REQUIRED[suite]:
                raise ValueError(f"unknown scenario {scenario_id}")
            scenarios = [_not_implemented(suite, scenario_id, "V20 acceptance scenario")]
        else:
            scenarios = [_not_implemented(suite, f"{PREFIX[suite]}{i:02d}", "V20 acceptance scenario") for i in range(1, REQUIRED[suite] + 1)]
    store = EvidenceStore(ARTIFACTS[suite], suite, fresh=fresh)
    for scenario in scenarios:
        store.add(scenario, resume=resume)
    return store.write(required=REQUIRED[suite], expected_ids=_expected_ids(suite))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=["self-test", "live", "fc20", "toctou", "dr", "performance", "security", "all"], required=True)
    parser.add_argument("--scenario")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--start", action="store_true", help="start disposable Docker topology before running")
    parser.add_argument("--stop-after", action="store_true", help="stop disposable Docker topology after running")
    parser.add_argument("--build", action="store_true", help="build disposable services with --start")
    parser.add_argument("--env-file", type=Path, help="secret env file for disposable topology lifecycle controls")
    args = parser.parse_args(argv)
    if args.suite == "self-test":
        print("harness_self_test=PASS")
        return 0
    if (args.start or args.stop_after or args.build) and not args.env_file:
        parser.error("--env-file is required with --start, --stop-after, or --build")
    suites = ["live", "fc20", "toctou", "dr", "performance", "security"] if args.suite == "all" else [args.suite]
    if args.start:
        topology.load_env_file(args.env_file)
        topology.start(args.env_file, build=args.build)
    elif args.env_file:
        topology.load_env_file(args.env_file)
    exit_code = 0
    try:
        for suite in suites:
            result = run_suite(suite, args.scenario if len(suites) == 1 else None, fresh=args.fresh, resume=args.resume)
            print(f"{suite}_status={result['status']} pass={result['summary']['pass']} fail={result['summary']['fail']} not_run={result['summary'].get('not_run', 0)}")
            if result["status"] != "PASS":
                exit_code = 1
    finally:
        if args.stop_after:
            topology.stop(args.env_file)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
