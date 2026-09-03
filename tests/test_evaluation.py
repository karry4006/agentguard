"""Public-seam tests for deterministic offline regression evaluation."""

from agentguard_server.services.evaluation import CaseMetrics, evaluate_population


def _case(case_id: str, *, success: bool = True, timeout: bool = False, duration: float = 1.0) -> CaseMetrics:
    return CaseMetrics(
        case_id=case_id, trace_id=f"trace-{case_id}", integrity_status="valid",
        success=success, failure_categories=("TIMEOUT",) if timeout else (),
        tool_calls=1, model_calls=1, span_count=3, duration_seconds=duration,
    )


def test_evaluation_fails_for_success_and_timeout_regression():
    baseline = [_case("one"), _case("two")]
    candidate = [_case("one"), _case("two", success=False, timeout=True)]
    result = evaluate_population(baseline, candidate, {
        "minimum_cases": 2,
        "minimum_pair_coverage": 1.0,
        "missing_case_policy": "INSUFFICIENT_DATA",
        "rules": [
            {"metric": "candidate_success_rate", "operator": ">=", "value": 0.75},
            {"metric": "candidate_timeout_rate", "operator": "<=", "value": 0.25},
        ],
    })
    assert result.decision == "FAIL"
    assert {reason["reason"] for reason in result.reasons} == {"success_rate_regression", "timeout_rate_regression"}
    assert result.metrics["matched_cases"] == 2


def test_evaluation_requires_paired_sample_and_keeps_missing_tokens_unavailable():
    result = evaluate_population([_case("one"), _case("two")], [_case("one")], {
        "minimum_cases": 2, "minimum_pair_coverage": 1.0,
        "missing_case_policy": "INSUFFICIENT_DATA", "rules": [],
    })
    assert result.decision == "INSUFFICIENT_DATA"
    assert result.metrics["missing_candidate_cases"] == ["two"]
    assert result.metrics["candidate_input_tokens_mean"] is None
