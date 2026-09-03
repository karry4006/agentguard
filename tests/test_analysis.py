import pytest
from types import SimpleNamespace

from agentguard_server.services.analysis import (
    AnalysisRefused,
    FailureCategory,
    FindingSource,
    analyze_trace,
    detect_findings,
    persist_analysis,
    validate_ai_judgment,
)
from agentguard_server.schemas.events import Event
from agentguard_server.services.auth import create_tenant
from agentguard_server.services.ingestion import ingest_events
from agentguard_server.models import AnalysisRun


def span(span_id, *, parent=None, span_type="tool", name="tool", status="success", attributes=None, error_type=None):
    return SimpleNamespace(span_id=span_id, parent_span_id=parent, span_type=span_type, name=name,
                           status=status, attributes=attributes or {}, error_type=error_type,
                           error_message=None)


def test_deterministic_detectors_classify_structured_failures_and_separate_root_from_symptom():
    spans = [
        span("route", name="wrong_tool", status="success", attributes={"status_code": 403}),
        span("timeout", parent="route", name="get_weather", status="error", error_type="TimeoutError"),
        span("final", parent="timeout", span_type="agent", name="final_answer", status="error"),
    ]
    findings = detect_findings(spans)
    categories = {finding.category for finding in findings}
    assert FailureCategory.AUTHORIZATION in categories
    assert FailureCategory.TIMEOUT in categories
    assert findings[-1].source == FindingSource.DETERMINISTIC
    assert any(f.root_cause_span_id == "route" and f.symptom_span_id == "route" for f in findings)
    assert any(f.root_cause_span_id == "timeout" and f.symptom_span_id == "timeout" for f in findings)


def test_loop_and_excessive_tool_use_are_bounded_findings():
    spans = [span(f"s{i}", name="search", attributes={"status_code": 429}) for i in range(4)]
    findings = detect_findings(spans, loop_threshold=3, max_tool_spans=3)
    assert any(f.category == FailureCategory.LOOP_OR_REPETITION for f in findings)
    assert any(f.category == FailureCategory.RATE_LIMIT for f in findings)
    assert any(f.category == FailureCategory.ENVIRONMENT_DRIFT for f in findings)


def test_detector_handles_bounded_thousand_span_packet():
    findings = detect_findings([span(f"s{i}", name=f"tool-{i}") for i in range(1000)], max_tool_spans=1000)
    assert findings == []


def test_ai_judgment_rejects_unknown_category_confidence_and_evidence_ids():
    packet = {"span_ids": {"root", "symptom"}, "event_ids": {"event-1"}, "replay_ids": set()}
    with pytest.raises(ValueError, match="evidence"):
        validate_ai_judgment({"category": "UNKNOWN_NEW", "model_confidence": 0.8,
                              "root_cause_span_id": "not-supplied", "symptom_span_id": "symptom",
                              "evidence_span_ids": ["not-supplied"], "evidence_event_ids": [], "reason": "x"}, packet)
    with pytest.raises(ValueError, match="confidence"):
        validate_ai_judgment({"category": "TIMEOUT", "model_confidence": 2,
                              "root_cause_span_id": "root", "symptom_span_id": "symptom",
                              "evidence_span_ids": ["root"], "evidence_event_ids": [], "reason": "x"}, packet)


def test_analysis_is_integrity_gated_and_ai_failure_keeps_deterministic_findings(db_session):
    tenant = create_tenant(db_session, "analysis-engine-test", "Analysis engine")
    trace_id = "analysis-trace"
    events = [
        Event(event_type="trace.started", event_id="analysis-start", data={"trace_id": trace_id}),
        Event(event_type="span.started", event_id="analysis-timeout", data={"trace_id": trace_id, "span_id": "timeout-span", "span_type": "tool", "name": "tool", "status": "error", "error_type": "TimeoutError"}),
        Event(event_type="trace.ended", event_id="analysis-end", data={"trace_id": trace_id, "status": "success"}),
    ]
    ingest_events(db_session, events, tenant.id, capture_content=True)
    class FailingJudge:
        def analyze(self, packet):
            raise TimeoutError("provider timeout")
    report, packet = analyze_trace(db_session, tenant.id, trace_id, mode="ai_assisted", judge=FailingJudge())
    assert report.ai_status == "failed"
    assert report.findings[0].category == FailureCategory.TIMEOUT
    assert packet["span_ids"] == {"timeout-span"}
    run = persist_analysis(db_session, tenant_id=tenant.id, report=report, mode="ai_assisted")
    assert db_session.get(AnalysisRun, run.id).ai_status == "failed"

    db_session.query(AnalysisRun).filter_by(id=run.id).delete()
    db_session.commit()
    from agentguard_server.models import IntegrityRecord
    db_session.query(IntegrityRecord).filter_by(tenant_id=tenant.id, trace_id=trace_id).first().key_id = "missing"
    db_session.commit()
    with pytest.raises(AnalysisRefused) as exc_info:
        analyze_trace(db_session, tenant.id, trace_id)
    assert exc_info.value.reason == "ANALYSIS_REFUSED_INTEGRITY"
