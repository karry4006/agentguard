"""A deterministic AgentGuard SDK demo; no model or paid API is required."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from agentguard import AgentGuardConfig, AgentGuardTracingProcessor


def now() -> datetime:
    return datetime.now(timezone.utc)


def main() -> None:
    config = AgentGuardConfig.from_env()
    if not config.api_key:
        raise SystemExit(
            "Set AGENTGUARD_API_KEY to the one-time key created by the Quick Start."
        )

    trace_id = str(uuid4())
    agent_span_id = str(uuid4())
    tool_span_id = str(uuid4())
    processor = AgentGuardTracingProcessor(config)
    trace = SimpleNamespace(
        trace_id=trace_id,
        workflow_name="basic-agent-demo",
        provider="local-demo",
        metadata={"demo": True},
    )
    agent_span = SimpleNamespace(
        span_id=agent_span_id,
        trace_id=trace_id,
        span_type="agent",
        name="answer-question",
        attributes={"question": "What is 2 + 2?"},
    )
    tool_span = SimpleNamespace(
        span_id=tool_span_id,
        trace_id=trace_id,
        parent_span_id=agent_span_id,
        span_type="tool",
        name="calculator",
        attributes={"operation": "addition", "result": 4},
    )

    try:
        processor.on_trace_start(trace)
        processor.on_span_start(agent_span)
        processor.on_span_start(tool_span)
        tool_span.ended_at = now()
        tool_span.status = "success"
        processor.on_span_end(tool_span)
        agent_span.ended_at = now()
        agent_span.status = "success"
        processor.on_span_end(agent_span)
        trace.ended_at = now()
        trace.status = "success"
        processor.on_trace_end(trace)
        if not processor.force_flush():
            raise SystemExit("AgentGuard exporter did not flush within 10 seconds.")
    finally:
        processor.shutdown()

    print(f"trace_id={trace_id}")
    print("result=4")
    print("status=success")


if __name__ == "__main__":
    main()
