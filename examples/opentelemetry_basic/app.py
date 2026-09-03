"""Synthetic OpenTelemetry GenAI workflow for AgentGuard V6."""

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

from agentguard import AgentGuardConfig, AgentGuardOpenTelemetrySpanProcessor


def main() -> None:
    provider = TracerProvider()
    processor = AgentGuardOpenTelemetrySpanProcessor(config=AgentGuardConfig.from_env())
    provider.add_span_processor(processor)
    tracer = provider.get_tracer("agentguard-opentelemetry-basic")

    with tracer.start_as_current_span("workflow", attributes={
        "gen_ai.operation.name": "invoke_workflow",
        "gen_ai.provider.name": "generic",
    }) as workflow:
        trace_id = f"{workflow.get_span_context().trace_id:032x}"
        with tracer.start_as_current_span("agent", attributes={"gen_ai.operation.name": "invoke_agent"}):
            with tracer.start_as_current_span("local-model", attributes={
                "gen_ai.operation.name": "chat",
                "gen_ai.provider.name": "openai",
                "gen_ai.input.messages": "synthetic content is redacted by default",
            }):
                with tracer.start_as_current_span("local-tool", attributes={
                    "gen_ai.operation.name": "execute_tool",
                    "tool.name": "deterministic_fixture",
                }):
                    pass

    processor.force_flush(5000)
    provider.shutdown()
    print(f"AgentGuard OpenTelemetry trace emitted: {trace_id}")


if __name__ == "__main__":
    main()
