"""Minimal OpenAI Agents SDK run wired to AgentGuard.

Run with OPENAI_API_KEY set and the server running. No prompt/tool payload is
captured by default; only structural telemetry is exported.
"""
import asyncio
import os

from agentguard import AgentGuardConfig, AgentGuardTracingProcessor


def get_weather(city: str) -> str:
    """Deterministic demo tool: no external weather request is made."""
    return {"Kaohsiung": "Kaohsiung: sunny, 30C"}.get(city, f"{city}: sunny, 30C")


async def main() -> None:
    if not os.getenv("OPENAI_API_KEY"):
        raise SystemExit("Set OPENAI_API_KEY to run this demo (the key is never traced).")
    try:
        from agents import Agent, Runner, function_tool, set_trace_processors
    except ImportError as exc:
        raise SystemExit("Install the optional SDK dependency with: pip install -e 'sdk/python[openai]'") from exc

    processor = AgentGuardTracingProcessor(AgentGuardConfig.from_env())
    set_trace_processors([processor])

    weather_tool = function_tool(get_weather)
    agent = Agent(
        name="Weather assistant",
        instructions="Answer weather questions. Use get_weather for the city. Keep the answer concise.",
        tools=[weather_tool],
    )
    try:
        result = await Runner.run(agent, "What is the weather in Kaohsiung?")
        print(result.final_output)
        processor.force_flush()
    finally:
        processor.shutdown()


if __name__ == "__main__":
    asyncio.run(main())

