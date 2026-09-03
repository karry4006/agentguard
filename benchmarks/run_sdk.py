from __future__ import annotations

import json
from types import SimpleNamespace

from agentguard import AgentGuardConfig, AgentGuardTracingProcessor
from agentguard.exporter import HttpBatchExporter
from agentguard.spool import SQLiteSpool

from support import summary, timing


def instrumented_once(processor, index: int) -> None:
    trace_id = f"benchmark-{index}"
    span = SimpleNamespace(span_id=f"span-{index}", trace_id=trace_id, span_type="tool", name="get_weather",
                           attributes={"city": "Kaohsiung"})
    processor.on_span_start(span); processor.on_span_end(span)


def plain_once(index: int) -> None:
    payload = {"trace_id": f"benchmark-{index}", "span_id": f"span-{index}", "name": "get_weather", "status": "success"}
    _ = payload["span_id"]


def main() -> None:
    warmup, iterations = 20, 500
    config = AgentGuardConfig(ingest_url="http://127.0.0.1:9", api_key="benchmark")
    processor = AgentGuardTracingProcessor(config, exporter=HttpBatchExporter(config, send_batch=lambda batch: None,
                                                                              spool=SQLiteSpool(":memory:")))
    for _ in range(warmup):
        plain_once(_); instrumented_once(processor, _)
    counter = [warmup]
    def next_plain():
        plain_once(counter[0]); counter[0] += 1
    def next_instrumented():
        instrumented_once(processor, counter[0]); counter[0] += 1
    plain = timing(next_plain, iterations)
    instrumented = timing(next_instrumented, iterations)
    processor.force_flush(); processor.shutdown()
    result = {"benchmark": "sdk_event_path", "sample_count": iterations,
              "warmup": warmup, "plain": summary(plain), "instrumented": summary(instrumented),
              "relative_overhead": round((sum(instrumented) / sum(plain)) - 1, 4),
              "notes": "Local exporter callback and in-memory SQLite spool; no network or paid API."}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
