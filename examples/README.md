# AgentGuard examples

The examples are intentionally deterministic and do not require a paid model
API. Start with the basic demo after the Quick Start, then use the failure,
replay, regression, integrity, and quorum demos to explore the product seams.

| Demo | Teaches | External API? | Time | Topology | Level |
| --- | --- | --- | --- | --- | --- |
| `basic_agent/run.py` | SDK spans, tool call, trace ID | No | 1 min | Compose server | Beginner |
| `failure_demo/run.py` | Deterministic failure analysis | No | <1 sec | Disposable SQLite | Beginner |
| `replay_demo/run.py` | Dry-run replay and simulator match | No | <1 sec | Disposable SQLite | Beginner |
| `regression_demo/run.py` | Baseline/candidate gate | No | <1 sec | In-memory | Beginner |
| `integrity_demo/run.py` | Tamper detection | No | <1 sec | Disposable SQLite | Advanced |
| `quorum_demo/run.py` | V20 degraded match and conflict block | No | <1 sec | In-memory witnesses | Advanced |
| `openai_basic/demo.py` | Optional OpenAI Agents adapter | Optional | API-dependent | Compose server | Advanced |
| `opentelemetry_basic/app.py` | Optional OTLP bridge | Optional | API-dependent | Compose collector | Advanced |

Each demo directory documents expected output and cleanup. `openai_basic` and
`opentelemetry_basic` remain optional integrations, not primary acceptance
paths.
