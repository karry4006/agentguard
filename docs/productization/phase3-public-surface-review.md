# AgentGuard 1.0 — Phase 3 public surface review

## Review result

The public surface now leads with the product role: AgentGuard is an AI-agent
flight recorder and reliability/debugging platform, not another agent. The
README first screen states the workflows and links to deterministic examples,
the architecture visual, API reference, and limitation-aware docs.

## Stranger test

| Question | Answer |
| --- | --- |
| What is this? | A recorder and evidence/debugging layer around an AI-agent application. |
| Who is it for? | Teams that need inspectable agent runs, failure boundaries, replay safety, and regression evidence. |
| What does it not do? | It does not reason, plan, execute tools, provide hosted service, or guarantee security/compliance. |
| Can I try it without a paid API? | Yes. Quick Start and all primary demos use a local deterministic fixture. |
| What is the first command? | `scripts/bootstrap-dev.ps1`, then `docker compose up --build -d` and `python examples/basic_agent/run.py`. |
| How is evidence used? | Integrity verification gates analysis/replay; valid quorum conflicts block destructive actions. |
| What remains optional? | OpenAI, OpenTelemetry, archive, witness, OIDC, and external anchoring integrations. |

## Visual and demo material

`docs/assets/agentguard-overview.svg` is a clean local-topology visual with no
user data. `examples/README.md` indexes six primary demos and two optional
integrations. Each primary demo documents expected output and cleanup.

## Deliberate limitations

The local topology uses loopback HTTP, one PostgreSQL instance, local
credentials, and no external witness or archive. The RC is not publicly
released, no PyPI or container publication is performed, and the OpenAI path
is not required for acceptance. A security reporting channel remains blocked
by the current GitHub configuration; this keeps `PUBLIC_RELEASE_READY=NO`.

## Audit notes

Claims were reviewed for absolute security, compliance, superiority, and
hosted-service language. The public docs distinguish deterministic local
capabilities from optional integrations and do not alter historical V20
acceptance evidence.
