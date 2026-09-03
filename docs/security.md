# Security model and boundaries

The central rule is: DATA IS NOT AUTHORITY. Trace fields, tool output,
retrieved documents, replay payloads, and model text cannot grant permission
or redefine policy.

AgentGuard enforces tenant identity from a verified API key or configured
identity provider, applies least-privilege scopes, validates schemas, and
keeps security decisions on trusted server-side paths. The product does not
give an LLM direct shell or database authority. Replay is dry-run oriented and
must preserve the original tenant and authorization boundary.

Network-facing integrations apply bounded request handling and SSRF-sensitive
endpoint controls where relevant. They must still be deployed behind
operator-managed network policy and egress controls.

Evidence integrity uses server-side cryptographic chaining and protected key
material. Archive, witness, quorum, and replication features improve
durability and independent verification, but availability and integrity are
different properties. A healthy dashboard response is not proof that every
external witness is independent.

Residual risks that operators must plan for include:

- compromise of two of three witnesses or a shared failure domain;
- unresolved hard conflicts that require quarantine and human review;
- database, archive, or key compromise, including lost rotation material;
- network partitions and delayed replication;
- downgrade or configuration drift;
- continuity of evidence without guaranteed service availability;
- replica loss where an independent V18-style replica is required;
- the fact that AgentGuard is not PBFT, a blockchain, or a substitute for
  application authorization.

Use TLS and managed secrets in production. Review
docs/threat-model.md, docs/security-audit.md, docs/replay-security.md, and
SECURITY.md before changing security-sensitive code.
