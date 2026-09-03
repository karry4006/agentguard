# Architecture

AgentGuard has two trust boundaries:

1. The SDK observes an application and sends bounded, redacted batches.
2. The API authenticates the tenant and persists the accepted event into
   PostgreSQL.

The basic flow is:

    application -> SDK processor -> bounded spool -> HTTP batch exporter
    exporter -> authenticated ingest API -> tenant-scoped PostgreSQL storage
    API -> trace retrieval and dashboard

SDK delivery is deliberately fail-open for the host application: a recorder
outage must not become an agent outage. The API is fail-closed for identity,
tenant scope, schema validation, and authorization.

Trace and span identifiers are application telemetry identifiers, not
authority. Evidence integrity is maintained by the server-side integrity
chain and its key management. Optional archive, witness, and replication
services add durability and independent verification; they are not required by
the default local topology.

The V20 acceptance environment is defined separately in
tests/compose.v20-live.yaml. It is release evidence, not the normal developer
stack. See the existing detailed documents for dashboard, OTLP, archive,
retention, disaster recovery, and distributed coordination behavior.
