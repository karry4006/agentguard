# AgentGuard V14 Distributed Coordination

V14 makes the PostgreSQL database the authority for coordination shared by
multiple AgentGuard server replicas. Two or more stateless FastAPI processes
may use the same database without sticky sessions or a permanent leader.

## Coordination model

PostgreSQL was selected because AgentGuard already requires it in production
and its transactions, unique constraints, row locks, SKIP LOCKED, and atomic
upserts are sufficient for the coordination state used here. Redis, Kafka,
Celery, and a leader-election service are not required.

Each process has a bounded non-secret AGENTGUARD_INSTANCE_ID (or a random
startup ID). It is diagnostic metadata and a lease label, never an
authentication credential. Notification claims also carry an unpredictable
per-claim token, so accidentally reusing an instance ID does not authorize a
second worker.

## Shared rate limiting

Server request paths use a deterministic SHA-256 storage key and a
PostgreSQL-backed fixed-window counter. The logical key contains only a
controlled operation name and tenant or client protection identity; raw URLs,
prompts, errors, telemetry, and secrets are never included. The upsert
increments atomically and caps the stored overflow marker at limit + 1.
The configured limit therefore applies to the combined traffic of all
replicas. A new window starts at the database current time. Old buckets are
removed only by a bounded maintenance operation; request handlers do not
need DELETE privilege.

Security-sensitive login, OIDC, control-plane, and API paths fail closed when
the coordination store is unavailable. SDK export behavior remains fail-open
for the monitored application because it does not depend on server
coordination.

## Notification claims and leases

Pending and retryable deliveries are claimed with a row lock. The claim
stores claimed_by, a per-claim token, claim timestamps, and a bounded lease
expiry. An expired claim is reclaimable by another worker. Final state writes
are conditional on the claim token, which prevents a stale worker from
completing a delivery after its lease was reclaimed.

Webhook delivery remains at-least-once. If a worker commits a claim, the
webhook accepts the request, and the worker crashes before committing
DELIVERED, another worker may send the same physical request after lease
expiry. The stable delivery ID and signature timestamp headers allow a
destination to deduplicate. Exactly-once external delivery is not claimed.

## Shared circuit breaker

Circuit state is one durable row per destination and preserves CLOSED, OPEN,
and HALF_OPEN. Failure counts and open intervals are shared across replicas.
When the open interval expires, a single probe lease globally authorizes a
HALF_OPEN probe. Success closes the breaker; a probe failure reopens it.

## Sessions, RBAC, and OIDC

Dashboard sessions, revocation, API-key status, human membership, and role
are read from PostgreSQL on every authenticated request. There is no
authorization cache that can delay logout or RBAC revocation.

OIDC state, nonce hash, PKCE verifier, safe return path, and one-time used_at
are stored in oidc_login_attempts. Callback consumption uses a database row
lock and is committed before token exchange, so an A-to-B callback works and
a concurrent or replayed callback is rejected. JWKS and discovery caches may
remain per-process because they are bounded protocol caches, not login
authority.

## Pooling and failure behavior

Every replica has its own SQLAlchemy pool. Size the sum of all replica
pools, overflow, migration jobs, and operational connections below the
PostgreSQL connection budget. Readiness fails when the database cannot be
reached or the migration head is stale. Recovery is automatic once the
database becomes reachable again. Security-sensitive requests return a
bounded unavailable response rather than inventing authority.

## Backup and disaster recovery

Coordination rows are disposable runtime state. Restoring them is safe:
active notification leases naturally expire, rate-limit windows age out, and
OIDC attempts remain subject to their expiry and one-time-use fields. A
restore must not revive an expired login transaction. Restore validation must
run the full migration chain and must not weaken runtime privileges.

V14 is single-PostgreSQL-cluster HA. It does not provide global multi-region
consensus, cross-region clock/network validation, or exactly-once webhook
delivery. PostgreSQL is now an explicit dependency for shared security and
control-plane correctness.

## Deployment checklist

Run the migration container once against the shared database, then run N
replicas with the same database URL, pepper, integrity key, OIDC
configuration, and notification policy. Give replicas distinct bounded
instance IDs, use a load balancer without sticky sessions, and expose
/health/live and /health/ready for health and readiness checks. Keep
replica pool sizes conservative and monitor database connection saturation,
rate-limit writes, lease reclaim counts, circuit state, and coordination
errors.