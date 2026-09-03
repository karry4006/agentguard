# AgentGuard V11 Secure Notification & Alerting

V11 sends trusted, server-side incident decisions to generic HTTPS webhooks.
Telemetry, incident text, and model output are data only; they cannot select a
destination, change severity, disable cooldowns, or execute a notification rule.

## Configuration

`notifications:manage` creates destinations and policies. `notifications:read`
lists them and delivery status. Existing API keys are not granted either scope.
The destination response contains only normalized scheme/host/port/path and a
secret reference; it never returns a secret value.

The canonical Compose configuration has `AGENTGUARD_ALLOW_PRIVATE_WEBHOOK_TESTS`
set to false. HTTPS is required, DNS is resolved completely, private/internal
addresses are rejected, redirects are disabled, and POST is the only method.
An operator may use an allowlist with
`AGENTGUARD_NOTIFICATION_ALLOWED_WEBHOOK_HOSTS`. The private HTTP exception is
accepted only in `AGENTGUARD_ENVIRONMENT=test`; production configuration rejects
it.

Signing is optional and uses a separate protected
`AGENTGUARD_NOTIFICATION_SIGNING_SECRET_FILE`, never the V3 integrity key, API
key pepper, or a database password. The signature is HMAC-SHA256 over
`timestamp + "." + exact payload bytes` and is sent in
`X-AgentGuard-Signature` with `X-AgentGuard-Timestamp`.

## Payload and delivery

The fixed `webhook-v1` payload contains only event, incident id, trusted
severity/status/title/category, bounded occurrence count, timestamps, and trend.
Prompts, model output, tool arguments/results, credentials, authorization
headers, PII, and raw error content are excluded.

An intent is committed before outbound I/O. Delivery identity is a stable
tenant/incident/event/policy/destination/lifecycle key, so duplicate retries do
not create another logical event. HTTP delivery is at-least-once: a receiver
must deduplicate `X-AgentGuard-Delivery-Id`. Only timeout/reset, 408/425, 429,
and 5xx failures retry, with bounded exponential delay and bounded
`Retry-After`. 401/403/404 do not tight-loop. A per-destination bounded
closed/open/half-open circuit breaker prevents storms. Delivery failures never
rollback incidents, mutate evidence, or invoke replay/remediation.

The dispatch endpoint is an operator-controlled delivery attempt seam:
`POST /v1/notification-deliveries/{id}/dispatch`. It is not automatic replay.
Pending intents remain in PostgreSQL and can be dispatched after a server
restart.

## Recovery and residual risks

Backups include destination metadata, policy, and delivery history. Signing
secret files are external to the database backup and must be restored through
the protected secret configuration before delivery resumes.

Residual risks are at-least-once external delivery, DNS/network trust at the
webhook boundary, destination outage, minimized metadata exposure, and the
existing process-local rate/circuit state. Provider-specific adapters are out
of scope for V11.


## V14 distributed dispatch

Notification workers claim rows with PostgreSQL locks and per-claim leases.
Expired claims are reclaimable, while final writes require the claim token.
Delivery remains at-least-once: a crash after webhook acceptance can cause
a physical duplicate, so consumers should deduplicate by delivery ID.