# V12/V13 Secure Web Dashboard & Operator Console

The V12 console is a server-rendered presentation and control layer on the
existing FastAPI services. It is not a shell, deployment system, remediation
engine, arbitrary HTTP client, or generic MCP client. Production has no Node.js
runtime, external fonts, CDN assets, analytics, or third-party JavaScript.

## Login and session boundary

V13 adds OIDC human sessions and organization RBAC while retaining the V12
opaque session, CSRF, CSP, and tenant-query boundaries. See
[identity-rbac.md](identity-rbac.md). Human sessions store only the HumanUser
and selected Organization references; every request reloads user, membership,
role, organization, and tenant state. OIDC tokens are never stored in the
browser session or database.

`POST /ui/login` accepts an AgentGuard API key once. The key must authenticate
through the existing V2 path and include `dashboard:access`; existing keys are
not auto-granted this scope. The browser receives only an opaque
`agentguard_session` cookie. The database stores SHA-256 hashes of the session
token and a derived CSRF token, never either plaintext value or the API key.

Sessions last eight hours by default, have a one-hour idle timeout, and are
limited to five active sessions per API key. Login attempts are bounded by a
process-local limiter. Logout sets `revoked_at`; cookie deletion is only a
convenience. Every request rechecks the originating API key's presence,
expiration, revocation, tenant, and current scopes, so API-key revocation
invalidates existing sessions.

The production cookie is `HttpOnly; Secure; SameSite=Strict; Path=/`. All
state-changing routes are POST-only and require a constant-time CSRF check
tied to the session. Return paths are relative same-origin paths only.

## Data and action policy

Every page is tenant-scoped and bounded (50 rows for paginated lists, 100 for
notification/evaluation views). Incident lifecycle actions reuse V10
`transition_incident`; analysis reuses V5 deterministic analysis; optional
replay is explicitly V4 `DRY_RUN` only. No dashboard action executes tools,
opens a shell, or changes deployment state.

Telemetry and AI output are plain text under Jinja autoescaping. Raw prompts,
model output, tool content, credentials, API-key hashes, webhook secrets, and
database URLs are not displayed. With content capture disabled the trace page
shows `CONTENT NOT CAPTURED`; enabling capture never automatically exposes it.
Integrity labels are rendered from V3 truth, and AI findings are labeled as
advisory. V8 results retain their backend gate decision.

The response CSP is self-only with no `unsafe-inline` or `unsafe-eval`, and
the app sets `nosniff`, `no-store`, `no-referrer`, `frame-ancestors 'none'`,
`X-Frame-Options: DENY`, and a restrictive Permissions-Policy.

## Recovery and limitations

Dashboard sessions are included in PostgreSQL backups. After disaster recovery,
operators should conservatively revoke restored sessions before resuming
operator access. API-key revocation and expiry remain authoritative. Session
cleanup is bounded by filtering and does not require runtime `DELETE`.

There is no local human username/password system, SAML, SCIM, LDAP, third-party
analytics, or raw sensitive trace-content browser. OIDC supports one trusted
operator-configured issuer. Rate limiting remains process-local and session
cleanup is not yet a distributed maintenance worker.


## V14 cross-instance behavior

Dashboard sessions and current API-key, membership, and role state are read
from PostgreSQL on each request. Login on one replica, logout or revocation
on another, and role changes therefore take effect without sticky sessions
or an authorization cache.
## Integrity anchors

The V15 system view may show local checkpoint sequence/time, last successful
anchor, explicit verification/freshness state, continuity state, and signer key
ID. Do not display private keys, raw public-key configuration, raw signatures, or
local tenant-chain entries by default.
