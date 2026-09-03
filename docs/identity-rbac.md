# V13 Human Identity, Organizations, and RBAC

AgentGuard is an OpenID Connect relying party for human operators. It does not
store passwords or implement social authentication. A deployment trusts one
operator-configured issuer; browser, tenant, telemetry, and AI-controlled input
cannot select another issuer.

## Identity and protocol boundary

Human identity is the immutable `(issuer, subject)` pair. Email and display
name are presentation metadata and are never identity keys or authorization
inputs. Login uses Authorization Code, PKCE S256, high-entropy state and nonce,
short-lived one-use login attempts, bounded discovery/token/JWKS responses,
explicit RS256 verification, and issuer/audience/time/nonce validation. JWKS
is cached for a bounded interval and refreshed once when a trusted issuer
rotates its signing key. Provider access and refresh tokens are not persisted.

Production and staging issuer, discovery, token, JWKS, and redirect URLs must
use HTTPS without embedded credentials. The HTTP exception for localhost and
`host.docker.internal` exists only in `AGENTGUARD_ENVIRONMENT=test` for the
isolated integration fixture.

If a confidential client is required, supply its secret through
`AGENTGUARD_OIDC_CLIENT_SECRET_FILE` from an external secret manager and mount
it only into `agentguard-server`. Never place it in Compose source, `.env`, an
image, release manifest, log, or browser response.

## Organizations and permissions

Each Organization maps one-to-one to an existing Tenant. A HumanUser may hold
multiple independent OrganizationMembership records. Multi-organization login
creates an unselected session and requires an explicit, server-validated
organization choice before tenant data is available.

Roles are fixed and deny unknown permissions by default:

- `VIEWER`: bounded read access to dashboard, traces, integrity, analyses,
  incidents, evaluations, notifications, and system status.
- `ENGINEER`: VIEWER plus incident lifecycle, deterministic analysis, safe
  replay, and evaluation execution.
- `ADMIN`: ENGINEER plus membership, tenant-scoped machine API-key,
  notification, and evaluation administration.

An ADMIN does not gain database, migration, shell, Docker, deployment,
arbitrary HTTP, raw-secret, or cross-tenant authority. Role and membership are
reloaded on every dashboard request, so demotion, membership disablement, user
disablement, API-key revocation, and expiry take effect immediately. The final
active ADMIN cannot be demoted or disabled; PostgreSQL row locks serialize that
guard.

## Bootstrap and machine credentials

The first ADMIN is created only by the explicit one-shot operator command:

```text
agentguard-server identity bootstrap-admin --tenant TENANT --subject OIDC_SUBJECT
```

`AGENTGUARD_OIDC_ISSUER` supplies the trusted issuer. The command refuses once
an active administrator exists. There is no email-based invitation or implicit
first-login provisioning.

Machine API keys remain separate tenant/scoped principals for SDK, OTLP,
automation, CI, and APIs. They are never converted to HumanUser rows. Human
ADMINs may list key metadata, create a bounded-scope key whose secret is shown
once, and revoke tenant keys. Existing secrets are never displayed. Legacy V12
browser API-key sessions can be retained explicitly with
`AGENTGUARD_DASHBOARD_API_KEY_LOGIN_ENABLED=true`; OIDC deployments should keep
the safer default `false` unless compatibility requires it.

## Audit, recovery, and limitations

Human login/logout, organization selection, bootstrap, membership, role, and
API-key administration produce append-only `identity_audit_events` containing
safe identifiers and bounded metadata, never OIDC tokens or secrets. Migration
`0010_human_identity_rbac` grants runtime only the application operations it
needs; runtime has no identity-table DELETE or schema/database CREATE.

Current limitations are one configured issuer, no SCIM/SAML/LDAP, no automatic
just-in-time provisioning, process-local login rate limiting, and
operator-managed session revocation after disaster recovery.


## V14 cross-instance identity

OIDC state, nonce hashes, and the PKCE verifier are stored in the shared
database. A callback may complete on another replica, while row-locked
one-time consumption rejects concurrent and replayed callbacks. Current
membership and role remain database authority.