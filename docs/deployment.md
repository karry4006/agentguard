# Deployment guidance

Compose is the canonical local deployment. It is useful for development,
migration checks, and a single-node evaluation. It is not an HA claim and
does not create independent witness or archive failure domains.

For production, provide TLS termination, externally managed secrets, managed
PostgreSQL with backups and restore drills, explicit database role separation,
OIDC or another approved identity provider, rate and size limits, structured
logs, metrics, traces, alerting, and a tested key-rotation procedure.
Independent archive and witness locations must have genuinely independent
credentials, storage, and failure domains.

Pin application and image versions, review migrations before rollout, use a
forward-only migration process, and preserve release evidence separately from
runtime data. A production candidate image built during Phase 1 is distinct
from the sealed V20 image; V20 Scout results must not be presented as a scan
of that new candidate.

See docs/production-deployment.md and docs/disaster-recovery.md for the
detailed operational controls.
