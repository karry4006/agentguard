# AgentGuard V19 residual risks

These are operational risks retained after V19 implementation and must remain
visible in release evidence:

- Loss of all V19 replicas can make compacted V3 integrity history unavailable.
- Loss of a historical V3 HMAC key makes archived integrity evidence unverifiable.
- Loss of an archive-encryption key makes the corresponding segments unreadable.
- Replicas on the same provider or account are not fully independent.
- V15 provides continuity and tamper detection, not archive availability.
- Provider object lifecycle policies remain an availability risk.
- Current chain heads and the configured hot tail remain in PostgreSQL.
- PostgreSQL physical files may not shrink immediately after deletion.
- `VACUUM FULL`, `CLUSTER`, table rewrites, and automatic disk reclamation are
  intentionally outside V19.
- The archive metadata catalog continues to grow.
- Supply-chain license and attestation residuals remain where the approved
  Docker Scout policy records them.
