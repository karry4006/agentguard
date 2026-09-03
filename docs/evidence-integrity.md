# Evidence integrity

AgentGuard’s integrity chain supports tamper-evident trace history and
verification workflows. Integrity evidence should be kept separate from
ordinary application data and checked after restore, replication, archive
transfer, and key rotation.

External anchoring, archive encryption, witness quorum, and ledger segment
archival are optional operational layers. They do not make an untrusted
application payload authoritative and do not eliminate key-management or
failure-domain risk.

See docs/external-integrity-anchoring.md, docs/evidence-retention-archival.md,
docs/ledger-segment-archival.md, and docs/v20-multi-witness-quorum.md.
