SPOOL_SCHEMA = """
CREATE TABLE IF NOT EXISTS spool_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    payload_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT,
    last_attempt_at TEXT,
    last_error TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'inflight', 'dead_letter'))
);
CREATE INDEX IF NOT EXISTS ix_spool_pending_due
    ON spool_events(status, next_attempt_at, sequence);
CREATE INDEX IF NOT EXISTS ix_spool_status ON spool_events(status);
CREATE TABLE IF NOT EXISTS spool_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

