import json
import threading
from pathlib import Path

from agentguard import AgentGuardConfig
from agentguard.exporter import AuthFailure, HttpBatchExporter
from agentguard.spool import SQLiteSpool


def telemetry(event_id="event-1", event_type="span.ended"):
    return {"event_id": event_id, "event_type": event_type, "data": {"attributes": {"ok": True}}}


def test_sqlite_spool_insert_duplicate_batch_and_ack(tmp_path):
    spool = SQLiteSpool(tmp_path / "spool.sqlite3")
    assert spool.put(telemetry()) is True
    assert spool.put(telemetry()) is False
    batch = spool.get_batch(10)
    assert len(batch) == 1
    assert batch[0].event_id == "span.ended:event-1"
    assert batch[0].status == "inflight"
    assert batch[0].attempt_count == 1
    spool.acknowledge([batch[0].event_id])
    assert spool.stats().pending == 0
    assert spool.stats().inflight == 0
    spool.close()


def test_retry_persists_metadata_and_backoff(tmp_path):
    spool = SQLiteSpool(tmp_path / "spool.sqlite3", max_retries=3)
    spool.put(telemetry())
    spool.get_batch(1)
    spool.retry(["span.ended:event-1"], "Bearer sk-secret")
    assert spool.stats().pending == 1
    spool.wake_pending()
    retry_batch = spool.get_batch(1)
    assert retry_batch[0].attempt_count == 2
    assert retry_batch[0].last_error == "Bearer sk-secret"
    spool.close()


def test_restart_recovers_inflight_rows(tmp_path):
    path = tmp_path / "spool.sqlite3"
    first = SQLiteSpool(path)
    first.put(telemetry())
    first.get_batch(1)
    first.close()
    second = SQLiteSpool(path)
    assert second.stats().pending == 1
    assert len(second.get_batch(1)) == 1
    second.close()


def test_wal_and_max_spool_limit(tmp_path):
    spool = SQLiteSpool(tmp_path / "spool.sqlite3", max_events=1, max_bytes=10000)
    journal_mode = spool._connection.execute("PRAGMA journal_mode").fetchone()[0]
    assert journal_mode.lower() == "wal"
    assert spool.put(telemetry("first")) is True
    assert spool.put(telemetry("second")) is False
    assert spool.stats().rejected_events == 1
    spool.close()


def test_redaction_happens_before_spool_persistence(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    def blocked_send(batch):
        entered.set()
        release.wait(2)

    spool = SQLiteSpool(tmp_path / "spool.sqlite3")
    exporter = HttpBatchExporter(AgentGuardConfig(spool_path=str(tmp_path / "spool.sqlite3")), send_batch=blocked_send, spool=spool)
    exporter.submit({"event_id": "secret-event", "event_type": "custom", "Authorization": "Bearer top-secret", "data": {"prompt": "private"}})
    assert entered.wait(1)
    row = spool._connection.execute("SELECT payload FROM spool_events WHERE event_id='custom:secret-event'").fetchone()
    assert "top-secret" not in row[0]
    assert "CONTENT_CAPTURE_DISABLED" in row[0]
    release.set()
    exporter.shutdown()


def test_outage_restart_recovery_and_ack(tmp_path):
    path = tmp_path / "spool.sqlite3"
    state = {"available": False, "calls": 0}

    def send(batch):
        state["calls"] += 1
        if not state["available"]:
            raise ConnectionError("connection refused")

    first = HttpBatchExporter(AgentGuardConfig(spool_path=str(path), max_retries=5, flush_interval_seconds=0.01), send_batch=send)
    assert first.submit(telemetry("restart-event"))
    assert first.force_flush(2)
    first.shutdown(2)
    recovered = SQLiteSpool(path)
    assert recovered.stats().pending == 1
    recovered.close()

    state["available"] = True
    second = HttpBatchExporter(AgentGuardConfig(spool_path=str(path), max_retries=5, flush_interval_seconds=0.01), send_batch=send)
    assert second.force_flush(2)
    assert second.diagnostics()["pending_events"] == 0
    second.shutdown(2)
    assert state["calls"] >= 2


def test_force_flush_failure_retains_event_and_diagnostics(tmp_path):
    path = tmp_path / "spool.sqlite3"

    def fail(_batch):
        raise RuntimeError("HTTP 500 sk-do-not-persist")

    exporter = HttpBatchExporter(AgentGuardConfig(spool_path=str(path), max_retries=10), send_batch=fail)
    assert exporter.submit(telemetry("failed-event"))
    assert exporter.force_flush(2)
    diagnostics = exporter.diagnostics()
    assert diagnostics["pending_events"] == 1
    assert diagnostics["retry_count"] >= 1
    assert "sk-do-not-persist" not in diagnostics["last_exporter_error"]
    exporter.shutdown(1)


def test_auth_failure_retains_spool_and_enters_cooldown(tmp_path):
    path = tmp_path / "auth-spool.sqlite3"

    def reject(_batch):
        raise AuthFailure("HTTP 401 authentication/authorization failure")

    exporter = HttpBatchExporter(AgentGuardConfig(spool_path=str(path), max_retries=10, auth_cooldown_seconds=60), send_batch=reject)
    assert exporter.submit(telemetry("auth-event"))
    assert exporter.force_flush(2)
    diagnostics = exporter.diagnostics()
    assert diagnostics["pending_events"] == 1
    assert diagnostics["auth_failures"] == 1
    exporter.shutdown(1)


def test_unwritable_spool_fails_open_to_memory(tmp_path):
    bad_path = tmp_path / "spool-directory"
    bad_path.mkdir()
    exporter = HttpBatchExporter(AgentGuardConfig(spool_path=str(bad_path)))
    assert exporter.submit(telemetry("fallback-event")) is True
    assert exporter.diagnostics()["errors"] >= 1
    exporter.shutdown()
