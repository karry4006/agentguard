"""V11 live acceptance against the running PostgreSQL/FastAPI stack."""

from datetime import datetime, timezone
import hashlib
import hmac
import http.server
import json
import os
import queue
import threading
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete, select, create_engine
from sqlalchemy.orm import sessionmaker

from agentguard_server.models import NotificationDelivery, Tenant
from agentguard_server.services.auth import create_api_key, create_tenant


class _Receiver(http.server.BaseHTTPRequestHandler):
    requests = queue.Queue()
    statuses = queue.Queue()

    def do_POST(self):  # noqa: N802
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        self.__class__.requests.put((dict(self.headers), body))
        try:
            status = self.__class__.statuses.get_nowait()
        except queue.Empty:
            status = 200
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        return


@pytest.fixture()
def v11_live_context():
    database_url = os.environ.get("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url or not database_url.startswith(("postgresql", "postgres")):
        pytest.skip("set AGENTGUARD_TEST_DATABASE_URL to run V11 live acceptance")
    engine = create_engine(database_url, future=True, pool_pre_ping=True)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    db = session_factory()
    tenant_ids = []
    try:
        db.execute(select(1))
        tenant_a = create_tenant(db, f"v11-a-{uuid4().hex[:12]}", "V11 temporary tenant A")
        tenant_b = create_tenant(db, f"v11-b-{uuid4().hex[:12]}", "V11 temporary tenant B")
        tenant_ids.extend([tenant_a.id, tenant_b.id])
        pepper = os.environ["AGENTGUARD_KEY_PEPPER"]
        scopes = ["ingest:write", "traces:read", "analysis:run", "incidents:read", "incidents:manage", "notifications:read", "notifications:manage"]
        _, key_a = create_api_key(db, tenant_a, scopes, "v11-a", pepper)
        _, key_b = create_api_key(db, tenant_b, scopes, "v11-b", pepper)
        yield {"db": db, "a": tenant_a, "b": tenant_b, "key_a": key_a, "key_b": key_b}
    finally:
        db.rollback()
        db.execute(delete(Tenant).where(Tenant.id.in_(tenant_ids)))
        db.commit()
        db.close()
        engine.dispose()


def test_live_https_webhook_delivery_signature_dedup_and_tenant_boundary(v11_live_context):
    ctx = v11_live_context
    _Receiver.requests = queue.Queue()
    _Receiver.statuses = queue.Queue()
    receiver_port = int(os.getenv("AGENTGUARD_TEST_RECEIVER_PORT", "0"))
    receiver = http.server.ThreadingHTTPServer(("0.0.0.0", receiver_port), _Receiver)
    thread = threading.Thread(target=receiver.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000")
        with httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {ctx['key_a']}"}, timeout=10) as client:
            destination = client.post("/v1/notification-destinations", json={
                "name": "V11 local receiver", "url": f"http://host.docker.internal:{receiver.server_port}/hook",
                "signing_secret_reference": "v11-default",
            })
            assert destination.status_code == 201, destination.text
            policy = client.post("/v1/alert-policies", json={"name": "high incidents", "minimum_severity": "HIGH"})
            assert policy.status_code == 201, policy.text
            trace_id = f"v11-live-{uuid4().hex}"
            events = [
                {"event_type": "trace.started", "event_id": f"start-{trace_id}", "schema_version": "0.1", "data": {"trace_id": trace_id, "workflow_name": "v11", "status": "running"}},
                {"event_type": "span.started", "event_id": f"span-{trace_id}", "schema_version": "0.1", "data": {"trace_id": trace_id, "span_id": f"span-{trace_id}", "span_type": "tool", "name": "get_weather"}},
                {"event_type": "span.ended", "event_id": f"end-span-{trace_id}", "schema_version": "0.1", "data": {"trace_id": trace_id, "span_id": f"span-{trace_id}", "status": "error", "error_type": "TimeoutError"}},
                {"event_type": "trace.ended", "event_id": f"end-{trace_id}", "schema_version": "0.1", "data": {"trace_id": trace_id, "status": "error"}},
            ]
            assert client.post("/v1/ingest", json={"schema_version": "0.1", "events": events}).status_code == 202
            assert client.post(f"/v1/traces/{trace_id}/analysis", json={"mode": "deterministic"}, headers={"Idempotency-Key": f"v11-{trace_id}"}).status_code == 200
            deliveries = client.get("/v1/notification-deliveries")
            assert deliveries.status_code == 200 and len(deliveries.json()) == 1
            delivery_id = deliveries.json()[0]["id"]
            dispatched = client.post(f"/v1/notification-deliveries/{delivery_id}/dispatch")
            assert dispatched.status_code == 200 and dispatched.json()["status"] == "DELIVERED"
            duplicate = client.post(f"/v1/notification-deliveries/{delivery_id}/dispatch")
            assert duplicate.status_code == 200 and duplicate.json()["status"] == "DELIVERED"
            headers, body = _Receiver.requests.get(timeout=5)
            payload = json.loads(body)
            assert payload["schema_version"] == "webhook-v1"
            assert payload["event"] == "INCIDENT_CREATED"
            assert "prompt" not in body.decode().lower()
            assert headers.get("X-Agentguard-Signature") or headers.get("X-AgentGuard-Signature")
            assert client.get(f"/v1/notification-deliveries/{delivery_id}", headers={"Authorization": f"Bearer {ctx['key_b']}"}).status_code == 404
    finally:
        receiver.shutdown()
        receiver.server_close()
