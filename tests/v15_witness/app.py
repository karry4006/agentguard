"""Disposable V15 witness fixture; never import from the AgentGuard runtime."""
from base64 import b64encode
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import os
from uuid import uuid4
from fastapi import FastAPI, HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

app = FastAPI(title="AgentGuard V15 test witness")
state_path = Path(os.getenv("WITNESS_STATE_FILE", "/data/state.json"))
key_path = Path(os.getenv("WITNESS_PRIVATE_KEY_FILE", "/data/private.key"))
key_id = os.getenv("WITNESS_KEY_ID", "witness-test-v1")
last_request: dict | None = None


def _load_key() -> Ed25519PrivateKey:
    if key_path.exists():
        return Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
    key = Ed25519PrivateKey.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    return key


def _load_state() -> dict:
    if not state_path.exists(): return {}
    return json.loads(state_path.read_text(encoding="utf-8"))


def _save_state(value: dict) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _message(request: dict, anchor_id: str, received: str) -> bytes:
    return json.dumps({"checkpoint_digest": request["checkpoint_digest"], "checkpoint_sequence": request["checkpoint_sequence"],
        "created_at": request["created_at"], "external_anchor_id": anchor_id, "namespace": request["namespace"],
        "previous_checkpoint_digest": request.get("previous_checkpoint_digest"), "schema_version": request["schema_version"],
        "signer_key_id": key_id, "witness_received_at": received}, separators=(",", ":"), sort_keys=True).encode()


def _receipt(request: dict, anchor_id: str, received: str) -> dict:
    key = _load_key()
    return {"schema_version": request["schema_version"], "external_anchor_id": anchor_id,
        "namespace": request["namespace"], "checkpoint_sequence": request["checkpoint_sequence"],
        "checkpoint_digest": request["checkpoint_digest"], "witness_received_at": received,
        "signer_key_id": key_id, "signature": b64encode(key.sign(_message(request, anchor_id, received))).decode()}


@app.get("/public-key")
def public_key() -> dict[str, str]:
    return {"signer_key_id": key_id, "public_key": b64encode(_load_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()}


@app.post("/anchor")
def anchor(request: dict) -> dict:
    global last_request
    last_request = dict(request)
    if set(request) != {"schema_version", "namespace", "checkpoint_sequence", "checkpoint_digest", "previous_checkpoint_digest", "created_at"}:
        raise HTTPException(400, "invalid request")
    key = (request["namespace"], str(request["checkpoint_sequence"]))
    state = _load_state()
    existing = state.get("|".join(key))
    if existing:
        if existing["checkpoint_digest"] != request["checkpoint_digest"]: raise HTTPException(409, "checkpoint conflict")
        return existing
    received = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    value = _receipt(request, str(uuid4()), received)
    state["|".join(key)] = value
    _save_state(state)
    return value


@app.get("/debug/last-request")
def debug_last_request() -> dict:
    return last_request or {}

@app.post("/anchor/latest")
def latest(request: dict) -> dict:
    values = [value for key, value in _load_state().items() if key.startswith(request.get("namespace", "") + "|")]
    if not values: raise HTTPException(404, "no anchors")
    return max(values, key=lambda value: value["checkpoint_sequence"])
