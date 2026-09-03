"""Disposable V20 witness fixture.

This process owns its private Ed25519 key and exposes only signed evidence to
AgentGuard.  It is test infrastructure, not part of the production runtime.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from threading import Lock
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from fastapi import FastAPI, Header, HTTPException


app = FastAPI(title="AgentGuard V20 disposable witness")
state_path = Path(os.getenv("WITNESS_STATE_FILE", "/data/state.json"))
key_path = Path(os.getenv("WITNESS_PRIVATE_KEY_FILE", "/data/private.key"))
key_id = os.getenv("WITNESS_KEY_ID", "v20-witness-key-v1")
expected_witness_id = os.getenv("WITNESS_ID", "")
mode = os.getenv("WITNESS_MODE", "MATCH")
control_token = os.getenv("V20_TEST_CONTROL_TOKEN", "")
state_lock = Lock()


def _load_key() -> Ed25519PrivateKey:
    if key_path.exists():
        value = key_path.read_bytes()
        if len(value) == 64:
            value = bytes.fromhex(value.decode("ascii"))
        return Ed25519PrivateKey.from_private_bytes(value)
    key = Ed25519PrivateKey.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    return key


def _load_state() -> dict[str, dict]:
    if not state_path.exists():
        return {}
    return json.loads(state_path.read_text(encoding="utf-8"))


def _save_state(value: dict[str, dict]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def _canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _evidence(request: dict, *, head_sequence: int, head_digest: str, continuity: str) -> dict:
    observed_at = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    result = {
        "receipt_version": "multi-witness-receipt-v1",
        "witness_id": request["witness_id"],
        "verification_key_id": key_id,
        "policy_epoch": request["policy_epoch"],
        "checkpoint_sequence": request["checkpoint_sequence"],
        "checkpoint_digest": request["checkpoint_digest"],
        "witness_head_sequence": head_sequence,
        "witness_head_digest": head_digest,
        "continuity_state": continuity,
        "observed_at": observed_at,
    }
    signature = _load_key().sign(_canonical(result))
    result["signature"] = base64.b64encode(signature).decode("ascii")
    return result


def _fingerprint() -> str:
    public = _load_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(public).hexdigest()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/control")
def control(request: dict, x_v20_control_token: str = Header(default="")) -> dict[str, str]:
    """Test-only witness control; disabled unless the disposable token is set."""
    global mode, key_id
    if not control_token or x_v20_control_token != control_token:
        raise HTTPException(404, "not found")
    if set(request) - {"mode", "reset"}:
        raise HTTPException(400, "invalid control request")
    requested_mode = request.get("mode", mode)
    if requested_mode not in {"MATCH", "REMOTE_AHEAD", "DIVERGED", "LOCAL_AHEAD", "INVALID_SIGNATURE", "OFFLINE"}:
        raise HTTPException(400, "invalid witness mode")
    with state_lock:
        if request.get("reset"):
            _save_state({})
        mode = requested_mode
    return {"mode": mode}


@app.get("/public-key")
def public_key() -> dict[str, str]:
    public = _load_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"verification_key_id": key_id, "public_key": base64.b64encode(public).decode("ascii")}


@app.post("/anchor")
def anchor(request: dict) -> dict:
    if mode == "OFFLINE":
        raise HTTPException(503, "witness unavailable")
    required = {"receipt_version", "witness_id", "policy_epoch", "checkpoint_sequence", "checkpoint_digest"}
    if set(request) != required or request["receipt_version"] != "multi-witness-receipt-v1":
        raise HTTPException(400, "invalid V20 publish request")
    if expected_witness_id and request["witness_id"] != expected_witness_id:
        raise HTTPException(400, "witness identity mismatch")
    if not isinstance(request["checkpoint_sequence"], int) or not isinstance(request["policy_epoch"], int):
        raise HTTPException(400, "invalid V20 publish request")
    key = f"{request['policy_epoch']}|{request['checkpoint_sequence']}"
    with state_lock:
        state = _load_state()
        existing = state.get(key)
        if existing:
            if existing["checkpoint_digest"] != request["checkpoint_digest"]:
                raise HTTPException(409, "checkpoint conflict")
            return existing
        if mode == "REMOTE_AHEAD":
            receipt = _evidence(request, head_sequence=request["checkpoint_sequence"] + 1,
                                 head_digest=hashlib.sha256(b"remote-ahead").hexdigest(), continuity="REMOTE_AHEAD")
        elif mode == "DIVERGED":
            receipt = _evidence(request, head_sequence=request["checkpoint_sequence"],
                                 head_digest=hashlib.sha256(b"diverged").hexdigest(), continuity="DIVERGED")
        elif mode == "LOCAL_AHEAD":
            receipt = _evidence(request, head_sequence=max(0, request["checkpoint_sequence"] - 1),
                                 head_digest=hashlib.sha256(b"local-ahead").hexdigest(), continuity="LOCAL_AHEAD")
        elif mode == "INVALID_SIGNATURE":
            receipt = _evidence(request, head_sequence=request["checkpoint_sequence"],
                                 head_digest=request["checkpoint_digest"], continuity="MATCH")
            receipt["signature"] = base64.b64encode(bytes(64)).decode("ascii")
        else:
            receipt = _evidence(request, head_sequence=request["checkpoint_sequence"],
                                 head_digest=request["checkpoint_digest"], continuity="MATCH")
        state[key] = receipt
        _save_state(state)
        return receipt


@app.get("/latest")
def latest(policy_epoch: int = 1) -> dict:
    values = list(_load_state().values())
    values = [value for value in values if value["policy_epoch"] == policy_epoch]
    if not values:
        raise HTTPException(404, "no V20 evidence")
    return max(values, key=lambda value: value["checkpoint_sequence"])


@app.get("/debug/fingerprint")
def debug_fingerprint() -> dict[str, str]:
    return {"verification_key_id": key_id, "public_key_sha256": _fingerprint()}


@app.get("/debug/mode")
def debug_mode() -> dict[str, str]:
    return {"mode": mode}
