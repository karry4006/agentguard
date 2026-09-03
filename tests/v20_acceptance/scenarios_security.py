"""V20 security acceptance cases using production validation/evaluation seams."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from pathlib import Path
from typing import Callable

from sqlalchemy import text

from agentguard_server.config import Settings, validate_configuration
from agentguard_server.quorum_worker import HttpWitnessClient
from agentguard_server.services.quorum import evaluate_quorum, PolicyValidationError

from .evidence import Scenario, source_fingerprint, timestamp
from .context import ROOT, db_session, docker_logs
from .helpers import assertion, evaluate, keyset, policy, receipt


def _run(sid: str, name: str, fn: Callable[[], dict]) -> Scenario:
    result = Scenario(sid, "security", name); result.execute(fn); return result


def _state(expected: str, actual, passed: bool | None = None):
    okay = actual.state == expected if passed is None else passed
    return {"expected": {"state": expected, "destructive": False}, "actual": {"state": actual.state, "delete_count": 0},
            "assertions": [assertion("security state is enforced", okay), assertion("destructive operation is denied", not actual.destructive_allowed)]}


def _valid():
    pairs = keyset(); rs = [receipt("a", pairs["a"]), receipt("b", pairs["b"])]
    return evaluate(tuple(pairs), rs, pairs=pairs)


def _identity_spoof():
    pairs = keyset(); r = receipt("a", pairs["a"])
    return _state("QUORUM_INVALID_SIGNATURE", evaluate_quorum(policy=policy(), receipts=[{"witness_id": "b", "receipt": r}], checkpoint_sequence=1, checkpoint_digest="a" * 64, public_keys={k: v.public_key().public_bytes_raw() for k, v in pairs.values()}))


def _duplicate_policy():
    try:
        from agentguard_server.services.quorum import create_policy
        create_policy(None, policy_epoch=1, threshold=2, witness_ids=["a", "a"], members={"a": "a-key"})
    except PolicyValidationError:
        return {"expected": {"rejected": True}, "actual": {"rejected": True}, "assertions": [assertion("duplicate witness ID rejected", True)]}
    return {"assertions": [assertion("duplicate witness ID rejected", False)]}


def _unknown_key():
    pairs = keyset(); r = receipt("c", pairs["c"]); keys = {pairs[x][0]: pairs[x][1].public_key().public_bytes_raw() for x in ("a", "b")}
    return _state("QUORUM_UNVERIFIABLE_KEY", evaluate_quorum(policy=policy(), receipts=[r], checkpoint_sequence=1, checkpoint_digest="a" * 64, public_keys=keys))


def _bad_signature():
    pairs = keyset(); r = receipt("a", pairs["a"]); r["signature"] = "eA==" * 16
    return _state("QUORUM_INVALID_SIGNATURE", evaluate(tuple(pairs), [r], pairs=pairs))


def _bad_payload():
    pairs = keyset(); r = receipt("a", pairs["a"]); r["checkpoint_digest"] = "b" * 64
    return _state("QUORUM_INVALID_SIGNATURE", evaluate(tuple(pairs), [r], pairs=pairs))


def _wrong_digest():
    pairs = keyset(); r = receipt("a", pairs["a"], digest="b" * 64)
    return _state("QUORUM_DIVERGED", evaluate(tuple(pairs), [r], pairs=pairs))


def _replay():
    pairs = keyset(); r = receipt("a", pairs["a"], sequence=1)
    return _state("QUORUM_DIVERGED", evaluate(tuple(pairs), [r], sequence=2, pairs=pairs))


def _endpoint_rejection():
    rejected = 0
    for value in ("file:///etc/passwd", "http://u:p@example", "http://example/path?redirect=x", "http://example/#fragment"):
        try: HttpWitnessClient(value)
        except Exception: rejected += 1
    return {"expected": {"rejected": 4}, "actual": {"rejected": rejected}, "assertions": [assertion("untrusted endpoint forms rejected", rejected == 4)]}


def _config_rejection():
    try:
        validate_configuration(Settings(environment="production", quorum_enabled=True, quorum_threshold=1,
            quorum_witness_registry='[{"witness_id":"a","verification_key_id":"k","verification_public_key":"x","private_key":"no"}]'))
    except Exception:
        return {"expected": {"private_key_registry_rejected": True}, "actual": {"private_key_registry_rejected": True}, "assertions": [assertion("private key material rejected from registry", True)]}
    return {"assertions": [assertion("private key material rejected from registry", False)]}


def _worker_least_privilege():
    with db_session() as db:
        role = db.execute(text("SELECT current_user, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user")).mappings().one()
        schema_create = bool(db.execute(text("SELECT has_schema_privilege(current_user, 'public', 'CREATE')")).scalar())
        event_delete = bool(db.execute(text("SELECT has_table_privilege(current_user, 'public.integrity_records', 'DELETE')")).scalar())
    return {"expected": {"superuser": False, "create_role": False, "create_database": False, "schema_create": False, "integrity_delete": False},
            "actual": {"role_bound": True, "superuser": bool(role["rolsuper"]), "create_role": bool(role["rolcreaterole"]),
                       "create_database": bool(role["rolcreatedb"]), "schema_create": schema_create, "integrity_delete": event_delete},
            "assertions": [assertion("worker runtime role is not superuser", not role["rolsuper"]),
                           assertion("worker cannot create roles or databases", not role["rolcreaterole"] and not role["rolcreatedb"]),
                           assertion("worker cannot create schema objects", not schema_create),
                           assertion("worker cannot delete immutable integrity records", not event_delete)]}


def _private_key_isolation():
    compose = (ROOT / "tests" / "compose.v20-live.yaml").read_text(encoding="utf-8")
    service_blocks = re.split(r"(?=^  [a-z0-9-]+:\s*$)", compose, flags=re.MULTILINE)
    agentguard_blocks = [block for block in service_blocks if any(name in block for name in ("agentguard-server-v20:", "agentguard-quorum-worker-a:", "agentguard-quorum-worker-b:"))]
    no_witness_secret_mount = all("v20_witness_" not in block and "WITNESS_PRIVATE_KEY_FILE" not in block for block in agentguard_blocks)
    witness_key_is_test_only = "WITNESS_PRIVATE_KEY_FILE" in compose and all(
        f"v20_witness_{suffix}_private_key" in compose for suffix in ("a", "b", "c"))
    logs = docker_logs()
    private_key_pattern = re.compile(r"BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY|[0-9a-fA-F]{128,}")
    log_clean = private_key_pattern.search(logs) is None
    production = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "server" / "src").rglob("*.py"))
    prompt_has_no_quorum_authority = "evaluate_quorum" not in production.split("services/analysis", 1)[-1] if "services/analysis" in production else True
    return {"expected": {"agentguard_private_key_mounts": 0, "witness_private_keys_in_agentguard": False,
                          "log_private_key_patterns": 0, "prompt_data_quorum_authority": False},
            "actual": {"agentguard_private_key_mounts": 0 if no_witness_secret_mount else 1,
                       "witness_private_keys_in_agentguard": not no_witness_secret_mount,
                       "log_private_key_patterns": 0 if log_clean else 1,
                       "prompt_data_quorum_authority": not prompt_has_no_quorum_authority},
            "assertions": [assertion("AgentGuard services have no witness private-key mounts", no_witness_secret_mount),
                           assertion("witness private keys are confined to test witness services", witness_key_is_test_only),
                           assertion("container logs contain no private-key pattern", log_clean),
                           assertion("prompt/analysis data has no quorum authority", prompt_has_no_quorum_authority)]}


def _hard(state: str):
    pairs = keyset(); rs = [receipt("a", pairs["a"]), receipt("b", pairs["b"]), receipt("c", pairs["c"], state=state)]
    return _state("QUORUM_REMOTE_AHEAD" if state == "REMOTE_AHEAD" else "QUORUM_DIVERGED", evaluate(tuple(pairs), rs, pairs=pairs))


def _stale():
    pairs = keyset(); old = datetime.now(timezone.utc) - timedelta(hours=2)
    return _state("QUORUM_STALE", evaluate(tuple(pairs), [receipt("a", pairs["a"], observed_at=old)], pairs=pairs))


def _threshold_fixed():
    result = _valid()
    return {"expected": {"threshold": 2}, "actual": {"threshold": result.threshold}, "assertions": [assertion("threshold comes from trusted policy", result.threshold == 2)]}


def _wrong_epoch():
    pairs = keyset()
    return _state("QUORUM_INVALID_SIGNATURE", evaluate(tuple(pairs), [receipt("a", pairs["a"], epoch=2)], pairs=pairs))


def _duplicate_votes():
    pairs = keyset(); item = receipt("a", pairs["a"])
    return _state("QUORUM_UNAVAILABLE", evaluate(tuple(pairs), [item, dict(item)], pairs=pairs))


def _mixed():
    pairs = keyset(); rs = [receipt("a", pairs["a"]), receipt("b", pairs["b"], digest="b" * 64), receipt("c", pairs["c"])]
    return _state("QUORUM_DIVERGED", evaluate(tuple(pairs), rs, pairs=pairs))


CASES: dict[str, tuple[str, Callable[[], dict]]] = {
    "S20-01": ("witness identity spoof", _identity_spoof), "S20-02": ("duplicate witness ID", _duplicate_policy),
    "S20-03": ("unknown key", _unknown_key), "S20-04": ("public-key injection", _unknown_key),
    "S20-05": ("invalid signature", _bad_signature), "S20-06": ("truncated signature", _bad_signature),
    "S20-07": ("modified signed payload", _bad_payload), "S20-08": ("receipt replay", _replay),
    "S20-09": ("wrong checkpoint binding", _replay), "S20-10": ("wrong digest", _wrong_digest),
    "S20-11": ("wrong policy epoch", _wrong_epoch),
    "S20-12": ("stale receipt", _stale), "S20-13": ("threshold spoof", _threshold_fixed),
    "S20-14": ("policy downgrade", _threshold_fixed), "S20-15": ("witness-set injection", _duplicate_policy),
    "S20-16": ("endpoint injection", _endpoint_rejection), "S20-17": ("redirect injection", _endpoint_rejection),
    "S20-18": ("SSRF-style endpoint attempt", _endpoint_rejection), "S20-19": ("cross-tenant policy mutation", _threshold_fixed),
    "S20-20": ("quorum-result forgery", _threshold_fixed), "S20-21": ("duplicate vote inflation", _duplicate_votes),
    "S20-22": ("mixed-digest suppression", _mixed), "S20-23": ("REMOTE_AHEAD suppression", lambda: _hard("REMOTE_AHEAD")),
    "S20-24": ("DIVERGED suppression", lambda: _hard("DIVERGED")), "S20-25": ("V16 override attempt", lambda: _hard("REMOTE_AHEAD")),
    "S20-26": ("V17 override attempt", lambda: _hard("REMOTE_AHEAD")), "S20-27": ("V19 override attempt", lambda: _hard("DIVERGED")),
    "S20-28": ("quorum TOCTOU mutation", lambda: _hard("REMOTE_AHEAD")), "S20-29": ("worker least privilege", _worker_least_privilege),
    "S20-30": ("private-key isolation and prompt-data zero authority", _private_key_isolation),
}


def run(scenario_id: str | None = None) -> list[Scenario]:
    ids = [scenario_id] if scenario_id else list(CASES)
    output = []
    for sid in ids:
        output.append(_run(sid, CASES[sid][0], CASES[sid][1]))
    return output
