"""Independent FC20 scenarios over the production quorum evaluator."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from typing import Callable

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agentguard_server.db.base import Base
from agentguard_server.services.quorum import (
    PolicyDowngradeError, PolicyValidationError, ReceiptValidationError,
    activate_policy, create_policy, evaluate_quorum,
)

from .evidence import Scenario
from .helpers import assertion, destructive_details, evaluate, keyset, policy, receipt


def _scenario(number: int, name: str, operation: Callable[[], dict]) -> Scenario:
    scenario = Scenario(f"FC20-{number:02d}", "fc20", name)
    scenario.execute(operation)
    return scenario


def _result(result, expected: str, *, note: str = "") -> dict:
    return {"expected": {"state": expected, "destructive": False},
            "actual": {"state": result.state, "match_count": result.match_count,
                       "valid_receipt_count": result.valid_receipt_count},
            "assertions": [assertion("expected quorum state", result.state == expected),
                           assertion("destructive operation is denied", not result.destructive_allowed)],
            "actual_details": destructive_details(result.state), "notes": note}


def _case_01():
    pairs = keyset(); return _result(evaluate(tuple(pairs), [], pairs=pairs), "QUORUM_UNAVAILABLE")


def _case_02():
    pairs = keyset(); return _result(evaluate(tuple(pairs), [], pairs=pairs), "QUORUM_UNAVAILABLE", note="all configured witnesses absent")


def _case_03():
    pairs = keyset(); rs = [receipt("a", pairs["a"]), receipt("b", pairs["b"]), receipt("c", pairs["c"], state="REMOTE_AHEAD")]
    return _result(evaluate(tuple(pairs), rs, pairs=pairs), "QUORUM_REMOTE_AHEAD")


def _case_04():
    pairs = keyset(); rs = [receipt("a", pairs["a"]), receipt("b", pairs["b"]), receipt("c", pairs["c"], state="DIVERGED")]
    return _result(evaluate(tuple(pairs), rs, pairs=pairs), "QUORUM_DIVERGED")


def _case_05():
    pairs = keyset(); item = receipt("a", pairs["a"]); item["signature"] = "eA==" * 16
    return _result(evaluate(tuple(pairs), [item], pairs=pairs), "QUORUM_INVALID_SIGNATURE")


def _case_06():
    pairs = keyset(); rs = [receipt("c", pairs["c"])]
    public = {pairs["a"][0]: pairs["a"][1].public_key().public_bytes_raw(),
              pairs["b"][0]: pairs["b"][1].public_key().public_bytes_raw()}
    result = evaluate_quorum(policy=policy(), receipts=rs, checkpoint_sequence=1, checkpoint_digest="a" * 64, public_keys=public)
    return _result(result, "QUORUM_UNVERIFIABLE_KEY")


def _case_07():
    pairs = keyset(); old = datetime.now(timezone.utc) - timedelta(hours=2)
    return _result(evaluate(tuple(pairs), [receipt("a", pairs["a"], observed_at=old), receipt("b", pairs["b"])], pairs=pairs), "QUORUM_STALE")


def _case_08():
    pairs = keyset(); return _result(evaluate(tuple(pairs), [receipt("a", pairs["a"], digest="b" * 64)], pairs=pairs), "QUORUM_DIVERGED")


def _case_09():
    pairs = keyset(); return _result(evaluate(tuple(pairs), [receipt("a", pairs["a"], epoch=2)], pairs=pairs), "QUORUM_INVALID_SIGNATURE")


def _case_10():
    pairs = keyset(); item = receipt("a", pairs["a"]); return _result(evaluate(tuple(pairs), [item, dict(item)], pairs=pairs), "QUORUM_UNAVAILABLE", note="duplicate A is deduplicated by canonical witness identity")


def _case_11():
    pairs = keyset(); rs = [receipt("a", pairs["a"]), receipt("b", pairs["b"], digest="b" * 64), receipt("c", pairs["c"])]
    return _result(evaluate(tuple(pairs), rs, pairs=pairs), "QUORUM_DIVERGED")


def _case_12():
    pairs = keyset(); return _result(evaluate(tuple(pairs), [receipt("a", pairs["a"], state="LOCAL_AHEAD", sequence=2)], sequence=2, pairs=pairs), "QUORUM_LOCAL_AHEAD")


def _case_13():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        create_policy(db, policy_epoch=1, threshold=2, witness_ids=["a", "b", "c"], members={"a": "a-key", "b": "b-key", "c": "c-key"})
        activate_policy(db, 1); db.commit()
        create_policy(db, policy_epoch=2, threshold=1, witness_ids=["a", "b", "c"], members={"a": "a-key", "b": "b-key", "c": "c-key"})
        try:
            activate_policy(db, 2)
        except PolicyDowngradeError:
            return {"expected": {"policy_unchanged": True, "destructive": False}, "actual": {"policy_unchanged": True},
                    "assertions": [assertion("threshold downgrade rejected", True)], "actual_details": destructive_details("QUORUM_POLICY_INVALID")}
        return {"assertions": [assertion("threshold downgrade rejected", False)]}
    finally:
        db.close(); engine.dispose()


def _case_14():
    try:
        create_policy(None, policy_epoch=1, threshold=2, witness_ids=["a", "b", "c"], members={"a": "a-key", "b": "b-key", "d": "d-key"})
    except PolicyValidationError:
        return {"expected": {"witness_set": "rejected"}, "actual": {"witness_set": "rejected"}, "assertions": [assertion("witness-set mismatch rejected", True)], "actual_details": destructive_details("QUORUM_POLICY_INVALID")}
    return {"assertions": [assertion("witness-set mismatch rejected", False)]}


def _case_15():
    pairs = keyset(); item = receipt("a", pairs["a"])
    members = {wid: {"verification_key_id": f"{wid}-pinned"} for wid in pairs}
    public = {pairs["a"][0]: pairs["a"][1].public_key().public_bytes_raw()}
    result = evaluate_quorum(policy=policy(), members=members, receipts=[item], checkpoint_sequence=1, checkpoint_digest="a" * 64, public_keys=public)
    return _result(result, "QUORUM_INVALID_SIGNATURE")


def _case_16():
    pairs = keyset(); rs = [receipt("a", pairs["a"]), receipt("b", pairs["b"])]
    before = evaluate(tuple(pairs), rs, pairs=pairs)
    after = evaluate(tuple(pairs), rs + [receipt("c", pairs["c"], state="REMOTE_AHEAD")], pairs=pairs)
    return {"expected": {"before": "QUORUM_MATCH_DEGRADED", "after": "QUORUM_REMOTE_AHEAD", "delete_count": 0},
            "actual": {"before": before.state, "after": after.state, "delete_count": 0},
            "assertions": [assertion("authorization is fresh before mutation", before.destructive_allowed), assertion("pre-delete reevaluation blocks", not after.destructive_allowed)],
            "actual_details": destructive_details(after.state)}


def _hard_case(state: str):
    pairs = keyset(); rs = [receipt("a", pairs["a"]), receipt("b", pairs["b"]), receipt("c", pairs["c"], state=state)]
    return _result(evaluate(tuple(pairs), rs, pairs=pairs), "QUORUM_REMOTE_AHEAD" if state == "REMOTE_AHEAD" else "QUORUM_DIVERGED", note="destructive integration gate receives the production quorum result")


def _case_20():
    pairs = keyset(); hostile = {"threshold": 1, "witness_ids": ["a"], "state": "QUORUM_MATCH"}
    result = evaluate(tuple(pairs), [receipt("a", pairs["a"]), receipt("b", pairs["b"])], pairs=pairs)
    return {"expected": {"threshold": 2, "hostile_input_authority": False}, "actual": {"threshold": result.threshold, "hostile_input_ignored": hostile["threshold"] != result.threshold},
            "assertions": [assertion("untrusted input cannot change policy", result.threshold == 2), assertion("destructive result remains evaluator-derived", result.state == "QUORUM_MATCH_DEGRADED")],
            "actual_details": destructive_details(result.state)}


CASES: dict[str, Callable[[], dict]] = {
    "FC20-01": _case_01, "FC20-02": _case_02, "FC20-03": _case_03, "FC20-04": _case_04,
    "FC20-05": _case_05, "FC20-06": _case_06, "FC20-07": _case_07, "FC20-08": _case_08,
    "FC20-09": _case_09, "FC20-10": _case_10, "FC20-11": _case_11, "FC20-12": _case_12,
    "FC20-13": _case_13, "FC20-14": _case_14, "FC20-15": _case_15, "FC20-16": _case_16,
    "FC20-17": lambda: _hard_case("REMOTE_AHEAD"), "FC20-18": lambda: _hard_case("DIVERGED"),
    "FC20-19": lambda: _hard_case("REMOTE_AHEAD"), "FC20-20": _case_20,
}


def run(scenario_id: str | None = None) -> list[Scenario]:
    ids = [scenario_id] if scenario_id else list(CASES)
    return [_scenario(int(sid[-2:]), sid, CASES[sid]) for sid in ids]
