"""Evidence schema and checkpoint persistence for the V20 acceptance harness."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
HEAD = "0018_v20_archive_quorum_bindings"
VALID_STATUSES = {"PASS", "FAIL", "STALE", "NOT_RUN"}


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def source_fingerprint() -> str:
    digest = hashlib.sha256()
    for path in sorted((ROOT / "server" / "src").rglob("*.py")):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    for path in sorted((ROOT / "server" / "alembic" / "versions").glob("*.py")):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def validate_scenario_payload(payload: dict[str, Any]) -> None:
    required = {"scenario_id", "suite", "name", "status"}
    missing = sorted(required - payload.keys())
    if missing:
        raise ValueError(f"scenario evidence missing fields: {', '.join(missing)}")
    if payload["status"] not in VALID_STATUSES:
        raise ValueError(f"invalid scenario status: {payload['status']}")


@dataclass
class Scenario:
    scenario_id: str
    suite: str
    name: str
    status: str = "NOT_RUN"
    started_at: str = ""
    finished_at: str = ""
    duration_ms: int = 0
    production_source_fingerprint: str = ""
    migration_head: str = HEAD
    tenant_id: str = "v20-harness-tenant"
    policy_epoch: int = 1
    threshold: int = 2
    configured_witness_ids: list[str] = field(default_factory=lambda: ["v20-witness-a", "v20-witness-b", "v20-witness-c"])
    preconditions: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    expected: dict[str, Any] = field(default_factory=dict)
    actual: dict[str, Any] = field(default_factory=dict)
    assertions: list[dict[str, Any]] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    error_category: str | None = None
    notes: str = ""

    def execute(self, operation: Callable[[], dict[str, Any]]) -> None:
        self.started_at = timestamp()
        started = time.perf_counter()
        self.production_source_fingerprint = source_fingerprint()
        try:
            result = operation()
            self.actual = result.get("actual", {})
            if result.get("actual_details"):
                self.actual.update(result["actual_details"])
            self.expected = result.get("expected", self.expected)
            self.assertions = result.get("assertions", [])
            self.actions = result.get("actions", self.actions)
            self.preconditions = result.get("preconditions", self.preconditions)
            self.evidence_refs = result.get("evidence_refs", self.evidence_refs)
            self.notes = result.get("notes", self.notes)
            if self.suite == "dr" and result.get("restore_proof") is not True:
                self.assertions.append({"name": "restore proof is explicit", "passed": False})
            if self.suite == "performance" and result.get("threshold_proof") is not True:
                self.assertions.append({"name": "performance threshold proof is explicit", "passed": False})
            self.status = "PASS" if self.assertions and all(item.get("passed", False) for item in self.assertions) else "FAIL"
            if self.status == "FAIL":
                self.error_category = result.get("error_category", "ASSERTION_FAILURE")
        except Exception as exc:  # bounded scenario failures become evidence, never PASS
            self.status = "FAIL"
            self.error_category = type(exc).__name__
            self.notes = str(exc)[:500]
            self.assertions = [{"name": "scenario completed without exception", "passed": False}]
        finally:
            self.duration_ms = int((time.perf_counter() - started) * 1000)
            self.finished_at = timestamp()

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class EvidenceStore:
    def __init__(self, path: Path, suite: str, *, fresh: bool = False) -> None:
        self.path = path
        self.suite = suite
        self.scenarios: dict[str, dict[str, Any]] = {}
        self._added_ids: set[str] = set()
        if not fresh and path.exists():
            value = json.loads(path.read_text(encoding="utf-8"))
            for scenario in value.get("scenarios", []):
                if scenario.get("suite") == suite:
                    self.scenarios[scenario["scenario_id"]] = scenario

    def add(self, scenario: Scenario, *, resume: bool = False) -> None:
        validate_scenario_payload(scenario.as_dict())
        if scenario.status == "PASS" and not scenario.assertions:
            scenario.status = "FAIL"
            scenario.error_category = "PASS_WITHOUT_ASSERTIONS"
        if scenario.scenario_id in self._added_ids:
            raise ValueError(f"duplicate scenario ID: {scenario.scenario_id}")
        self._added_ids.add(scenario.scenario_id)
        previous = self.scenarios.get(scenario.scenario_id)
        if resume and previous and previous.get("status") == "PASS":
            return
        self.scenarios[scenario.scenario_id] = scenario.as_dict()

    def write(self, *, required: int, expected_ids: set[str] | None = None) -> dict[str, Any]:
        scenarios = sorted(self.scenarios.values(), key=lambda item: item["scenario_id"])
        summary = {status.lower(): sum(item["status"] == status for item in scenarios)
                   for status in ("PASS", "FAIL", "STALE", "NOT_RUN")}
        summary["skipped"] = 0
        observed_ids = [item["scenario_id"] for item in scenarios]
        coverage_complete = expected_ids is None or set(observed_ids) == expected_ids and len(observed_ids) == len(set(observed_ids))
        value = {
            "artifact": f"v20-{self.suite}-acceptance-harness",
            "version": "V20",
            "migration": HEAD,
            "status": "PASS" if coverage_complete and len(scenarios) == required and summary["pass"] == required else "BLOCKED",
            "coverage": {"status": "PASS" if coverage_complete else "FAIL", "expected_ids": sorted(expected_ids or set()), "observed_ids": observed_ids},
            "summary": {"required": required, **summary},
            "source_fingerprint": source_fingerprint(),
            "scenarios": scenarios,
            "secret_values_emitted": False,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return value
