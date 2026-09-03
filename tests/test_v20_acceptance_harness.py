from tests.v20_acceptance.evidence import EvidenceStore, Scenario
from tests.v20_acceptance.runner import self_test


def test_harness_self_tests_pass():
    assert all(value == "PASS" for value in self_test().values())


def test_exception_cannot_produce_pass():
    scenario = Scenario("SELF-EXCEPTION", "self-test", "exception")
    scenario.execute(lambda: (_ for _ in ()).throw(RuntimeError("expected")))
    assert scenario.status == "FAIL"


def test_not_run_and_stale_are_not_pass():
    assert Scenario("SELF-NOT-RUN", "self-test", "not run").status == "NOT_RUN"
    assert Scenario("SELF-STALE", "self-test", "stale", status="STALE").status == "STALE"


def test_missing_assertion_cannot_produce_pass():
    scenario = Scenario("SELF-NO-ASSERTION", "self-test", "missing assertion")
    scenario.execute(lambda: {"actual": {"observed": True}})
    assert scenario.status == "FAIL"


def test_duplicate_scenario_ids_are_rejected(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.json", "self-test", fresh=True)
    store.add(Scenario("SELF-DUP", "self-test", "duplicate"))
    try:
        store.add(Scenario("SELF-DUP", "self-test", "duplicate"))
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate scenario IDs must be rejected")
