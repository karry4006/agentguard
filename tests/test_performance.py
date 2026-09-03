import time

from agentguard.spool import SQLiteSpool


def test_performance_sanity_1000_synthetic_events(tmp_path):
    started = time.perf_counter()
    spool = SQLiteSpool(tmp_path / "benchmark.sqlite3", max_events=2000, max_bytes=10_000_000)
    for index in range(1000):
        assert spool.put({"event_type": "custom", "event_id": f"benchmark-{index}", "data": {"index": index}})
    delivered = 0
    while batch := spool.get_batch(100):
        delivered += len(batch)
        spool.acknowledge([event.event_id for event in batch])
    elapsed = time.perf_counter() - started
    assert delivered == 1000
    assert spool.stats().pending == 0
    assert elapsed < 5.0
    spool.close()

