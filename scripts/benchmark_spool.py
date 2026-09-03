"""Small V1 spool sanity benchmark; never writes to the user's configured spool."""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from agentguard.spool import SQLiteSpool


def main() -> None:
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="agentguard-benchmark-") as directory:
        path = Path(directory) / "spool.sqlite3"
        spool = SQLiteSpool(path, max_events=2000, max_bytes=10_000_000)
        for index in range(1000):
            assert spool.put({"event_type": "custom", "event_id": f"benchmark-{index}", "data": {"index": index}})
        delivered = 0
        while True:
            batch = spool.get_batch(100)
            if not batch:
                break
            delivered += len(batch)
            spool.acknowledge([event.event_id for event in batch])
        stats = spool.stats()
        spool.close()
    print(json.dumps({"events": 1000, "delivered": delivered, "pending": stats.pending, "seconds": round(time.perf_counter() - started, 4)}))


if __name__ == "__main__":
    main()

