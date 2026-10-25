"""In-memory intake jobs: a worker thread runs the pipeline and appends StageEvents; SSE readers replay then follow."""
from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from lineage.schemas.artifact import StageEvent

MAX_JOBS = 200
KEEPALIVE_SECONDS = 15.0


class Job:
    def __init__(self, job_id: str):
        self.job_id = job_id
        self.events: list[StageEvent] = []
        self.done = False
        self._cond = threading.Condition()

    def push(self, event: StageEvent) -> None:
        with self._cond:
            self.events.append(event)
            self._cond.notify_all()

    def finish(self) -> None:
        with self._cond:
            self.done = True
            self._cond.notify_all()

    def follow(self) -> Iterator[StageEvent | None]:
        """Yield every event from the start; yield None as a keepalive tick while waiting. Ends when the job is done."""
        i = 0
        while True:
            with self._cond:
                while i >= len(self.events) and not self.done:
                    if not self._cond.wait(timeout=KEEPALIVE_SECONDS):
                        break
                batch = self.events[i:]
                finished = self.done and i + len(batch) >= len(self.events)
            if not batch and not finished:
                yield None
            for ev in batch:
                yield ev
            i += len(batch)
            if finished:
                return


class JobStore:
    def __init__(self, workers: int = 4):
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="intake")
        self._lock = threading.Lock()

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def start(self, run: Callable[[Job], None]) -> Job:
        """`run(job)` is executed on a worker thread; the job is finished however it ends."""
        job = Job(uuid.uuid4().hex[:12])
        with self._lock:
            self._jobs[job.job_id] = job
            while len(self._jobs) > MAX_JOBS:
                self._jobs.popitem(last=False)

        def work() -> None:
            try:
                run(job)
            except Exception as e:  # noqa: BLE001 - surface the failure on the stream instead of dying silently
                job.push(StageEvent(job_id=job.job_id, stage="S7", name="Admit", status="failed",
                                    message=f"intake aborted: {type(e).__name__}: {e}", ts=datetime.now(timezone.utc)))
            finally:
                job.finish()

        self._pool.submit(work)
        return job
