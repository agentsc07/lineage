"""In-memory intake jobs: a worker thread runs the pipeline and appends StageEvents; SSE readers replay then follow."""
from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from lineage.schemas.artifact import StageEvent
from lineage_server import db

MAX_JOBS = 200
KEEPALIVE_SECONDS = 15.0


class Job:
    def __init__(self, job_id: str, db_path=None):
        self.job_id = job_id
        self.events: list[StageEvent] = []
        self.done = False
        self._cond = threading.Condition()
        self._db_path = db_path  # events are written through to SQLite so a reload (or a restart) can rebuild the page

    def _persist(self, sql: str, args: tuple) -> None:
        if self._db_path is None:
            return
        conn = db.connect(self._db_path)
        try:
            conn.execute(sql, args)
        except Exception:  # noqa: BLE001 - a failed write must not stop the intake; the live stream still works
            pass
        finally:
            conn.close()

    def push(self, event: StageEvent) -> None:
        self._persist("INSERT INTO job_events (job_id, body) VALUES (?, ?)", (self.job_id, event.model_dump_json()))
        with self._cond:
            self.events.append(event)
            self._cond.notify_all()

    def finish(self) -> None:
        self._persist("UPDATE jobs SET done = 1 WHERE job_id = ?", (self.job_id,))
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
    def __init__(self, workers: int = 4, db_path=None):
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="intake")
        self._lock = threading.Lock()
        self._db_path = db_path

    def get(self, job_id: str) -> Job | None:
        """The live job if this process runs it, else one rebuilt from SQLite (a page reload or a server restart). A job that was still
        running when the server stopped gets one real, labelled `failed` event: it was interrupted, it did not finish."""
        if job_id in self._jobs:
            return self._jobs[job_id]
        if self._db_path is None:
            return None
        conn = db.connect(self._db_path)
        try:
            row = conn.execute("SELECT done FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if row is None:
                return None
            job = Job(job_id)  # not written through: it is already in the database
            job.events = [StageEvent.model_validate_json(r["body"]) for r in conn.execute("SELECT body FROM job_events WHERE job_id = ? ORDER BY seq", (job_id,))]
            job.done = True
            if not row["done"]:
                job.events.append(StageEvent(job_id=job_id, stage="S7", name="Admit", status="failed", ts=datetime.now(timezone.utc),
                                             message="intake interrupted: the server stopped before this job finished"))
            return job
        finally:
            conn.close()

    def describe(self, job_id: str) -> dict | None:
        if self._db_path is None:
            return None
        conn = db.connect(self._db_path)
        try:
            r = conn.execute("SELECT job_id, requester, artifact_type, environment, label, created_at, done FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            return dict(r) if r else None
        finally:
            conn.close()

    def start(self, run: Callable[[Job], None], meta: dict | None = None) -> Job:
        """`run(job)` is executed on a worker thread; the job is finished however it ends. `meta` (requester, artifact_type, environment,
        label) is stored so a reload can say what the job was."""
        job = Job(uuid.uuid4().hex[:12], self._db_path)
        if self._db_path is not None:
            conn = db.connect(self._db_path)
            try:
                conn.execute("INSERT INTO jobs (job_id, requester, artifact_type, environment, label, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                             (job.job_id, (meta or {}).get("requester"), (meta or {}).get("artifact_type"), (meta or {}).get("environment"),
                              (meta or {}).get("label"), datetime.now(timezone.utc).isoformat()))
            finally:
                conn.close()
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
