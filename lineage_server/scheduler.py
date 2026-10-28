"""Scheduled monitor (REFACTOR_SPEC 6.2): a background thread runs `monitor.tick` every LINEAGE_MONITOR_MINUTES (default 60;
0 turns it off, the demo uses 1). POST /monitor/tick still runs one on demand."""
from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timedelta, timezone

from lineage_server import db, monitor, policy_store

log = logging.getLogger(__name__)


def run_once(app) -> None:
    conn = db.connect(app.state.db_path)
    try:
        policy, _ = policy_store.active(conn)
        result = monitor.tick(conn, policy=policy, hub=app.state.hub)
        conn.execute("INSERT INTO monitor_ticks (n_alerts, body) VALUES (?, ?)", (len(result.alerts), result.model_dump_json()))
        conn.commit()
    finally:
        conn.close()
    app.state.monitor_status["last"] = datetime.now(timezone.utc)


def start(app, minutes: float | None = None) -> threading.Event | None:
    minutes = float(os.environ.get("LINEAGE_MONITOR_MINUTES", "60")) if minutes is None else minutes
    app.state.monitor_status = {"last": None, "next": None, "interval_minutes": minutes}
    if minutes <= 0:
        return None
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            app.state.monitor_status["next"] = datetime.now(timezone.utc) + timedelta(minutes=minutes)
            if stop.wait(minutes * 60):
                return
            try:
                run_once(app)
            except Exception:  # noqa: BLE001 - the watch must keep running
                log.exception("scheduled monitor tick failed")

    threading.Thread(target=loop, name="monitor", daemon=True).start()
    app.state.monitor_stop = stop
    return stop
