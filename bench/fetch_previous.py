"""Fetch the release before each real-world package (never committed), for diff-aware review.

    uv run python -m bench.fetch_previous <rw_dir>     # rw_dir from bench/fetch_realworld.py

Writes <rw_dir>/previous/<name>/ (wheel contents of the newest earlier release that has a wheel) and
<rw_dir>/previous.json {name: {"version", "previous"}}. Same pip target as fetch_realworld.py.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from lineage.inspect.package_previous import PYPI_JSON, candidate_versions, download_wheel

PIP_TARGET = ["--python-version", "3.11", "--implementation", "cp", "--abi", "cp311", "--abi", "abi3", "--abi", "none",
              "--platform", "manylinux2014_x86_64", "--platform", "manylinux_2_28_x86_64", "--platform", "any"]


def one(name: str, wheel: str, out: Path) -> dict:
    version = wheel.split("-")[1]
    row = {"version": version, "previous": None}
    try:
        req = urllib.request.Request(PYPI_JSON.format(name=name), headers={"User-Agent": "lineage-validation/0.1"})
        releases = json.loads(urllib.request.urlopen(req, timeout=60).read())["releases"]
    except Exception as e:  # noqa: BLE001
        return {**row, "error": str(e)[:120]}
    for v in candidate_versions(releases, version, limit=4):
        if download_wheel(name, v, out / "previous" / name, PIP_TARGET):
            row["previous"] = v
            break
    return row


def main(rw: Path) -> None:
    fetch = json.loads((rw / "fetch.json").read_text())
    pk = [p for p in fetch["packages"] if p["ok"]]
    with ThreadPoolExecutor(8) as ex:
        rows = list(ex.map(lambda p: one(p["name"], p["wheel"], rw), pk))
    res = {p["name"]: r for p, r in zip(pk, rows)}
    (rw / "previous.json").write_text(json.dumps(res, indent=1))
    print(f"previous release found for {sum(bool(r['previous']) for r in rows)}/{len(rows)}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
