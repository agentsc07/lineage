from lineage.inspect import package_capabilities as pc
from tests.fixtures.builders import make_benign_update, make_malicious_package


def ids(fs):
    return {f.id for f in fs}


def test_benign_package_has_no_findings(toy_package):
    assert pc.scan(toy_package) == []
    assert pc.extract(toy_package) == {}


def test_malicious_package_capabilities(tmp_path):
    caps = pc.extract(make_malicious_package(tmp_path / "evil"))
    assert {"network", "env_secrets", "dynamic_exec", "encoded_blob", "startup_hook", "network_at_install"} <= set(caps)
    assert caps["startup_hook"] == ["evilpkg_init.pth:1"]
    assert "setup.py:4" in caps["network_at_install"]
    assert "evilpkg/core.py:6" in caps["env_secrets"]


def test_scan_flags_startup_decode_exec_as_critical(tmp_path):
    fs = pc.scan(make_malicious_package(tmp_path / "evil"))
    by_id = {f.id: f for f in fs}
    assert by_id["PKG.HOOK.STARTUP_HOOK"].severity == "critical"
    assert by_id["PKG.CODE.DECODE_EXEC"].evidence[0].ref == "evilpkg_init.pth:1"
    assert by_id["PKG.HOOK.NETWORK_AT_INSTALL"].severity == "high"
    assert all(f.source == "deterministic" and f.grounded for f in fs)


def test_version_diff_only_raises_new_capabilities(tmp_path):
    old = make_benign_update(tmp_path / "old")
    new = make_malicious_package(tmp_path / "new")
    fs = pc.scan(new, previous=old)
    assert "PKG.HOOK.STARTUP_HOOK" in ids(fs)
    assert all("newly added" in f.title for f in fs)
    # identical versions raise nothing new
    assert ids(pc.scan(new, previous=new)) == {"PKG.CAP.NO_NEW"}


def test_diff_capabilities():
    old = {"network": ["a.py:3"]}
    new = {"network": ["a.py:9", "b.py:1"], "subprocess": ["a.py:4"]}
    assert pc.diff_capabilities(old, new) == {"network": ["b.py:1"], "subprocess": ["a.py:4"]}


def test_alias_resolution_and_obfuscation(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "m.py").write_text(
        "import subprocess as sp\nfrom os import system as s\nimport builtins\n"
        "sp.run(['ls'])\ns('id')\ngetattr(builtins, 'ex' + 'ec')('1')\n"
    )
    caps = pc.extract(d)
    assert caps["subprocess"] == ["m.py:4", "m.py:5"]
    assert "m.py:6" in caps["obfuscation"]
