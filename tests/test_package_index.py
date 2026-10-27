"""R2.7 / test 6: pip installs only admitted wheels, pinned by hash (REFACTOR_SPEC section 5)."""
import base64
import socket
import subprocess
import sys
import threading
import time
import zipfile

import pytest
import uvicorn

from lineage.intake.hub import HttpHub
from lineage_server import auth, db
from lineage_server.app import create_app
from tests.fakehub import create_app as create_hub


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Serve:
    def __init__(self, app):
        self.port = free_port()
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return f"http://127.0.0.1:{self.port}"
            time.sleep(0.05)
        raise RuntimeError("server did not start")

    def __exit__(self, *a):
        self.server.should_exit = True
        self.thread.join(5)


def wheel(path, name, version, files):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        for n, c in files.items():
            z.writestr(n, c)
        z.writestr(f"{name}-{version}.dist-info/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")
        z.writestr(f"{name}-{version}.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        z.writestr(f"{name}-{version}.dist-info/RECORD", "")
    return path


@pytest.fixture
def stack(tmp_path, policy_path, monkeypatch):
    monkeypatch.setenv("LINEAGE_OFFLINE", "1")
    root = tmp_path / "hub"
    wheel(root / "pypi" / "toypkg" / "1.0.0" / "toypkg-1.0.0-py3-none-any.whl", "toypkg", "1.0.0", {"toypkg/__init__.py": "def f():\n    return 1\n"})
    payload = base64.b64encode(b"open('/tmp/lineage_marker_toypkg','w').write('inert')").decode()
    wheel(root / "pypi" / "toypkg" / "2.0.0" / "toypkg-2.0.0-py3-none-any.whl", "toypkg", "2.0.0",
          {"toypkg/__init__.py": "def f():\n    return 2\n", "toypkg_init.pth": f"import base64; exec(base64.b64decode('{payload}'))\n"})
    records = {"pypi:toypkg==1.0.0": {"released_at": "2025-01-01T00:00:00Z"}, "pypi:toypkg==2.0.0": {"released_at": "2025-01-02T00:00:00Z"}}
    with Serve(create_hub(root, records)) as hub_url:
        app = create_app(tmp_path / "idx.db", policy_path, hub=HttpHub(base_url=hub_url, trusted_local=False), require_auth=True)
        conn = db.connect(tmp_path / "idx.db")
        token = auth.create_user(conn, "pipuser", "requester", env="dev")
        conn.commit()
        with Serve(app) as url:
            yield url, token, tmp_path
    return


def intake(url, token, source):
    import httpx

    h = {"Authorization": f"Bearer {token}"}
    r = httpx.post(f"{url}/intake", headers=h, json={"artifact_type": "package", "source": source, "environment": "dev"})
    assert r.status_code == 200, r.text
    text = httpx.get(url + r.json()["events_url"], headers=h, timeout=60).text
    import json

    return next(json.loads(e)["decision"] for e in text.split("data: ")[1:] if json.loads(e).get("decision"))


def pip_download(url, token, spec, out):
    index = url.replace("http://", f"http://pipuser:{token}@") + "/simple/"
    return subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps", "--no-cache-dir", "--disable-pip-version-check",
                           "--index-url", index, "-d", str(out), spec], capture_output=True, text=True, timeout=120)


def test_pip_gets_the_admitted_wheel_and_nothing_for_the_blocked_one(stack):
    import httpx

    url, token, tmp = stack
    good = intake(url, token, "pypi:toypkg==1.0.0")
    bad = intake(url, token, "pypi:toypkg==2.0.0")
    assert good["outcome"] == "allow" and bad["outcome"] == "block"
    # the index lists only the admitted version, with a hash pin on every link
    page = httpx.get(f"{url}/simple/toypkg/", headers={"Authorization": f"Bearer {token}"}).text
    assert "toypkg-1.0.0" in page and "toypkg-2.0.0" not in page and "#sha256=" in page
    ok = pip_download(url, token, "toypkg==1.0.0", tmp / "out1")
    assert ok.returncode == 0, ok.stderr[-600:]
    assert list((tmp / "out1").glob("toypkg-1.0.0*.whl"))
    nope = pip_download(url, token, "toypkg==2.0.0", tmp / "out2")
    assert nope.returncode != 0 and not list((tmp / "out2").glob("*")) if (tmp / "out2").exists() else nope.returncode != 0
    # unpinned latest resolves to the newest *admitted* version, not the blocked 2.0.0
    latest = pip_download(url, token, "toypkg", tmp / "out3")
    assert latest.returncode == 0 and list((tmp / "out3").glob("toypkg-1.0.0*.whl"))


def test_revocation_takes_the_wheel_off_the_index_at_once(stack):
    import httpx

    url, token, tmp = stack
    d = intake(url, token, "pypi:toypkg==1.0.0")
    h = {"Authorization": f"Bearer {token}"}
    sha = httpx.get(f"{url}/simple/toypkg/", headers=h).text.split("#sha256=")[1].split('"')[0]
    assert httpx.get(f"{url}/files/{sha}/toypkg-1.0.0-py3-none-any.whl", headers=h).status_code == 200
    # a requester cannot revoke; use an approver token
    conn = db.connect(tmp / "idx.db")
    boss = auth.create_user(conn, "boss", "approver")
    conn.commit()
    assert httpx.post(f"{url}/revoke/{d['artifact_id']}?reason=x", headers={"Authorization": f"Bearer {token}"}).status_code == 403
    assert httpx.post(f"{url}/revoke/{d['artifact_id']}?reason=x", headers={"Authorization": f"Bearer {boss}"}).status_code == 200
    assert httpx.get(f"{url}/files/{sha}/toypkg-1.0.0-py3-none-any.whl", headers=h).status_code == 404
    assert "toypkg-1.0.0" not in httpx.get(f"{url}/simple/toypkg/", headers=h).text


def test_unknown_project_triggers_an_intake_and_answers_404_with_the_job(stack):
    import httpx

    url, token, _ = stack
    r = httpx.get(f"{url}/simple/toypkg/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404 and r.headers["X-Lineage-Intake-Job"].startswith("/events/")
    # the job runs; once it finishes the project is served
    httpx.get(url + r.headers["X-Lineage-Intake-Job"], headers={"Authorization": f"Bearer {token}"}, timeout=60)
    assert "toypkg" in httpx.get(f"{url}/simple/toypkg/", headers={"Authorization": f"Bearer {token}"}).text


def test_the_index_needs_a_token(stack):
    import httpx

    url, _, _ = stack
    assert httpx.get(f"{url}/simple/").status_code == 401
