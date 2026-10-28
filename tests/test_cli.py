import pytest
from typer.testing import CliRunner

from lineage.cli import app

runner = CliRunner()
COMMANDS = ["intake", "verify", "sign", "diff", "run", "load-check", "revoke", "bench"]


def test_help_lists_all_commands():
    out = runner.invoke(app, ["--help"]).output
    assert all(c in out for c in COMMANDS)


def test_intake_runs_through_the_pipeline(tiny_model):
    r = runner.invoke(app, ["intake", str(tiny_model)])  # Track B: stages stream as JSON lines, S6 carries the decision
    assert r.exit_code == 0 and '"stage":"S6"' in r.output.replace(" ", "") and '"outcome"' in r.output


def test_revoke_uses_the_configured_server_and_sends_the_token(monkeypatch):
    """Mocked transport: it checks the request the CLI builds. The live behaviour is in docs/CONSUMER_AND_PASSPORT_FLOW.md."""
    import httpx
    from typer.testing import CliRunner
    from lineage.cli import app

    seen = {}

    def fake_post(url, params=None, headers=None, timeout=None):
        seen.update(url=url, headers=headers)
        return httpx.Response(200, request=httpx.Request("POST", url), json={"revoked": "lp:x", "reason": "r", "blast_radius": []})

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setenv("LINEAGE_SERVER", "http://registry.example:9")
    monkeypatch.setenv("LINEAGE_TOKEN", "lg_secret")
    res = CliRunner().invoke(app, ["revoke", "lp:x", "--reason", "r"])
    assert res.exit_code == 0, res.output
    assert seen["url"] == "http://registry.example:9/revoke/lp:x" and seen["headers"] == {"Authorization": "Bearer lg_secret"}
