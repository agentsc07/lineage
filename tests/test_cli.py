import pytest
from typer.testing import CliRunner

from lineage.cli import app

runner = CliRunner()
COMMANDS = ["intake", "verify", "sign", "diff", "run", "load-check", "revoke", "bench"]


def test_help_lists_all_commands():
    out = runner.invoke(app, ["--help"]).output
    assert all(c in out for c in COMMANDS)


def test_stub_command_exits_cleanly(tiny_model, tiny_model_child):
    r = runner.invoke(app, ["diff", str(tiny_model / "model.safetensors"), str(tiny_model_child / "model.safetensors")])
    assert r.exit_code == 2 and "not implemented" in r.output
