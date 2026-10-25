import pytest
from typer.testing import CliRunner

from lineage.cli import app

runner = CliRunner()
COMMANDS = ["intake", "verify", "sign", "diff", "run", "load-check", "revoke", "bench"]


def test_help_lists_all_commands():
    out = runner.invoke(app, ["--help"]).output
    assert all(c in out for c in COMMANDS)


def test_stub_command_exits_cleanly(tiny_model):
    r = runner.invoke(app, ["intake", str(tiny_model)])  # Track B's command is still a stub
    assert r.exit_code == 2 and "not implemented" in r.output
