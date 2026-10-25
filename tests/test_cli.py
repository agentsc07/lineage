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
