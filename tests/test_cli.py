"""Tests for the scan-toolkit CLI stubs."""

import pytest
from typer.testing import CliRunner

from scan_toolkit.main import app

runner = CliRunner()


def test_help_shows_subcommands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ["intake", "run", "status", "report"]:
        assert cmd in result.output


def test_intake_stub():
    result = runner.invoke(app, ["intake"])
    assert result.exit_code == 0
    assert "not implemented" in result.output.lower()
    assert "phase 2" in result.output.lower()


def test_run_stub():
    result = runner.invoke(app, ["run", "dummy-engagement-id"])
    assert result.exit_code == 0
    assert "not implemented" in result.output.lower()


def test_status_stub():
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "not implemented" in result.output.lower()
    assert "phase 11" in result.output.lower()


def test_report_stub():
    result = runner.invoke(app, ["report", "dummy-engagement-id"])
    assert result.exit_code == 0
    assert "not implemented" in result.output.lower()
    assert "phase 10" in result.output.lower()