"""Public consent and execution receipts for the bounded import followups."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from apm_cli.adopt import materialize
from apm_cli.cli import cli
from apm_cli.utils import console

from .conftest import write

pytestmark = pytest.mark.component


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(root)
    return root


def _apply(*args: str, answer: str | None = None):
    return CliRunner().invoke(cli, ["init", "--discover", "--apply", *args], input=answer)


@pytest.mark.parametrize("targets", ["[cursor, misspelled-target]", "[]", "null"])
@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_invalid_manifest_targets_preserve_all_declared_state(
    project: Path, targets: str, fmt: str
) -> None:
    write(project / ".claude/rules/test.md", "Keep this rule.\n")
    manifest = write(
        project / "apm.yml",
        f"name: existing\nversion: 1.0.0\ntargets: {targets}\ndependencies:\n  apm: []\n",
    )
    before = manifest.read_bytes()
    result = _apply("--yes", "--format", fmt)
    assert result.exit_code == 1, result.output
    assert manifest.read_bytes() == before
    assert not (project / ".apm").exists()
    report = json.loads(result.stdout) if fmt == "json" else yaml.safe_load(result.stdout)
    assert report["write"]["status"] == "failed"
    assert "targets" in report["write"]["reason"]
    assert "targets: added" not in result.stderr


def test_no_writable_plan_names_protected_destination(project: Path) -> None:
    source = write(project / ".claude/rules/test.md", "Original rule.\n")
    assert _apply("--yes").exit_code == 0
    output = write(project / ".apm/instructions/test.instructions.md", "My local edit.\n")
    source.write_text("Source changed.\n")
    result = _apply("--yes")
    assert result.exit_code == 1, result.output
    assert ".claude/rules/test.md" in result.stdout
    assert "instructions/test.instructions.md" in result.stdout
    assert "locally-modified" in result.stdout
    assert "reconcile" in result.stdout
    assert output.read_text() == "My local edit.\n"
    assert "[y/N]" not in result.stdout + result.stderr


@pytest.mark.parametrize("fmt", ["json", "yaml"])
@pytest.mark.parametrize("yes", [False, True], ids=["consent", "yes"])
def test_scan_errors_are_disclosed_before_machine_consent(
    project: Path, monkeypatch: pytest.MonkeyPatch, fmt: str, yes: bool
) -> None:
    write(project / ".claude/rules/test.md", "Valid rule.\n")
    write(project / ".claude/settings.json", "{ malformed")
    monkeypatch.setattr(materialize, "_stdin_is_tty", lambda: True)
    result = _apply("--format", fmt, *(["--yes"] if yes else []), answer="n\n")
    assert result.exit_code == (1 if yes else 0), result.output
    report = json.loads(result.stdout) if fmt == "json" else yaml.safe_load(result.stdout)
    assert report["write"]["status"] == ("partial" if yes else "cancelled")
    assert "settings.json" in result.stderr
    assert "scan" in result.stderr.lower()
    if not yes:
        assert result.stderr.index("settings.json") < result.stderr.index("[y/N]")
    assert console._console_stderr is True


@pytest.mark.parametrize("fmt", ["text", "json", "yaml"])
def test_always_on_cursor_activation_warning_is_visible(project: Path, fmt: str) -> None:
    write(project / ".cursor/rules/test.mdc", "---\nalwaysApply: true\n---\nAlways on.\n")
    result = _apply("--yes", "--format", fmt)
    assert result.exit_code == 0, result.output
    plan = result.stdout if fmt == "text" else result.stderr
    assert "alwaysApply" in plan
    assert "not preserved" in plan
    assert "file matching" in plan


def test_mcp_only_completion_names_manifest_and_install_step(project: Path) -> None:
    write(
        project / ".mcp.json",
        json.dumps({"mcpServers": {"demo": {"command": "demo", "args": []}}}),
    )
    first = _apply("--yes")
    assert first.exit_code == 0, first.output
    assert "Imported 1 MCP server" in first.stdout
    assert "apm.yml" in first.stdout
    assert "Next steps" in first.stdout
    assert "apm install" in first.stdout
    second = _apply("--yes")
    assert second.exit_code == 0, second.output
    assert "No changes" in second.stdout
    assert "Next steps" not in second.stdout


def test_empty_completion_is_not_a_write_success(project: Path) -> None:
    result = _apply("--yes")
    assert result.exit_code == 0, result.output
    assert "No changes" in result.stdout
    assert "Wrote 0" not in result.stdout
    assert not (project / ".apm").exists()


def test_cleanup_failure_names_retained_changes_and_directory(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(project / ".claude/rules/test.md", "Committed rule.\n")
    original_cleanup = materialize.safe_rmtree

    def deny_staging(path, *args, **kwargs):
        if Path(path).name.startswith(".apm-adopt-"):
            raise PermissionError("test cleanup refusal")
        return original_cleanup(path, *args, **kwargs)

    monkeypatch.setattr(materialize, "safe_rmtree", deny_staging)
    result = _apply("--yes")
    assert result.exit_code == 1, result.output
    assert "remain committed" in result.stdout
    assert "instructions/test.instructions.md" in result.stdout
    staging = next(project.glob(".apm-adopt-*"))
    assert staging.name in result.stdout
    assert (project / ".apm/instructions/test.instructions.md").exists()
