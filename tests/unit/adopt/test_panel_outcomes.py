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


@pytest.mark.parametrize("fmt", ["text", "json", "yaml"])
def test_cleanup_failure_names_retained_changes_and_directory(
    project: Path, monkeypatch: pytest.MonkeyPatch, fmt: str
) -> None:
    write(project / ".claude/rules/test.md", "Committed rule.\n")
    original_cleanup = materialize.safe_rmtree

    def deny_staging(path, *args, **kwargs):
        if Path(path).name.startswith(".apm-adopt-"):
            raise PermissionError("test cleanup refusal")
        return original_cleanup(path, *args, **kwargs)

    monkeypatch.setattr(materialize, "safe_rmtree", deny_staging)
    result = _apply("--yes", "--format", fmt)
    assert result.exit_code == 1, result.output
    staging = next(project.glob(".apm-adopt-*"))
    assert (project / ".apm/instructions/test.instructions.md").exists()
    if fmt == "text":
        assert "remain committed" in result.stdout
        assert "instructions/test.instructions.md" in result.stdout
        assert staging.name in result.stdout
    else:
        report = json.loads(result.stdout) if fmt == "json" else yaml.safe_load(result.stdout)
        receipt = report["write"]
        assert receipt["status"] == "failed"
        assert receipt["recovery"] == "not-needed"
        assert receipt["state_known"] is True
        assert receipt["written"] == ["instructions/test.instructions.md"]
        assert receipt["manifest_updated"] is True
        assert receipt["mcp_imported"] == 0
        assert receipt["affected"] == []
        assert receipt["recovery_directory"] == staging.name


@pytest.mark.parametrize("fmt", ["text", "json", "yaml"])
@pytest.mark.parametrize("deny_restore", [False, True], ids=["restored", "incomplete"])
@pytest.mark.parametrize("global_scope", [False, True], ids=["project", "user"])
def test_late_provenance_failure_reports_durable_or_unknown_state(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    fmt: str,
    deny_restore: bool,
    global_scope: bool,
) -> None:
    """Actual writes precede the injected fault; deleted outputs are not durable writes."""
    project = Path.home() if global_scope else project
    scope_args = ["--global"] if global_scope else []
    display_prefix = "~/" if global_scope else ""
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    source = write(project / ".claude/rules/test.md", "Original rule.\n")
    assert _apply("--yes", "--format", "json", *scope_args).exit_code == 0
    output = project / ".apm/instructions/test.instructions.md"
    manifest = project / ".apm/apm.yml" if global_scope else project / "apm.yml"
    provenance = project / ".apm/.import-sources.json"
    before = {path: path.read_bytes() for path in (output, manifest, provenance)}
    source.write_text("Upstream replacement.\n", encoding="utf-8")
    write(
        project / (".claude.json" if global_scope else ".mcp.json"),
        json.dumps({"mcpServers": {"late": {"command": "printf", "args": ["inert"]}}}),
    )
    original_save = materialize.ImportSources.save
    observed: list[str] = []

    def fail_after_save(self):
        original_save(self)
        assert b"Upstream replacement." in output.read_bytes()
        assert manifest.read_bytes() != before[manifest]
        assert provenance.read_bytes() != before[provenance]
        observed.append("saved")
        raise OSError("late provenance failure")

    def fail_restore(*args, **kwargs):
        observed.append("restore-denied")
        raise PermissionError("destination restore denied")

    monkeypatch.setattr(materialize.ImportSources, "save", fail_after_save)
    if deny_restore:
        monkeypatch.setattr(materialize, "_restore_destination", fail_restore)
    result = _apply("--yes", "--format", fmt, *scope_args)
    assert result.exit_code == 1, result.output
    assert observed == (["saved", "restore-denied"] if deny_restore else ["saved"])
    if deny_restore:
        assert not output.exists(), "rollback removed the output before restoration failed"
        assert manifest.read_bytes() != before[manifest]
        assert provenance.read_bytes() != before[provenance]
        assert yaml.safe_load(manifest.read_text())["dependencies"]["mcp"][0]["name"] == "late"
        staging = next(project.glob(".apm-adopt-*"))
        assert any(
            path.is_file() and path.read_bytes() == before[output]
            for path in (staging / ".adopt-backup").iterdir()
        ), "original bytes must remain in the reported recovery directory"
    else:
        assert {path: path.read_bytes() for path in before} == before
        assert not list(project.glob(".apm-adopt-*"))
    if fmt == "text":
        assert f"recovery: {'incomplete' if deny_restore else 'restored'}" in result.stdout
        assert "remain committed" not in result.stdout
        if deny_restore:
            receipt_text = result.stdout.split("Automatic recovery is incomplete;", 1)[1]
            assert "state is unknown" in receipt_text
            for path in before:
                assert display_prefix + path.relative_to(project).as_posix() in receipt_text
            assert display_prefix + staging.name in receipt_text
            assert "before retrying" in receipt_text
        return
    report = json.loads(result.stdout) if fmt == "json" else yaml.safe_load(result.stdout)
    receipt = report["write"]
    assert receipt["status"] == "failed"
    assert receipt["recovery"] == ("incomplete" if deny_restore else "restored")
    assert receipt["state_known"] is not deny_restore
    assert receipt["written"] == [], "never present attempted or removed paths as committed"
    assert receipt["manifest_updated"] is (None if deny_restore else False)
    assert receipt["mcp_imported"] == (None if deny_restore else 0)
    assert receipt["affected"] == (
        [display_prefix + path.relative_to(project).as_posix() for path in before]
        if deny_restore
        else []
    )
    assert receipt["recovery_directory"] == (
        display_prefix + staging.name if deny_restore else None
    )


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_success_and_noop_keep_known_receipt_contract(project: Path, fmt: str) -> None:
    write(project / ".claude/rules/test.md", "Import this rule.\n")
    write(
        project / ".mcp.json",
        json.dumps({"mcpServers": {"demo": {"command": "printf", "args": ["inert"]}}}),
    )
    for first in (True, False):
        result = _apply("--yes", "--format", fmt)
        assert result.exit_code == 0, result.output
        report = json.loads(result.stdout) if fmt == "json" else yaml.safe_load(result.stdout)
        receipt = report["write"]
        assert receipt["status"] == "complete"
        assert receipt["recovery"] == "not-needed"
        assert receipt["state_known"] is True
        assert receipt["written"] == (["instructions/test.instructions.md"] if first else [])
        assert receipt["manifest_updated"] is first
        assert receipt["mcp_imported"] == (1 if first else 0)
        assert receipt["affected"] == []
        assert receipt["recovery_directory"] is None
