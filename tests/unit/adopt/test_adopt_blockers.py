"""Regression tests for adopt review blockers (security, provenance, semantics)."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from apm_cli.adopt.converters import (
    ConvertContext,
    ConvertError,
    ConvertResult,
    register_builtin_converters,
)
from apm_cli.adopt.converters.agents import AgentsConverter
from apm_cli.adopt.converters.base import NameAllocator
from apm_cli.adopt.converters.hooks import HooksConverter
from apm_cli.adopt.converters.mcp import to_manifest_entry
from apm_cli.adopt.materialize import _preflight, plan_write, stage
from apm_cli.adopt.model import (
    AdoptionReport,
    Finding,
    HarnessKind,
    Importability,
    Ownership,
    Scope,
)
from apm_cli.adopt.provenance import ImportSources, hash_source, source_identity
from apm_cli.adopt.redact import Redactor
from apm_cli.cli import cli
from apm_cli.utils.path_security import PathTraversalError
from tests.unit.adopt.conftest import FAKE_TOKEN, write

pytestmark = pytest.mark.component


def _finding(path: Path, kind: HarnessKind, tool: str, fmt: str, converter: str) -> Finding:
    return Finding(
        id="x",
        tool=tool,
        scope=Scope.PROJECT,
        kind=kind,
        display_path=path.as_posix(),
        importability=Importability.CONVERTIBLE,
        ownership=Ownership.HOST_OWNED,
        converter_id=converter,
        abs_path=path,
        format_id=fmt,
    )


@pytest.mark.parametrize(
    "args",
    [
        [f"--token={FAKE_TOKEN}", "--verbose"],
        ["--token", FAKE_TOKEN, "--verbose"],
        ["--token=synthetic-password", "--verbose"],
        ["--token", "synthetic-password", "--verbose"],
    ],
)
def test_mcp_scrubs_flag_assignment_tokens(
    args: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refuse literals: argument placeholders cannot be replayed by the renderer."""
    result = ConvertResult()
    with pytest.raises(ConvertError, match="literal credential") as exc:
        to_manifest_entry("claude", "remote", {"command": "tool", "args": args}, result)
    assert FAKE_TOKEN not in str(exc.value)
    assert "synthetic-password" not in str(exc.value)
    assert FAKE_TOKEN not in json.dumps([change.to_dict() for change in result.changes])
    assert result.manifest_fragment is None
    entry = to_manifest_entry(
        "claude",
        "remote",
        {"command": "tool", "args": ["--log-level", "debug", "--verbose"]},
        ConvertResult(),
    )
    assert entry["args"] == ["--log-level", "debug", "--verbose"]
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(project)
    source = write(
        project / ".mcp.json",
        json.dumps({"mcpServers": {"remote": {"command": "tool", "args": args}}}),
    )
    before = source.read_bytes()
    applied = CliRunner().invoke(
        cli, ["init", "--discover", "--apply", "--yes", "--format", "json"]
    )
    assert applied.exit_code == 1
    for stream in (applied.stdout, applied.stderr):
        assert FAKE_TOKEN not in stream
        assert "synthetic-password" not in stream
    report = json.loads(applied.stdout)
    assert report["write"]["status"] == "partial"
    assert "literal credential" in report["write"]["failed"][0]["reason"]
    assert report["write"]["mcp_imported"] == 0
    assert report["write"]["written"] == []
    assert not (project / "apm.yml").exists()
    assert source.read_bytes() == before


def test_provenance_directory_hash_detects_local_edits(tmp_path: Path) -> None:
    source = tmp_path / ".tool" / "skills" / "demo"
    source.mkdir(parents=True)
    write(source / "SKILL.md", "---\nname: demo\ndescription: d\n---\nbody\n")
    dest = tmp_path / ".apm" / "skills" / "demo"
    dest.mkdir(parents=True)
    write(dest / "SKILL.md", "---\nname: demo\ndescription: d\n---\nbody\n")
    finding = replace(
        _finding(source, HarnessKind.SKILL, "claude", "skill", "skills->skill"),
        display_path=".tool/skills/demo",
    )
    identity = source_identity(finding)
    source_hash = hash_source(source, root=tmp_path)
    assert source_hash
    provenance = ImportSources.load(tmp_path / ".apm")
    provenance.record(
        "skills/demo",
        source=".tool/skills/demo",
        scope="project",
        converter="skills->skill",
        source_hash=source_hash,
        dest_abs=dest,
        identity=identity,
    )
    before = provenance.inspect("skills/demo", dest, source_hash, identity=identity)
    assert before.decision == "unchanged"
    assert before.current_hash == hash_source(dest, root=tmp_path)
    write(dest / "notes.txt", "local edit\n")
    after = provenance.inspect("skills/demo", dest, source_hash, identity=identity)
    assert after.decision == "locally-modified"
    assert after.current_hash == hash_source(dest, root=tmp_path)
    assert after.current_hash != before.current_hash
    assert (dest / "notes.txt").read_text(encoding="utf-8") == "local edit\n"


def test_resolve_dest_reuses_provenance_source(tmp_path: Path) -> None:
    apm_dir = tmp_path / ".apm"
    apm_dir.mkdir()
    provenance = ImportSources.load(apm_dir)
    finding = Finding(
        id="1",
        tool="claude",
        scope=Scope.PROJECT,
        kind=HarnessKind.AGENT,
        display_path=".claude/agents/reviewer.md",
        importability=Importability.CONVERTIBLE,
        ownership=Ownership.HOST_OWNED,
        converter_id="claude_agent->agent",
        abs_path=tmp_path / ".claude/agents/reviewer.md",
        format_id="claude_agent",
    )
    source = write(finding.abs_path, "---\nname: reviewer\ndescription: d\n---\nbody\n")
    dest = write(apm_dir / "agents/reviewer.agent.md", source.read_text(encoding="utf-8"))
    source_hash = hash_source(source, root=tmp_path)
    assert source_hash is not None
    provenance.record(
        "agents/reviewer.agent.md",
        source=finding.display_path,
        scope=finding.scope.value,
        converter=finding.converter_id,
        source_hash=source_hash,
        dest_abs=dest,
        identity=source_identity(finding),
    )
    provenance.save()
    provenance = ImportSources.load(apm_dir)
    index = provenance.for_plan((finding,))
    assert index.destination(finding) == "agents/reviewer.agent.md"
    assert index.outputs("agents/reviewer.agent.md") == ["agents/reviewer.agent.md"]
    register_builtin_converters()
    plan = plan_write(_report(finding), apm_dir, provenance, NameAllocator(apm_dir))
    assert [(item.dest_rel, item.decision) for item in plan.items] == [
        ("agents/reviewer.agent.md", "unchanged")
    ]
    assert plan.items[0].expected == {"agents/reviewer.agent.md": hash_source(dest, root=tmp_path)}


def test_plan_write_refuses_different_source_at_same_dest(tmp_path: Path) -> None:
    apm_dir = tmp_path / ".apm"
    apm_dir.mkdir()
    dest = apm_dir / "agents/reviewer.agent.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    write(dest, "---\nname: reviewer\ndescription: d\n---\nbody\n")
    before = dest.read_bytes()
    original = replace(
        _finding(
            tmp_path / ".claude/agents/reviewer.md",
            HarnessKind.AGENT,
            "claude",
            "claude_agent",
            "claude_agent->agent",
        ),
        display_path=".claude/agents/reviewer.md",
    )
    provenance = ImportSources.load(apm_dir)
    provenance.record(
        "agents/reviewer.agent.md",
        source=".claude/agents/reviewer.md",
        scope="project",
        converter="claude_agent->agent",
        source_hash="sha256:old",
        dest_abs=dest,
        identity=source_identity(original),
    )
    other = tmp_path / ".cursor/agents/reviewer.md"
    write(other, "---\nname: reviewer\ndescription: d\n---\nbody\n")
    finding = Finding(
        id="2",
        tool="cursor",
        scope=Scope.PROJECT,
        kind=HarnessKind.AGENT,
        display_path=".cursor/agents/reviewer.md",
        importability=Importability.CONVERTIBLE,
        ownership=Ownership.HOST_OWNED,
        converter_id="claude_agent->agent",
        abs_path=other,
        format_id="claude_agent",
    )
    register_builtin_converters()
    plan = plan_write(_report(finding), apm_dir, provenance, NameAllocator(apm_dir))
    assert len(plan.items) == 1
    item = plan.items[0]
    assert item.error is None
    assert item.dest_rel == "agents/reviewer-cursor.agent.md"
    assert item.decision == "write"
    # The collision is solved by reservation, never by stealing the old owner.
    assert (
        provenance.inspect(
            "agents/reviewer.agent.md",
            dest,
            hash_source(other, root=tmp_path),
            identity=source_identity(finding),
        ).decision
        == "collision"
    )
    assert provenance.for_plan((original, finding)).destination(original) == (
        "agents/reviewer.agent.md"
    )
    repeated = plan_write(_report(finding), apm_dir, provenance, NameAllocator(apm_dir))
    assert repeated.items[0].dest_rel == item.dest_rel
    assert dest.read_bytes() == before
    assert provenance.entries["agents/reviewer.agent.md"].identity == source_identity(original)


def _report(finding: Finding) -> AdoptionReport:
    return AdoptionReport(
        project_root_display=".",
        scopes=(Scope.PROJECT,),
        findings=(finding,),
        errors=(),
        detected_tools=(finding.tool,),
        proposed_targets=(finding.tool,),
        proposed_mcp=(),
        apm_yml_exists=False,
    )


def test_guard_adopt_paths_rejects_symlink_apm(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlinks not reliable on this platform")
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "project"
    root.mkdir()
    (root / ".apm").symlink_to(outside)
    with pytest.raises(PathTraversalError, match="symlink"):
        _preflight(root, root / ".apm", root / "apm.yml")
    assert list(outside.iterdir()) == []
    assert not (root / "apm.yml").exists()


def test_hooks_emit_canonical_event_names(tmp_path: Path) -> None:
    payload = {"hooks": {"beforeSubmitPrompt": [{"command": "echo hi"}]}}
    finding = Finding(
        id="h",
        tool="cursor",
        scope=Scope.PROJECT,
        kind=HarnessKind.HOOK,
        display_path=".cursor/hooks.json",
        importability=Importability.CONVERTIBLE,
        ownership=Ownership.HOST_OWNED,
        converter_id="cursor_hooks->apm_hooks",
        format_id="cursor_hooks",
        payload={"tool": "cursor", "hooks": payload["hooks"]},
    )
    dest = tmp_path / ".apm" / "hooks" / "cursor-native.json"
    ctx = ConvertContext(project_root=tmp_path, scope=Scope.PROJECT, redactor=Redactor(tmp_path))
    result = HooksConverter().convert(finding, dest, ctx=ctx)
    assert result.skipped_reason is None
    assert result.written == [dest]
    hooks = json.loads(dest.read_text(encoding="utf-8"))["hooks"]
    assert "UserPromptSubmit" in hooks
    assert "beforeSubmitPrompt" not in hooks
    assert hooks["UserPromptSubmit"][0]["hooks"][0]["command"] == "echo hi"


def test_hooks_preserve_shell_operators(tmp_path: Path) -> None:
    write(tmp_path / "scripts/run.sh", "#!/bin/sh\necho ok\n")
    payload = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "./scripts/run.sh && echo $VAR",
                        }
                    ],
                }
            ]
        }
    }
    finding = Finding(
        id="h2",
        tool="claude",
        scope=Scope.PROJECT,
        kind=HarnessKind.HOOK,
        display_path=".claude/settings.json",
        importability=Importability.CONVERTIBLE,
        ownership=Ownership.HOST_OWNED,
        converter_id="claude_hooks->apm_hooks",
        format_id="claude_hooks",
        payload={"tool": "claude", "hooks": payload["hooks"]},
    )
    dest = tmp_path / ".apm" / "hooks" / "claude-native.json"
    ctx = ConvertContext(
        project_root=tmp_path,
        scope=Scope.PROJECT,
        redactor=Redactor(tmp_path),
        include_hook_scripts=True,
    )
    result = HooksConverter().convert(finding, dest, ctx=ctx)
    assert result.skipped_reason is None
    command = json.loads(dest.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]["hooks"][0][
        "command"
    ]
    assert command == "./claude-native/scripts/scripts/run.sh && echo $VAR"
    copied = dest.parent / "claude-native/scripts/scripts/run.sh"
    assert copied in result.written
    assert copied.read_bytes() == (tmp_path / "scripts/run.sh").read_bytes()


def test_opencode_agent_preserves_tools_map(tmp_path: Path) -> None:
    """Reference-only keeps the restriction; neutral rendering would drop it."""
    src = write(
        tmp_path / ".opencode/agents/reviewer.md",
        "---\nname: reviewer\ndescription: d\ntools:\n  read: true\n  write: false\n---\nbody\n",
    )
    dest = tmp_path / ".apm/agents/reviewer.agent.md"
    ctx = ConvertContext(project_root=tmp_path, scope=Scope.PROJECT, redactor=Redactor(tmp_path))
    before = src.read_bytes()
    finding = replace(
        _finding(src, HarnessKind.AGENT, "opencode", "opencode_agent", "opencode_agent->agent"),
        display_path=".opencode/agents/reviewer.md",
    )
    result = AgentsConverter().convert(finding, dest, ctx=ctx)
    assert result.skipped_reason == (
        "OpenCode native tools/permission policy has no preserving renderer"
    )
    assert result.written == []
    assert not dest.exists()
    register_builtin_converters()
    apm_dir = tmp_path / ".apm"
    plan = plan_write(
        _report(finding), apm_dir, ImportSources.load(apm_dir), NameAllocator(apm_dir)
    )
    assert stage(plan, tmp_path / "staging", ctx) == []
    assert plan.items[0].decision == "reference-only"
    assert plan.items[0].error is None
    assert not (tmp_path / "staging").exists()
    assert src.read_bytes() == before


def test_apply_refuses_symlink_apm_dir(in_project: Path, tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlinks not reliable on this platform")
    outside = tmp_path / "outside_apm"
    outside.mkdir()
    (in_project / ".apm").symlink_to(outside)
    result = CliRunner().invoke(cli, ["init", "--discover", "--apply", "--yes", "--format", "json"])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["write"]["status"] == "failed"
    assert "PathTraversalError" in payload["write"]["reason"]
    assert payload["write"]["written"] == []
    assert payload["write"]["manifest_updated"] is False
    assert payload["write"]["recovery"] == "not-needed"
    assert list(outside.iterdir()) == []
    assert not (in_project / "apm.yml").exists()
