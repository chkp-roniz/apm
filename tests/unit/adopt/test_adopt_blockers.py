"""Regression tests for adopt review blockers (security, provenance, semantics)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from apm_cli.adopt.converters import ConvertContext, ConvertResult, register_builtin_converters
from apm_cli.adopt.converters.agents import AgentsConverter
from apm_cli.adopt.converters.base import NameAllocator
from apm_cli.adopt.converters.hooks import HooksConverter
from apm_cli.adopt.converters.mcp import to_manifest_entry
from apm_cli.adopt.materialize import _guard_adopt_paths, _resolve_dest, plan_write
from apm_cli.adopt.model import (
    AdoptionReport,
    Finding,
    HarnessKind,
    Importability,
    Ownership,
    Scope,
)
from apm_cli.adopt.provenance import ImportSources, hash_source, output_hash
from apm_cli.adopt.redact import Redactor
from apm_cli.cli import cli
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


def test_mcp_scrubs_flag_assignment_tokens():
    result = ConvertResult()
    entry = to_manifest_entry(
        "claude",
        "remote",
        {"command": "tool", "args": [f"--token={FAKE_TOKEN}", "--verbose"]},
        result,
    )
    assert FAKE_TOKEN not in json.dumps(entry)
    assert entry["args"][0].startswith("--token=${")
    assert entry["args"][1] == "--verbose"


def test_provenance_directory_hash_detects_local_edits(tmp_path: Path):
    source = tmp_path / ".tool" / "skills" / "demo"
    source.mkdir(parents=True)
    write(source / "SKILL.md", "---\nname: demo\ndescription: d\n---\nbody\n")
    dest = tmp_path / ".apm" / "skills" / "demo"
    dest.mkdir(parents=True)
    write(dest / "SKILL.md", "---\nname: demo\ndescription: d\n---\nbody\n")
    source_hash = hash_source(source)
    assert source_hash
    provenance = ImportSources.load(tmp_path / ".apm")
    provenance.record(
        "skills/demo",
        source=".tool/skills/demo",
        scope="project",
        converter="skills->skill",
        source_hash=source_hash,
        dest_abs=dest,
    )
    write(dest / "notes.txt", "local edit\n")
    assert output_hash(dest) != ""
    assert (
        provenance.decide("skills/demo", dest, source_hash, source=".tool/skills/demo")
        == "locally-modified"
    )


def test_resolve_dest_reuses_provenance_source(tmp_path: Path):
    apm_dir = tmp_path / ".apm"
    apm_dir.mkdir()
    provenance = ImportSources.load(apm_dir)
    from apm_cli.adopt.provenance import ImportRecord

    provenance.entries["agents/reviewer.agent.md"] = ImportRecord(
        source=".claude/agents/reviewer.md",
        scope="project",
        converter="claude_agent->agent",
        source_sha256="sha256:abc",
        output_sha256="sha256:def",
    )
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
    allocator = NameAllocator(apm_dir)
    dest_rel, renamed = _resolve_dest(finding, provenance, allocator)
    assert dest_rel == "agents/reviewer.agent.md"
    assert renamed is False


def test_plan_write_refuses_different_source_at_same_dest(tmp_path: Path):
    apm_dir = tmp_path / ".apm"
    apm_dir.mkdir()
    dest = apm_dir / "agents/reviewer.agent.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    write(dest, "---\nname: reviewer\ndescription: d\n---\nbody\n")
    provenance = ImportSources.load(apm_dir)
    provenance.record(
        "agents/reviewer.agent.md",
        source=".claude/agents/reviewer.md",
        scope="project",
        converter="claude_agent->agent",
        source_hash="sha256:old",
        dest_abs=dest,
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
    report = AdoptionReport(
        project_root_display=".",
        scopes=(Scope.PROJECT,),
        findings=(finding,),
        errors=(),
        detected_tools=("cursor",),
        proposed_targets=("cursor",),
        proposed_mcp=(),
        apm_yml_exists=False,
    )
    register_builtin_converters()
    plan = plan_write(report, apm_dir, provenance, NameAllocator(apm_dir))
    assert plan.items[0].decision == "collision"


def test_guard_adopt_paths_rejects_symlink_apm(tmp_path: Path):
    if os.name == "nt":
        pytest.skip("symlinks not reliable on this platform")
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "project"
    root.mkdir()
    (root / ".apm").symlink_to(outside)
    with pytest.raises(Exception, match="symlink"):
        _guard_adopt_paths(root, root / ".apm", root / "apm.yml")


def test_hooks_emit_canonical_event_names(tmp_path: Path):
    payload = {
        "hooks": {
            "beforeSubmitPrompt": [
                {
                    "matcher": "",
                    "hooks": [{"type": "command", "command": "echo hi"}],
                }
            ]
        }
    }
    finding = Finding(
        id="h",
        tool="cursor",
        scope=Scope.PROJECT,
        kind=HarnessKind.HOOK,
        display_path=".cursor/hooks.json",
        importability=Importability.CONVERTIBLE,
        ownership=Ownership.HOST_OWNED,
        converter_id="cursor_hooks->apm_hooks",
        payload={"tool": "cursor", "hooks": payload["hooks"]},
    )
    dest = tmp_path / ".apm" / "hooks" / "cursor-native.json"
    ctx = ConvertContext(project_root=tmp_path, scope=Scope.PROJECT, redactor=Redactor(tmp_path))
    HooksConverter().convert(finding, dest, ctx=ctx)
    hooks = json.loads(dest.read_text(encoding="utf-8"))["hooks"]
    assert "UserPromptSubmit" in hooks
    assert "beforeSubmitPrompt" not in hooks


def test_hooks_preserve_shell_operators(tmp_path: Path):
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
        payload={"tool": "claude", "hooks": payload["hooks"]},
    )
    dest = tmp_path / ".apm" / "hooks" / "claude-native.json"
    ctx = ConvertContext(
        project_root=tmp_path,
        scope=Scope.PROJECT,
        redactor=Redactor(tmp_path),
        include_hook_scripts=True,
    )
    HooksConverter().convert(finding, dest, ctx=ctx)
    command = json.loads(dest.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]["hooks"][0][
        "command"
    ]
    assert "&&" in command
    assert "$VAR" in command


def test_opencode_agent_preserves_tools_map(tmp_path: Path):
    src = write(
        tmp_path / ".opencode/agents/reviewer.md",
        "---\nname: reviewer\ndescription: d\ntools:\n  read: true\n  write: false\n---\nbody\n",
    )
    dest = tmp_path / ".apm/agents/reviewer.agent.md"
    ctx = ConvertContext(project_root=tmp_path, scope=Scope.PROJECT, redactor=Redactor(tmp_path))
    AgentsConverter().convert(
        _finding(src, HarnessKind.AGENT, "opencode", "opencode_agent", "opencode_agent->agent"),
        dest,
        ctx=ctx,
    )
    meta = yaml.safe_load(dest.read_text(encoding="utf-8").split("---")[1])
    assert meta["tools"] == {"read": True, "write": False}


def test_apply_refuses_symlink_apm_dir(in_project: Path, tmp_path: Path):
    if os.name == "nt":
        pytest.skip("symlinks not reliable on this platform")
    outside = tmp_path / "outside_apm"
    outside.mkdir()
    (in_project / ".apm").symlink_to(outside)
    result = CliRunner().invoke(cli, ["init", "--discover", "--apply", "--yes", "--format", "json"])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["write"]["status"] == "failed"
    assert "symlink" in payload["write"]["manifest"][0].lower()
