"""Regression tests for adopt materialize helpers (review follow-ups)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from apm_cli.adopt.converters import ConvertResult
from apm_cli.adopt.converters.hooks import _unique_script_name, event_portability
from apm_cli.adopt.materialize import (
    WriteItem,
    _CommitTxn,
    _dedupe_mcp,
    _rollback,
    _staged_entries,
    commit,
)
from apm_cli.adopt.model import Finding, HarnessKind, Importability, Ownership, Scope
from apm_cli.adopt.provenance import ImportSources
from apm_cli.constants import APM_YML_FILENAME

pytestmark = pytest.mark.component


def _staged_item(staging: Path, primary: str, *outputs: str) -> WriteItem:
    finding = Finding(
        id=primary,
        tool="copilot",
        scope=Scope.PROJECT,
        kind=HarnessKind.INSTRUCTION,
        display_path=primary,
        importability=Importability.APM_NATIVE,
        ownership=Ownership.HOST_OWNED,
    )
    return WriteItem(
        finding,
        "passthrough.instruction",
        primary,
        "write",
        None,
        result=ConvertResult(written=[staging / output for output in outputs]),
    )


@pytest.mark.parametrize("parent_first", [False, True])
def test_staged_entries_cover_parent_and_children_once_in_retained_order(
    tmp_path: Path, parent_first: bool
) -> None:
    """Directories cover children even when another item reported the child first."""
    staging = tmp_path / "stage"
    parent = _staged_item(staging, "skills/example", "skills/example/SKILL.md")
    child = _staged_item(staging, "skills/example/assets/helper.py")
    first = _staged_item(staging, "instructions/first.md", "instructions/first.md")
    last = _staged_item(staging, "instructions/last.md", "instructions/last.md")
    middle = [parent, child] if parent_first else [child, parent]
    items = [first, *middle, last, parent, first]
    assert _staged_entries(items, staging) == [
        "instructions/first.md",
        "skills/example",
        "instructions/last.md",
    ]


def test_staged_entries_keep_hook_bundle_and_sibling_prefixes(tmp_path: Path) -> None:
    staging = tmp_path / "stage"
    (staging / "hooks/copilot-native/scripts").mkdir(parents=True)
    hook = _staged_item(
        staging,
        "hooks/copilot-native.json",
        "hooks/copilot-native.json",
        "hooks/copilot-native/scripts/check.sh",
        "hooks/copilot-native-extra/extra.sh",
        "hooks/copilot-native-extra/extra.sh",
    )
    hook.finding = replace(hook.finding, kind=HarnessKind.HOOK)
    assert _staged_entries([hook, hook], staging) == [
        "hooks/copilot-native.json",
        "hooks/copilot-native",
        "hooks/copilot-native-extra/extra.sh",
    ]


def test_staged_entries_ignore_failed_skipped_mcp_and_outside_outputs(tmp_path: Path) -> None:
    staging = tmp_path / "stage"
    valid = _staged_item(staging, "instructions/valid.md", "instructions/extra.md")
    valid.result.written.append(tmp_path / "outside.md")
    failed = replace(valid, dest_rel="failed", error="refused")
    skipped = replace(valid, dest_rel="skipped", result=ConvertResult(skipped_reason="ignored"))
    missing = replace(valid, dest_rel="missing", result=None)
    mcp = replace(valid, finding=replace(valid.finding, kind=HarnessKind.MCP_SERVER))
    assert _staged_entries([failed, skipped, missing, mcp, valid], staging) == [
        "instructions/valid.md",
        "instructions/extra.md",
    ]


def test_event_portability_lists_each_target_once():
    native, passthrough = event_portability("PreToolUse")
    assert native
    assert not (set(native) & set(passthrough))
    assert len(native) + len(passthrough) == len(set(native) | set(passthrough))


def test_dedupe_mcp_prefers_target_order():
    fragments = [
        ("claude", {"dependencies": {"mcp": [{"name": "shared", "command": "shared-cmd"}]}}),
        ("cursor", {"dependencies": {"mcp": [{"name": "shared", "command": "shared-cmd"}]}}),
    ]
    entries, notes = _dedupe_mcp(fragments, ("cursor", "claude"))
    assert entries[0]["command"] == "shared-cmd"
    assert not notes


def test_dedupe_mcp_keeps_target_rank_when_tool_reappears_in_defaults():
    """``cursor`` in both ``--target`` and the default order must not lose rank."""
    fragments = [
        ("claude", {"dependencies": {"mcp": [{"name": "shared", "command": "claude-cmd"}]}}),
        ("cursor", {"dependencies": {"mcp": [{"name": "shared", "command": "cursor-cmd"}]}}),
    ]
    entries, _ = _dedupe_mcp(fragments, ("cursor",))
    assert entries[0]["command"] == "cursor-cmd"


def test_dedupe_mcp_reports_divergent_definitions():
    fragments = [
        ("claude", {"dependencies": {"mcp": [{"name": "x", "command": "a"}]}}),
        ("cursor", {"dependencies": {"mcp": [{"name": "x", "command": "b"}]}}),
    ]
    entries, notes = _dedupe_mcp(fragments, ("cursor",))
    assert entries[0]["command"] == "b"
    assert notes and "divergent" in notes[0]


def test_unique_script_name_avoids_basename_collision(tmp_path: Path):
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    first = tmp_path / "hooks" / "notify.sh"
    second = tmp_path / "other" / "notify.sh"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_bytes(b"first\n")
    second.write_bytes(b"second\n")
    (scripts_dir / "notify.sh").write_bytes(b"first\n")
    name = _unique_script_name(scripts_dir, second, second.read_bytes())
    assert name != "notify.sh"
    assert (scripts_dir / name).name == name


def test_unique_script_name_reuses_identical_content(tmp_path: Path):
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    candidate = tmp_path / "notify.sh"
    candidate.write_bytes(b"same\n")
    (scripts_dir / "notify.sh").write_bytes(b"same\n")
    assert _unique_script_name(scripts_dir, candidate, candidate.read_bytes()) == "notify.sh"


def test_commit_refresh_rollback_restores_previous_import(tmp_path: Path):
    apm_dir = tmp_path / ".apm"
    staging = tmp_path / "stage" / ".apm"
    backup_root = tmp_path / "stage" / ".adopt-backup"
    apm_dir.mkdir(parents=True)
    staging.mkdir(parents=True)
    dest_rel = "agents/reviewer.agent.md"
    original = apm_dir / dest_rel
    original.parent.mkdir(parents=True)
    original.write_text("original import\n", encoding="utf-8")
    (staging / dest_rel).parent.mkdir(parents=True)
    (staging / dest_rel).write_text("refreshed import\n", encoding="utf-8")
    manifest = tmp_path / APM_YML_FILENAME
    manifest.write_text("name: p\n", encoding="utf-8")
    provenance = ImportSources.load(apm_dir)
    provenance.record(
        dest_rel,
        source=".claude/agents/reviewer.md",
        scope="project",
        converter="claude_agent->agent",
        source_hash="sha256:old",
        dest_abs=original,
    )
    provenance.save()
    manifest_before = manifest.read_bytes()
    provenance_before = provenance.path.read_bytes()
    txn = _CommitTxn()
    committed = commit(
        staging,
        apm_dir,
        [dest_rel],
        overwrite_rels=frozenset({dest_rel}),
        txn=txn,
        backup_root=backup_root,
    )
    assert committed == [dest_rel]
    assert original.read_text(encoding="utf-8") == "refreshed import\n"
    with patch(
        "apm_cli.adopt.manifest_edit.apply_manifest_delta",
        side_effect=RuntimeError("manifest write failed"),
    ):
        _rollback(
            apm_dir,
            txn,
            manifest,
            manifest_before,
            provenance_path=provenance.path,
            provenance_before=provenance_before,
        )
    assert original.read_text(encoding="utf-8") == "original import\n"
    assert manifest.read_bytes() == manifest_before
    assert provenance.path.read_bytes() == provenance_before
