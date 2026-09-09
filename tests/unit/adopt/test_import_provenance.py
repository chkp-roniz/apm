"""Behavioral guardrail for full importer witnesses and durable source ownership."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from apm_cli.adopt import provenance
from apm_cli.adopt.converters import register_builtin_converters
from apm_cli.adopt.converters.base import NameAllocator
from apm_cli.adopt.materialize import plan_write
from apm_cli.adopt.model import (
    AdoptionReport,
    Finding,
    HarnessKind,
    Importability,
    Ownership,
    Scope,
)
from apm_cli.adopt.provenance import ImportSources, hash_source, source_identity
from apm_cli.utils.content_hash import compute_file_hash

from .conftest import write

pytestmark = pytest.mark.component


def _finding(root: Path, tool: str = "claude") -> Finding:
    """Make distinct sources that compete for the same flattened destination."""
    display = f".{tool}/rules/style.md"
    return Finding(
        id="same-abbreviated-display-id",
        tool=tool,
        scope=Scope.PROJECT,
        kind=HarnessKind.RULE,
        display_path=display,
        importability=Importability.CONVERTIBLE,
        ownership=Ownership.HOST_OWNED,
        converter_id="claude_rules->instruction",
        abs_path=write(root / display, f"Use {tool} conventions.\n"),
    )


def _report(findings: tuple[Finding, ...]) -> AdoptionReport:
    """Construct the planner input without invoking scanners or a CLI."""
    return AdoptionReport(
        project_root_display=".",
        scopes=(Scope.PROJECT,),
        detected_tools=tuple(finding.tool for finding in findings),
        findings=findings,
        errors=(),
        proposed_targets=(),
        proposed_mcp=(),
        apm_yml_exists=False,
    )


def _record(sources: ImportSources, finding: Finding, rel: str, *, primary: str = "") -> None:
    """Record real output bytes through the public owner API."""
    sources.record(
        rel,
        source=finding.display_path,
        scope=finding.scope.value,
        converter=finding.converter_id or "",
        source_hash=hash_source(finding.abs_path, root=sources.root) or "",
        dest_abs=sources.path.parent / rel,
        identity=source_identity(finding),
        primary=primary,
    )


@pytest.mark.parametrize("budget", ["file", "tree-file", "tree-total", "tree-entries"])
def test_hash_source_rejects_budget_before_any_content_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, budget: str
) -> None:
    """A valid sibling must not be read before an oversized tree is rejected."""
    tree = tmp_path / "skill"
    write(tree / "SKILL.md", "valid")
    write(tree / ".hidden", "x" * (9 if budget in ("file", "tree-file") else 5))
    if budget == "tree-total":
        monkeypatch.setattr(provenance, "_TREE_LIMIT", 8)
    if budget == "tree-entries":
        (tree / "empty").mkdir()
        monkeypatch.setattr(provenance, "_ENTRY_LIMIT", 3)
    reads: list[Path] = []

    def forbidden_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        reads.append(path)
        raise AssertionError("content read before the entire tree passed admission")

    monkeypatch.setattr(Path, "open", forbidden_open)
    with pytest.raises(ValueError, match="limit"):
        hash_source(tree / ".hidden" if budget == "file" else tree, root=tmp_path, file_limit=8)
    assert reads == []


@pytest.mark.parametrize(
    "change", ["hidden-bytes", "hidden-file", "empty-directory", "rename", "file-type", "exec-bit"]
)
def test_full_fingerprint_detects_hidden_empty_and_metadata_edits(
    tmp_path: Path, change: str
) -> None:
    """Local-edit witnesses include names, entry types, hidden bytes and empty dirs."""
    if change == "exec-bit" and os.name == "nt":
        pytest.skip("Windows has no portable executable-bit contract")
    tree = tmp_path / "skill"
    write(tree / "SKILL.md", "# Skill\n")
    hidden = write(tree / ".config", "first")
    before = hash_source(tree, root=tmp_path)
    if change == "hidden-bytes":
        hidden.write_text("other", encoding="utf-8")
    elif change == "hidden-file":
        write(tree / ".empty", "")
    elif change == "empty-directory":
        (tree / ".empty").mkdir()
    elif change == "rename":
        hidden.rename(tree / ".renamed")
    elif change == "file-type":
        hidden.unlink()
        hidden.mkdir()
    else:
        hidden.chmod(hidden.stat().st_mode ^ 0o100)
    assert hash_source(tree, root=tmp_path) != before


def test_fingerprint_is_byte_exact_but_ignores_timestamps(tmp_path: Path) -> None:
    """Package LF normalization must not hide edits from importer provenance."""
    path = write(tmp_path / "rule.md", "line\n")
    before = hash_source(path, root=tmp_path)
    os.utime(path, (100, 100))
    assert hash_source(path, root=tmp_path) == before
    path.write_bytes(b"line\r\n")
    assert hash_source(path, root=tmp_path) != before


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tool", "cursor"),
        ("scope", Scope.USER),
        ("kind", HarnessKind.INSTRUCTION),
        ("display_path", ".claude/rules/other.md"),
    ],
)
def test_source_identity_preserves_full_finding_dimensions(
    tmp_path: Path, field: str, value: Any
) -> None:
    """An abbreviated display-ID collision must never become ownership equality."""
    finding = _finding(tmp_path)
    changed = replace(finding, **{field: value})
    assert finding.id == changed.id
    assert source_identity(finding) != source_identity(changed)
    assert json.loads(source_identity(finding)) == [
        "claude",
        "project",
        "rule",
        ".claude/rules/style.md",
    ]


@pytest.mark.parametrize("churn", ["insert", "remove", "reorder"])
def test_source_set_churn_retains_destinations_and_reservations(tmp_path: Path, churn: str) -> None:
    """Planning preserves persisted identity, even when its first source disappeared."""
    register_builtin_converters()
    first, second, new = (_finding(tmp_path, tool) for tool in ("claude", "cursor", "copilot"))
    apm_dir = tmp_path / ".apm"
    sources = ImportSources.load(apm_dir, root=tmp_path)
    destinations = (
        "instructions/style.instructions.md",
        "instructions/style-cursor.instructions.md",
    )
    for finding, rel in zip((first, second), destinations, strict=True):
        write(apm_dir / rel, f"Converted from {finding.tool}\n")
        _record(sources, finding, rel)
    sources.save()
    sources = ImportSources.load(apm_dir, root=tmp_path)
    findings = {
        "insert": (new, first, second),
        "remove": (new, second),
        "reorder": (second, first),
    }[churn]
    plan = plan_write(_report(findings), apm_dir, sources, NameAllocator(apm_dir))
    by_tool = {item.finding.tool: item for item in plan.items}
    assert all(item.error is None for item in plan.items)
    assert by_tool["cursor"].dest_rel == destinations[1]
    assert by_tool["cursor"].decision == "unchanged"
    if first in findings:
        assert by_tool["claude"].dest_rel == destinations[0]
        assert by_tool["claude"].decision == "unchanged"
    if new in findings:
        assert by_tool["copilot"].dest_rel not in destinations
        assert by_tool["copilot"].decision == "write"
    assert set(sources.entries) == set(destinations)


def test_missing_owned_output_does_not_release_destination(tmp_path: Path) -> None:
    """Deleting imported output is a local edit, not permission to allocate again."""
    register_builtin_converters()
    finding = _finding(tmp_path)
    apm_dir = tmp_path / ".apm"
    rel = "instructions/style.instructions.md"
    target = write(apm_dir / rel, "Converted\n")
    sources = ImportSources.load(apm_dir, root=tmp_path)
    _record(sources, finding, rel)
    target.unlink()
    plan = plan_write(_report((finding,)), apm_dir, sources, NameAllocator(apm_dir))
    assert [(item.dest_rel, item.decision) for item in plan.items] == [(rel, "locally-modified")]


def test_auxiliary_outputs_roundtrip_identity_and_local_edits(tmp_path: Path) -> None:
    """All output witnesses remain bound to the same primary across save/load."""
    finding = _finding(tmp_path)
    apm_dir = tmp_path / ".apm"
    primary = "hooks/claude-native.json"
    auxiliary = "hooks/claude-native"
    write(apm_dir / primary, "{}\n")
    script = write(apm_dir / auxiliary / ".script.sh", "echo one\n")
    sources = ImportSources.load(apm_dir, root=tmp_path)
    _record(sources, finding, primary)
    _record(sources, finding, auxiliary, primary=primary)
    sources.save()
    sources = ImportSources.load(apm_dir, root=tmp_path)
    assert sources.destination(finding, (finding,)) == primary
    assert set(sources.outputs(primary)) == {primary, auxiliary}
    record = sources.entries[auxiliary]
    assert record.primary == primary
    assert record.identity == source_identity(finding)
    assert record.output_sha256 == hash_source(apm_dir / auxiliary, root=tmp_path)
    assert sources.decide(auxiliary, apm_dir / auxiliary, record.source_sha256) == "unchanged"
    script.write_text("echo two\n", encoding="utf-8")
    assert (
        sources.decide(auxiliary, apm_dir / auxiliary, record.source_sha256) == "locally-modified"
    )


def test_recorded_source_identity_rejects_takeover(tmp_path: Path) -> None:
    """Matching bytes and display IDs cannot authorize a different source."""
    finding = _finding(tmp_path)
    impostor = replace(finding, tool="cursor")
    rel = "instructions/style.instructions.md"
    apm_dir = tmp_path / ".apm"
    target = write(apm_dir / rel, "same bytes\n")
    sources = ImportSources.load(apm_dir, root=tmp_path)
    _record(sources, finding, rel)
    assert sources.destination(impostor, (impostor,)) is None
    assert (
        sources.decide(
            rel, target, sources.entries[rel].source_sha256, identity=source_identity(impostor)
        )
        == "collision"
    )


@pytest.mark.parametrize("ambiguous", [False, True])
def test_legacy_attribution_requires_unambiguous_source(tmp_path: Path, ambiguous: bool) -> None:
    """v1 records carry no trustworthy identity; ambiguous attribution stays reserved."""
    finding = _finding(tmp_path)
    other = replace(finding, tool="cursor")
    rel = "instructions/style.instructions.md"
    apm_dir = tmp_path / ".apm"
    target = write(apm_dir / rel, "legacy output\n")
    record = {
        "source": finding.display_path,
        "scope": "project",
        "converter": "claude_rules->instruction",
        "source_sha256": "old-source",
        "output_sha256": compute_file_hash(target),
        "identity": source_identity(other),
        "primary": "untrusted-v1-primary",
    }
    write(apm_dir / provenance.SIDECAR_NAME, json.dumps({"version": 1, "entries": {rel: record}}))
    sources = ImportSources.load(apm_dir, root=tmp_path)
    assert sources.entries[rel].identity == sources.entries[rel].primary == ""
    assert sources.destination(finding, (finding, other) if ambiguous else (finding,)) == (
        None if ambiguous else rel
    )
    allocator = NameAllocator(apm_dir)
    allocator.reserve(sources.entries)
    allocated, _ = allocator.allocate("instructions", "style", ".instructions.md", "claude")
    assert allocated != rel
    assert sources.decide(rel, target, "changed-source") == "refresh"
    target.write_text("local edit\n", encoding="utf-8")
    assert sources.decide(rel, target, "changed-source") == "locally-modified"


@pytest.mark.parametrize("witness", ["", "sha256:legacy-tree", "unsupported:hash"])
def test_legacy_directory_witness_cannot_authorize_refresh(tmp_path: Path, witness: str) -> None:
    """Normalized or missing legacy tree evidence never proves a complete local snapshot."""
    finding = _finding(tmp_path)
    apm_dir = tmp_path / ".apm"
    rel = "skills/example"
    write(apm_dir / rel / "SKILL.md", "# Skill\n")
    sources = ImportSources.load(apm_dir, root=tmp_path)
    _record(sources, finding, rel)
    sources.entries[rel].output_sha256 = witness
    assert sources.decide(rel, apm_dir / rel, "changed-source") == "locally-modified"
