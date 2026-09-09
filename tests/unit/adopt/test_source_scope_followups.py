"""Root-context activation uses semantic scope, not redacted display notation."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from apm_cli.adopt.classify import classify
from apm_cli.adopt.converters import ConvertContext
from apm_cli.adopt.converters.base import parse_markdown
from apm_cli.adopt.converters.root_context import RootContextConverter
from apm_cli.adopt.model import HarnessKind, Ownership, RawFinding, Scope
from apm_cli.adopt.redact import Redactor
from apm_cli.adopt.registry import ScanContext
from apm_cli.adopt.scanners.root_context import RootContextScanner

from .conftest import write

pytestmark = pytest.mark.component


@pytest.mark.parametrize(
    "relative",
    [
        ".claude/CLAUDE.md",
        ".codex/AGENTS.md",
        ".gemini/GEMINI.md",
        ".config/opencode/AGENTS.md",
        ".cursor/AGENTS.md",
        ".copilot/AGENTS.md",
    ],
)
def test_native_user_root_context_is_all_file_scope(tmp_path: Path, relative: str) -> None:
    """Exercise native scanner display paths, not a hand-normalized test finding."""
    home = tmp_path / "home"
    source = write(home / relative, "# User guidance\nKeep useful notes.\n")
    original = source.read_bytes()
    redactor = Redactor(tmp_path / "project", home=home)
    scan = ScanContext(root=home, scope=Scope.USER, targets=(), redactor=redactor)
    raw = next(f for f in RootContextScanner().scan(scan) if f.abs_path == source)
    assert raw.display_path == f"~/{relative}"
    finding = classify(raw, Ownership.HOST_OWNED, ())
    ctx = ConvertContext(project_root=home, scope=Scope.USER, redactor=redactor)
    destination = tmp_path / "output/root.instructions.md"

    result = RootContextConverter().convert(finding, destination, ctx=ctx)

    metadata, body = parse_markdown(destination.read_text(encoding="utf-8"))
    assert metadata["applyTo"] == "**"
    assert "Keep useful notes." in body
    assert source.read_bytes() == original
    assert [(c.action, c.path) for c in result.changes if c.path == "frontmatter.applyTo"] == [
        ("defaulted", "frontmatter.applyTo")
    ]

    # Relabeling a USER finding for presentation cannot change activation.
    relabeled = replace(finding, display_path="user-settings/context/CLAUDE.md")
    RootContextConverter().convert(relabeled, destination, ctx=ctx)
    assert parse_markdown(destination.read_text(encoding="utf-8"))[0]["applyTo"] == "**"


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("CLAUDE.md", "**"),
        (".claude/CLAUDE.md", "**"),
        ("AGENTS.md", "**"),
        ("GEMINI.md", "**"),
        (".cursorrules", "**"),
        ("frontend/CLAUDE.md", "frontend/**"),
        ("packages/widget/AGENTS.md", "packages/widget/**"),
    ],
)
def test_project_root_and_nested_context_scopes_are_preserved(
    tmp_path: Path, relative: str, expected: str
) -> None:
    source = write(tmp_path / relative, "# Project guidance\nKeep useful notes.\n")
    original = source.read_bytes()
    raw = RawFinding(
        tool="claude",
        scope=Scope.PROJECT,
        kind=HarnessKind.ROOT_CONTEXT,
        display_path=relative,
        abs_path=source,
        format_id="root_context",
    )
    finding = classify(raw, Ownership.HOST_OWNED, ())
    ctx = ConvertContext(project_root=tmp_path, scope=Scope.PROJECT, redactor=Redactor(tmp_path))
    destination = tmp_path / "output/root.instructions.md"

    RootContextConverter().convert(finding, destination, ctx=ctx)

    assert parse_markdown(destination.read_text(encoding="utf-8"))[0]["applyTo"] == expected
    assert source.read_bytes() == original
