"""Regression tests for adopt materialize helpers (review follow-ups)."""

from __future__ import annotations

from pathlib import Path

import pytest

from apm_cli.adopt.converters.hooks import _unique_script_name, event_portability
from apm_cli.adopt.materialize import _dedupe_mcp

pytestmark = pytest.mark.component


def test_event_portability_lists_each_target_once():
    native, passthrough = event_portability("PreToolUse")
    assert native
    assert not (set(native) & set(passthrough))
    assert len(native) + len(passthrough) == len(set(native) | set(passthrough))


def test_dedupe_mcp_prefers_target_order():
    fragments = [
        ("claude", {"dependencies": {"mcp": [{"name": "shared", "command": "claude-cmd"}]}}),
        ("cursor", {"dependencies": {"mcp": [{"name": "shared", "command": "cursor-cmd"}]}}),
    ]
    entries, notes = _dedupe_mcp(fragments, ("cursor", "claude"))
    assert entries[0]["command"] == "cursor-cmd"
    assert not notes


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
