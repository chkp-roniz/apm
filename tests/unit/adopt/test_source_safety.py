"""Source admission precedes filesystem inspection, not merely conversion."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from apm_cli.adopt import scan_targets
from apm_cli.adopt.model import HarnessKind, Scope
from apm_cli.adopt.redact import Redactor
from apm_cli.adopt.registry import ScanContext, ScanLimits, ScanRule, findings_for_rule
from apm_cli.adopt.safety import approved_path
from apm_cli.adopt.scanners.hooks import HooksScanner, _load_json, script_findings
from apm_cli.adopt.scanners.mcp import McpScanner
from apm_cli.adopt.scanners.plugins import PluginsScanner
from apm_cli.adopt.scanners.profile_files import unrecognised_files
from apm_cli.adopt.scanners.root_context import RootContextScanner
from apm_cli.integration.hook_integrator import _APM_HOOKS_SIDECAR
from apm_cli.utils.path_security import PathTraversalError

from .conftest import write

pytestmark = pytest.mark.component


def _context(root: Path, scope: Scope = Scope.PROJECT, **limits: int) -> ScanContext:
    """Use the real registry profiles and existing pytest temporary directory."""
    return ScanContext(
        root=root,
        scope=scope,
        targets=scan_targets(scope),
        redactor=Redactor(root, home=root if scope is Scope.USER else None),
        limits=ScanLimits(**limits),
    )


def _forbid_io(monkeypatch: pytest.MonkeyPatch, *blocked: Path) -> None:
    """Fail on inspection/read/enumeration; canonical symlink resolution is allowed."""
    resolving = 0
    resolve = Path.resolve

    def resolving_path(path: Path, *args: Any, **kwargs: Any) -> Path:
        nonlocal resolving
        resolving += 1
        try:
            return resolve(path, *args, **kwargs)
        finally:
            resolving -= 1

    monkeypatch.setattr(Path, "resolve", resolving_path)

    def guarded(original: Callable[..., Any]) -> Callable[..., Any]:
        def call(path: Path, *args: Any, **kwargs: Any) -> Any:
            # Python 3.12's resolve also stats its result to detect link loops.
            # Only resolution metadata is exempt, not scanner stat/type probes.
            if not resolving and kwargs.get("follow_symlinks") is not False:
                assert not any(path.is_relative_to(base) for base in blocked), (
                    f"unadmitted {original.__name__}: {path.name}"
                )
            return original(path, *args, **kwargs)

        return call

    for name in ("is_dir", "is_file", "stat", "open", "iterdir"):
        monkeypatch.setattr(Path, name, guarded(getattr(Path, name)))
    scandir = os.scandir

    def guarded_scandir(path: Any) -> Any:
        if not isinstance(path, int):
            assert not any(Path(path).is_relative_to(base) for base in blocked), (
                "unadmitted scandir"
            )
        return scandir(path)

    monkeypatch.setattr(os, "scandir", guarded_scandir)


@pytest.mark.parametrize("present", [False, True], ids=["absent", "present"])
def test_external_user_config_is_inventory_only_without_any_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, present: bool
) -> None:
    from apm_cli.factory import ClientFactory

    root = tmp_path / "home"
    root.mkdir()
    external = tmp_path / "external"
    monkeypatch.setenv("HOME", str(root))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: root))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(external))
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: ["intellij"])
    adapter = ClientFactory.create_client("intellij", project_root=root, user_scope=True)
    path = Path(adapter.get_config_path())
    assert path.is_relative_to(external)
    if present:
        write(path, '{"mcpServers":{"private":{"command":"must-not-read"}}}')
    ctx = _context(root, Scope.USER)
    with monkeypatch.context() as patch:
        _forbid_io(patch, external)
        found = list(McpScanner().scan(ctx))
    assert ctx.errors == []
    assert len(found) == 1 and found[0].kind is HarnessKind.UNKNOWN
    assert found[0].abs_path is None and found[0].payload is None
    assert "not inspected" in " ".join(found[0].notes)


@pytest.mark.parametrize("scope", [Scope.PROJECT, Scope.USER])
@pytest.mark.parametrize("scanner", ["root", "rules", "unknown", "hooks", "plugins"])
def test_escaped_source_ancestor_is_refused_before_inspection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scope: Scope, scanner: str
) -> None:
    root = tmp_path / "scope"
    root.mkdir()
    outside = tmp_path / "outside"
    write(outside / "CLAUDE.md", "# Private\n")
    write(outside / "rules/private.md", "private\n")
    write(outside / "settings.json", '{"hooks":{"PreToolUse":[{"command":"echo inert"}]}}')
    write(outside / "plugin.json", "{}")
    alias = root / (".claude-plugin" if scanner == "plugins" else ".claude")
    alias.symlink_to(outside, target_is_directory=True)
    ctx = _context(root, scope)
    rule = ScanRule("claude", HarnessKind.RULE, ".claude/rules/*.md", recursive=True)

    with monkeypatch.context() as patch:
        _forbid_io(patch, alias, outside)
        if scanner == "root":
            found = list(RootContextScanner().scan(ctx))
        elif scanner == "rules":
            found = list(findings_for_rule(ctx, rule))
        elif scanner == "unknown":
            found = list(unrecognised_files(ctx, [rule], set()))
        elif scanner == "hooks":
            found = list(HooksScanner().scan(ctx))
        else:
            # Plugin layouts are intentionally project-only.
            ctx.scope = Scope.PROJECT
            found = list(PluginsScanner().scan(ctx))
    assert not found
    assert ctx.errors
    assert any("scope" in error.reason or "scan root" in error.reason for error in ctx.errors)


@pytest.mark.parametrize("recursive", [False, True])
def test_wildcard_ancestors_are_admitted_before_glob_descent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recursive: bool
) -> None:
    root = tmp_path / "scope"
    write(root / ".agents/skills/good/SKILL.md", "# Good\n")
    outside = tmp_path / "outside"
    write(outside / "SKILL.md", "# Private\n")
    alias = root / ".agents/skills/escape"
    alias.symlink_to(outside, target_is_directory=True)
    ctx = _context(root)
    rule = ScanRule(
        "shared",
        HarnessKind.SKILL,
        ".agents/skills/*/SKILL.md",
        is_dir_rule=True,
        recursive=recursive,
    )
    with monkeypatch.context() as patch:
        _forbid_io(patch, alias, outside)
        found = list(findings_for_rule(ctx, rule))
    assert [finding.display_path for finding in found] == [".agents/skills/good"]
    assert ctx.errors


@pytest.mark.parametrize("leaf", [False, True])
def test_escaped_hook_sidecar_prevents_ownership_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, leaf: bool
) -> None:
    root = tmp_path / "scope"
    config = write(
        root / ".claude/settings.json", '{"hooks":{"PreToolUse":[{"command":"echo x"}]}}'
    )
    outside = write(tmp_path / "outside/ownership.json", '{"private":"do not read"}')
    sidecar = config.parent / _APM_HOOKS_SIDECAR
    if leaf:
        sidecar.symlink_to(outside)
    else:
        # The sidecar shares a redirected config parent in this variant.
        config.unlink()
        config.parent.rmdir()
        write(outside.parent / "settings.json", '{"hooks":{"PreToolUse":[{"command":"echo x"}]}}')
        config.parent.symlink_to(outside.parent, target_is_directory=True)
    ctx = _context(root)
    blocked = sidecar if leaf else config.parent
    with monkeypatch.context() as patch:
        _forbid_io(patch, blocked, outside.parent)
        found = list(HooksScanner().scan(ctx))
    assert not found
    assert ctx.errors


@pytest.mark.parametrize("relative", [".claude/settings.json", ".claude/" + _APM_HOOKS_SIDECAR])
def test_json_loader_admits_path_without_relying_on_its_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    root = tmp_path / "scope"
    root.mkdir()
    outside = write(tmp_path / "outside/config.json", "{}")
    (root / ".claude").symlink_to(outside.parent, target_is_directory=True)
    candidate = root / relative
    ctx = _context(root)
    with monkeypatch.context() as patch:
        _forbid_io(patch, root / ".claude", outside.parent)
        assert _load_json(candidate, ctx) is None
    assert ctx.errors


@pytest.mark.parametrize("scanner", ["rule", "json", "unknown", "plugin", "script"])
def test_oversize_source_is_refused_before_any_probe_or_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str
) -> None:
    source = write(tmp_path / "hooks.json", json.dumps({"hooks": "x" * 100}))
    ctx = _context(tmp_path, max_file_bytes=8)
    rule = ScanRule("root", HarnessKind.HOOK, "*.json")

    def no_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        pytest.fail("oversize source was opened")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", no_open)
        if scanner == "rule":
            found = list(findings_for_rule(ctx, rule))
        elif scanner == "json":
            found = _load_json(source, ctx)
        elif scanner == "unknown":
            found = list(unrecognised_files(ctx, [rule], set()))
        elif scanner == "plugin":
            found = list(PluginsScanner().scan(ctx))
        else:
            found = list(
                script_findings(
                    ctx,
                    "claude",
                    {
                        "hooks": {
                            "PreToolUse": [{"command": "./hooks.json"}],
                        }
                    },
                    "settings.json",
                    set(),
                )
            )
    assert not found
    assert any("oversize" in error.reason or "size limit" in error.reason for error in ctx.errors)


@pytest.mark.parametrize("name", ["agents", "hooks.json"])
def test_plugin_layout_preflight_precedes_canonical_presence_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    root = tmp_path / "scope"
    root.mkdir()
    outside = write(tmp_path / "outside/hooks.json", "{}")
    target = outside.parent if name == "agents" else outside
    alias = root / name
    alias.symlink_to(target, target_is_directory=name == "agents")
    ctx = _context(root)
    with monkeypatch.context() as patch:
        _forbid_io(patch, alias, outside.parent)
        found = list(PluginsScanner().scan(ctx))
    assert not found
    assert ctx.errors


def test_selected_root_and_contained_directory_aliases_remain_supported(tmp_path: Path) -> None:
    root = tmp_path / "scope"
    write(root / "shared/rules/style.md", "# Style\n")
    (root / ".claude").symlink_to(root / "shared", target_is_directory=True)
    selected = tmp_path / "selected"
    selected.symlink_to(root, target_is_directory=True)
    ctx = _context(selected)
    rule = ScanRule("claude", HarnessKind.RULE, ".claude/rules/*.md", recursive=True)
    found = list(findings_for_rule(ctx, rule))
    assert ctx.root == root.resolve()
    assert [finding.display_path for finding in found] == [".claude/rules/style.md"]
    assert not ctx.errors


def test_contained_hook_settings_alias_retains_host_entries(tmp_path: Path) -> None:
    source = write(
        tmp_path / "shared/settings.json", '{"hooks":{"PreToolUse":[{"command":"echo x"}]}}'
    )
    (tmp_path / ".claude").symlink_to(source.parent, target_is_directory=True)
    ctx = _context(tmp_path)
    found = list(HooksScanner().scan(ctx))
    assert any(finding.tool == "claude" and finding.payload["hooks"] for finding in found)
    assert not ctx.errors


def test_recursive_rule_bounds_enumeration_not_just_matching_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for index in range(20):
        write(tmp_path / f"rules/branch-{index}/ignored.txt", "inert\n")
    ctx = _context(tmp_path, max_entries_per_rule=4)
    rule = ScanRule("test", HarnessKind.RULE, "rules/*.md", recursive=True)
    count = 0
    scandir = os.scandir

    class CountedEntries:
        def __init__(self, path: Path) -> None:
            self.entries = scandir(path)

        def __enter__(self) -> CountedEntries:
            return self

        def __exit__(self, *args: Any) -> None:
            self.entries.close()

        def __iter__(self) -> CountedEntries:
            return self

        def __next__(self) -> os.DirEntry:
            nonlocal count
            item = next(self.entries)
            count += 1
            return item

    with monkeypatch.context() as patch:
        patch.setattr(os, "scandir", CountedEntries)
        assert not list(findings_for_rule(ctx, rule))
    assert count <= 5
    assert any("truncated" in error.reason for error in ctx.errors)


@pytest.mark.parametrize("mutable", [False, True])
def test_shared_helper_rejects_escaped_ancestor_and_redacts_target(
    tmp_path: Path, mutable: bool
) -> None:
    root = tmp_path / "scope"
    root.mkdir()
    outside = write(tmp_path / "private/place/source.md", "# Private\n")
    (root / "alias").symlink_to(outside.parent, target_is_directory=True)
    with pytest.raises(PathTraversalError, match="approved scope") as caught:
        approved_path(root / "alias/source.md", root, mutable=mutable)
    assert "private" not in str(caught.value)
    assert outside.read_text(encoding="utf-8") == "# Private\n"


@pytest.mark.parametrize("exists", [False, True])
def test_shared_helper_refuses_mutable_leaf_but_allows_contained_ancestors(
    tmp_path: Path, exists: bool
) -> None:
    target = tmp_path / "shared/target.md"
    target.parent.mkdir()
    if exists:
        write(target, "# Existing\n")
    (tmp_path / "alias").symlink_to(target.parent, target_is_directory=True)
    assert approved_path(tmp_path / "alias/target.md", tmp_path, mutable=True) == target
    leaf = tmp_path / "leaf.md"
    leaf.symlink_to(target)
    assert approved_path(leaf, tmp_path) == target
    with pytest.raises(PathTraversalError, match="symlink leaf"):
        approved_path(leaf, tmp_path, mutable=True)


def test_resolution_failure_is_explicit_and_does_not_expose_os_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apm_cli.adopt import safety

    def unreadable(path: Path, root: Path) -> Path:
        raise OSError("private filesystem details")

    monkeypatch.setattr(safety, "ensure_path_within", unreadable)
    with pytest.raises(PathTraversalError, match="cannot verify") as caught:
        approved_path(tmp_path / "source", tmp_path)
    assert "private" not in str(caught.value)


def test_symlink_loop_is_reported_instead_of_aborting_scan(tmp_path: Path) -> None:
    directory = tmp_path / ".claude"
    directory.symlink_to(directory, target_is_directory=True)
    ctx = _context(tmp_path)
    assert not list(RootContextScanner().scan(ctx))
    assert any("cannot verify" in error.reason for error in ctx.errors)


def test_depth_limit_stops_nonmatching_recursive_descent(tmp_path: Path) -> None:
    write(tmp_path / "rules/a/b/c/source.md", "# Too deep\n")
    ctx = _context(tmp_path, max_depth=1)
    rule = ScanRule("test", HarnessKind.RULE, "rules/*.md", recursive=True)
    assert not list(findings_for_rule(ctx, rule))
    assert any("depth limit" in error.reason for error in ctx.errors)


@pytest.mark.parametrize("kind", ["null", "directory", "oversize", "contained-symlink"])
def test_unverifiable_sidecar_never_becomes_missing_ownership_evidence(
    tmp_path: Path, kind: str
) -> None:
    config = write(
        tmp_path / ".claude/settings.json", '{"hooks":{"PreToolUse":[{"command":"echo x"}]}}'
    )
    sidecar = config.parent / _APM_HOOKS_SIDECAR
    if kind == "directory":
        sidecar.mkdir()
    elif kind == "contained-symlink":
        sidecar.symlink_to(write(tmp_path / "ownership.json", "{}"))
    else:
        write(sidecar, "null" if kind == "null" else json.dumps({"padding": "x" * 256}))
    ctx = _context(tmp_path, max_file_bytes=128)
    assert not list(HooksScanner().scan(ctx))
    assert ctx.errors
