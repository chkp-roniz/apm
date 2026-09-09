"""Scanner for plugin-shaped layouts that APM installs rather than converts."""

from __future__ import annotations

from collections.abc import Iterable

from apm_cli.bundle.plugin_layout import PLUGIN_ROOT_DIRS, find_plugin_root_sources

from ..model import HarnessKind, RawFinding, Scope
from ..registry import ScanContext


class PluginsScanner:
    """Report plugin-native root layouts and Claude plugin manifests."""

    name = "plugins"

    def scan(self, ctx: ScanContext) -> Iterable[RawFinding]:
        if ctx.scope is not Scope.PROJECT:
            return
        manifest = ctx.root / ".claude-plugin" / "plugin.json"
        size = ctx.file_size(manifest)
        if size is not None:
            yield RawFinding(
                tool="claude",
                scope=ctx.scope,
                kind=HarnessKind.PLUGIN,
                display_path=ctx.display(manifest),
                abs_path=manifest,
                size_bytes=size,
                format_id="claude_plugin",
                notes=("project is a Claude plugin; install it with `apm install ./`",),
                evidence=("plugin:manifest",),
            )
        # The canonical layout probe performs stat itself. Admit its entire
        # fixed candidate set first; never call it with an unsafe candidate.
        admitted = [
            ctx.approve(ctx.root / name) is not None for name in (*PLUGIN_ROOT_DIRS, "hooks.json")
        ]
        if not all(admitted):
            return
        try:
            sources = find_plugin_root_sources(ctx.root)
        except OSError:
            ctx.error(ctx.root, "unreadable plugin layout")
            return
        for source in sources:
            path = ctx.root / source
            size = ctx.file_size(path) if source not in PLUGIN_ROOT_DIRS else None
            if source not in PLUGIN_ROOT_DIRS and size is None:
                continue
            yield RawFinding(
                tool="root",
                scope=ctx.scope,
                kind=HarnessKind.PLUGIN,
                display_path=ctx.display(path),
                abs_path=path,
                size_bytes=size,
                format_id="plugin_root_layout",
                notes=("plugin-native root layout; `apm pack` already includes it",),
                evidence=("plugin:root-source",),
            )
