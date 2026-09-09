"""Scanner for hook configuration files and the scripts they reference.

Merged-config targets (Claude, Cursor, Codex, Gemini, Windsurf, Antigravity)
keep every hook in one JSON document that users also edit by hand. APM marks
the entries it wrote with ``_apm_source`` (kept in a sidecar for schema-strict
targets), so ownership is decided *per entry*: the finding carries only the
host-authored slice and notes how many APM entries were skipped.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

from apm_cli.hook_contract import walk_hook_commands
from apm_cli.integration.hook_command_paths import (
    UnsupportedHookCommand,
    project_script_references,
)
from apm_cli.integration.hook_integrator import _APM_HOOKS_SIDECAR, _MERGE_HOOK_TARGETS
from apm_cli.integration.hook_ownership import reinject_apm_source_from_sidecar
from apm_cli.integration.targets import KNOWN_TARGETS

from ..model import HarnessKind, Ownership, RawFinding, Risk, Scope
from ..registry import ScanContext, probe_text

_EXECUTES = frozenset({Risk.EXECUTES_CODE})


def _load_json(path: Path, ctx: ScanContext, *, mutable: bool = False) -> Any | None:
    """Load only admitted, regular, bounded JSON; missing files are quiet."""
    if ctx.file_size(path, mutable=mutable) is None:
        return None
    if probe_text(path) is None:
        ctx.error(path, "binary or unreadable")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8").removeprefix("\ufeff"))
    except (OSError, ValueError) as exc:
        ctx.error(path, f"invalid JSON: {type(exc).__name__}")
        return None


def split_hook_entries(hooks: dict[str, Any]) -> tuple[dict[str, list], int]:
    """Return (host-authored event map, count of APM-marked entries dropped)."""
    host: dict[str, list] = {}
    apm_count = 0
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        kept: list = []
        for entry in entries:
            if isinstance(entry, dict) and "_apm_source" in entry:
                apm_count += 1
                continue
            kept.append(entry)
        if kept:
            host[event] = kept
    return host, apm_count


def script_findings(
    ctx: ScanContext,
    tool: str,
    hooks_doc: dict[str, Any],
    source_display: str,
    seen: set[str],
    *,
    notes: list[str] | None = None,
) -> Iterable[RawFinding]:
    """Inventory every admitted lexical reference without evaluating commands."""
    for declaration in walk_hook_commands(hooks_doc):
        try:
            references = project_script_references(declaration.command)
        except UnsupportedHookCommand:
            # Do not echo command text (or a future parser's exception text).
            # Other supported declarations can still contribute their inventory.
            note = (
                "script inventory is reference-only for unsupported hook syntax; "
                "use literal project-relative script paths to inventory it"
            )
            if notes is not None and note not in notes:
                notes.append(note)
            continue
        for reference in references:
            target = ctx.root / reference.path
            resolved = ctx.approve(target)
            if resolved is None:
                continue
            size = ctx.file_size(target)
            if size is None:
                continue
            key = resolved.as_posix()
            if key in seen:
                continue
            seen.add(key)
            yield RawFinding(
                tool=tool,
                scope=ctx.scope,
                kind=HarnessKind.HOOK_SCRIPT,
                display_path=ctx.display(resolved),
                abs_path=resolved,
                size_bytes=size,
                risk=_EXECUTES,
                notes=(f"referenced by {source_display}",),
                evidence=(f"hook-command:{PurePosixPath(source_display).name}",),
            )


class HooksScanner:
    """Read merged hook configs and enumerate referenced scripts."""

    name = "hooks"

    def scan(self, ctx: ScanContext) -> Iterable[RawFinding]:
        seen_scripts: set[str] = set()
        for tool, config in _MERGE_HOOK_TARGETS.items():
            profile = KNOWN_TARGETS.get(tool)
            if profile is None:
                continue
            scoped = profile.for_scope(user_scope=ctx.scope is Scope.USER)
            if scoped is None:
                continue
            config_path = ctx.root / scoped.root_dir / config.config_filename
            data = _load_json(config_path, ctx)
            if not isinstance(data, dict):
                continue
            display = ctx.display(config_path)
            if config.event_container_key == "hooks":
                containers = {"hooks": data.get("hooks")}
            else:
                containers = {
                    name: value
                    for name, value in data.items()
                    if name != config.event_container_key and isinstance(value, dict)
                }
            sidecar_path = config_path.parent / _APM_HOOKS_SIDECAR
            errors_before = len(ctx.errors)
            sidecar = _load_json(sidecar_path, ctx, mutable=True)
            if len(ctx.errors) != errors_before:
                # Missing ownership evidence must not turn managed entries
                # into supposedly host-owned sources.
                continue
            if not isinstance(sidecar, dict):
                try:
                    # _load_json already admitted this metadata endpoint.
                    # JSON null and directories are not absent sidecars.
                    if sidecar_path.exists():
                        ctx.error(sidecar_path, "invalid hook ownership sidecar")
                        continue
                except OSError:
                    ctx.error(sidecar_path, "unreadable hook ownership sidecar")
                    continue
            host_events: dict[str, list] = {}
            apm_total = 0
            for container_name, hooks in containers.items():
                if not isinstance(hooks, dict) or not hooks:
                    continue
                working = copy.deepcopy(hooks)
                if isinstance(sidecar, dict) and container_name == "hooks":
                    reinject_apm_source_from_sidecar(working, sidecar)
                host, apm_count = split_hook_entries(working)
                apm_total += apm_count
                for event, entries in host.items():
                    key = event if container_name == "hooks" else f"{container_name}:{event}"
                    host_events.setdefault(key, []).extend(entries)
            if not host_events and apm_total == 0:
                continue
            host_count = sum(len(v) for v in host_events.values())
            notes = [f"host entries: {host_count}; apm-owned entries skipped: {apm_total}"]
            ownership = Ownership.HOST_OWNED if host_events else Ownership.APM_OWNED
            scripts = list(
                script_findings(
                    ctx, tool, {"hooks": host_events}, display, seen_scripts, notes=notes
                )
            )
            yield RawFinding(
                tool=tool,
                scope=ctx.scope,
                kind=HarnessKind.HOOK,
                display_path=display,
                abs_path=config_path,
                size_bytes=ctx.file_size(config_path),
                format_id=f"{tool}_hooks",
                primitive="hooks",
                risk=_EXECUTES,
                notes=tuple(notes),
                evidence=("hooks:per-entry-ownership",),
                ownership=ownership,
                payload={"tool": tool, "hooks": host_events},
            )
            yield from scripts
