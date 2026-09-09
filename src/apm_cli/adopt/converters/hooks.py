"""Native hook configs -> ``.apm/hooks/<tool>-native.json`` (neutral grammar).

Only host-authored entries reach this converter (the hooks scanner already
dropped ``_apm_source``-marked ones). Scripts are referenced, never executed;
``--include-hook-scripts`` copies in-project scripts next to the hook file.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Callable
from pathlib import Path
from typing import Any

from apm_cli.hook_contract import HookDocument
from apm_cli.integration.hook_integrator import _HOOK_EVENT_MAP
from apm_cli.integration.hook_native_formats import (
    _document_to_entries,
    _from_antigravity_hook_entries,
    _from_claude_hook_entries,
    _from_copilot_hook_file,
    _from_cursor_hook_entries,
    _from_gemini_hook_entries,
    _from_kiro_hook_docs,
    _from_windsurf_hook_entries,
)
from apm_cli.security.gate import SecurityGate
from apm_cli.utils.atomic_io import write_text_lf
from apm_cli.utils.path_security import PathTraversalError, ensure_path_within

from ..model import Finding
from . import ConvertContext, ConvertError, ConvertResult
from .base import read_text, refuse_credentials

CANONICAL_EVENTS: frozenset[str] = frozenset(
    {
        "PreToolUse",
        "PostToolUse",
        "UserPromptSubmit",
        "SessionStart",
        "Stop",
        "PreTaskExecution",
        "PostTaskExecution",
    }
)
_PROJECT_DIR_VARS = re.compile(
    r"""(?:"?\$\{?CLAUDE_PROJECT_DIR\}?"?|\$env:CLAUDE_PROJECT_DIR|\$\{?workspaceFolder\}?)[\\/]"""
)
_SHELL_META_RE = re.compile(r"[;&|`<>]|\$\(|\|\|")
_MERGED_READERS: dict[str, Callable[[list, str], HookDocument]] = {
    "claude": _from_claude_hook_entries,
    "codex": _from_claude_hook_entries,
    "cursor": _from_cursor_hook_entries,
    "windsurf": _from_windsurf_hook_entries,
    "gemini": _from_gemini_hook_entries,
    "antigravity": _from_antigravity_hook_entries,
}
_MAX_SCRIPT_BYTES = 1_048_576


# Targets that consume the canonical (Claude PascalCase) event names unchanged.
_CANONICAL_EVENT_TARGETS: frozenset[str] = frozenset(
    {"claude", "cursor", "codex", "windsurf", "antigravity"}
)


def event_portability(event: str) -> tuple[list[str], list[str]]:
    """Return (targets that render *event* natively, targets that pass it through).

    Each target appears exactly once, in one of the two lists.
    """
    targets = set(_HOOK_EVENT_MAP) | _CANONICAL_EVENT_TARGETS
    native: set[str] = set()
    for target in targets:
        mapping = _HOOK_EVENT_MAP.get(target, {})
        if event in mapping or (target in _CANONICAL_EVENT_TARGETS and event in CANONICAL_EVENTS):
            native.add(target)
    return sorted(native), sorted(targets - native)


def _replace_command_token(command: str, token: str, replacement: str) -> str:
    """Replace one argv token in *command* without reserialising the whole string."""
    pattern = r"(?<!\S)" + re.escape(token) + r"(?!\S)"
    return re.sub(pattern, replacement, command, count=1)


def _rewrite_project_dir_refs(command: str) -> tuple[str, bool]:
    """Rewrite project-dir variables to ``./`` without reserialising shell syntax."""
    new_command, count = _PROJECT_DIR_VARS.subn("./", command)
    return new_command, count > 0


def _rewrite_script_tokens(
    command: str,
    finding: Finding,
    dest_dir: Path,
    ctx: ConvertContext,
    result: ConvertResult,
    event: str,
) -> str:
    """Normalise project-dir variables; optionally copy in-project scripts."""
    new_command, project_changed = _rewrite_project_dir_refs(command)
    if project_changed:
        result.transform(
            f"hooks.{event}.command", "project-dir variable rewritten to a relative path"
        )
    shell_meta = bool(_SHELL_META_RE.search(new_command))
    try:
        argv = shlex.split(new_command, posix=True)
    except ValueError:
        return new_command
    for index, token in enumerate(argv):
        if shell_meta:
            continue
        candidate = ctx.project_root / token
        if ctx.include_hook_scripts and not Path(token).is_absolute() and candidate.is_file():
            try:
                ensure_path_within(
                    candidate.resolve(strict=False), ctx.project_root.resolve(strict=False)
                )
            except PathTraversalError:
                continue
            if candidate.is_symlink() or candidate.stat().st_size > _MAX_SCRIPT_BYTES:
                result.drop(f"hooks.{event}.script", "script skipped: symlink or oversize")
                continue
            text = candidate.read_bytes()
            if b"\x00" not in text:
                script_text = text.decode("utf-8", errors="ignore")
                refuse_credentials(script_text)
                verdict = SecurityGate.scan_text(script_text, candidate.name)
                if verdict.should_block:
                    raise ConvertError("hook script blocked by the security scan")
            scripts_dir = dest_dir / "scripts"
            scripts_dir.mkdir(parents=True, exist_ok=True)
            script_name = _unique_script_name(scripts_dir, candidate, text)
            target = scripts_dir / script_name
            if not target.exists():
                import shutil

                shutil.copy2(candidate, target)
                result.written.append(target)
            new_command = _replace_command_token(new_command, token, f"./scripts/{script_name}")
            result.transform(f"hooks.{event}.command", "script copied into .apm/hooks/scripts/")
        elif not Path(token).is_absolute() and token.startswith("./") and not candidate.exists():
            result.transform(
                f"hooks.{event}.command", "referenced script not found in project", "warning"
            )
        elif Path(token).is_absolute() or token.startswith("~"):
            if index == 0 or token.endswith((".sh", ".py", ".ps1", ".js")):
                result.transform(
                    f"hooks.{event}.command", "machine-local script path is not portable", "warning"
                )
    if shell_meta and ctx.include_hook_scripts:
        result.transform(
            f"hooks.{event}.command",
            "shell operators present; hook script paths not rewritten",
            "warning",
        )
    return new_command


def _unique_script_name(scripts_dir: Path, candidate: Path, content: bytes) -> str:
    """Return a file name under *scripts_dir* that does not shadow a different script.

    Two hooks may reference scripts with the same basename from different
    directories; the second one gets its parent directory folded into the name
    (``hooks-notify.sh``) instead of silently reusing the first copy.
    """
    existing = scripts_dir / candidate.name
    if not existing.exists() or existing.read_bytes() == content:
        return candidate.name
    parent = re.sub(r"[^A-Za-z0-9]+", "-", candidate.parent.name).strip("-") or "script"
    alternative = f"{parent}-{candidate.name}"
    counter = 2
    while (scripts_dir / alternative).exists() and (
        scripts_dir / alternative
    ).read_bytes() != content:
        alternative = f"{parent}-{counter}-{candidate.name}"
        counter += 1
    return alternative


def _load_json(path: Path, limit: int) -> Any:
    try:
        return json.loads(read_text(path, limit))
    except ValueError as exc:
        raise ConvertError(f"invalid JSON: {type(exc).__name__}") from exc


class HooksConverter:
    """Merged hook configs and per-file hook documents -> neutral hook files."""

    id = "hooks->apm_hooks"

    def handles(self, converter_id: str) -> bool:
        return converter_id.endswith("->apm_hooks")

    def convert(self, finding: Finding, dest: Path, *, ctx: ConvertContext) -> ConvertResult:
        result = ConvertResult()
        tool = finding.tool
        documents: dict[str, dict[str, HookDocument]] = {}
        if isinstance(finding.payload, dict) and "hooks" in finding.payload:
            reader = _MERGED_READERS.get(tool, _from_claude_hook_entries)
            for key, entries in finding.payload["hooks"].items():
                container, _, event = key.rpartition(":") if ":" in key else ("", "", key)
                documents.setdefault(container or "", {})[event] = reader(entries, event)
        elif finding.abs_path is not None:
            payload = _load_json(finding.abs_path, ctx.limits.max_file_bytes)
            if tool == "kiro":
                docs = _from_kiro_hook_docs(payload)
                if not docs:
                    raise ConvertError("legacy Kiro hook shape is not importable")
            else:
                docs = _from_copilot_hook_file(payload)
            documents[""] = docs
        else:
            raise ConvertError("no hook data")
        if not any(documents.values()):
            raise ConvertError("no host-authored hook entries")

        for container, per_event in documents.items():
            hooks_out: dict[str, list] = {}
            for _native_event, document in sorted(per_event.items()):
                entries = _document_to_entries(document)
                canonical = document.bindings[0].event if document.bindings else _native_event
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    for handler in entry.get("hooks", []):
                        if isinstance(handler, dict) and handler.get("command"):
                            handler["command"] = _rewrite_script_tokens(
                                str(handler["command"]),
                                finding,
                                dest.parent,
                                ctx,
                                result,
                                canonical,
                            )
                        if isinstance(handler, dict) and handler.get("type") not in (
                            None,
                            "command",
                        ):
                            result.transform(
                                f"hooks.{canonical}.type",
                                f"'{handler.get('type')}' handlers only fire on {tool}",
                                "warning",
                            )
                if entries:
                    hooks_out.setdefault(canonical, []).extend(entries)
                native, passthrough = event_portability(canonical)
                if passthrough:
                    where = (
                        f"native on {', '.join(native)}" if native else "not native on any target"
                    )
                    result.transform(
                        f"hooks.{canonical}",
                        f"{where}; passed through unmapped on {', '.join(passthrough)}",
                        "info" if canonical in CANONICAL_EVENTS else "warning",
                    )
            if not hooks_out:
                continue
            target = dest if not container else dest.with_name(f"{tool}-{container}-native.json")
            rendered = json.dumps({"hooks": hooks_out}, indent=2) + "\n"
            refuse_credentials(rendered)
            target.parent.mkdir(parents=True, exist_ok=True)
            write_text_lf(target, rendered)
            result.written.append(target)
        if not result.written:
            raise ConvertError("no hook entries produced")
        return result


CONVERTERS = (HooksConverter(),)
