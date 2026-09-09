"""Native hook configs -> ``.apm/hooks/<tool>-native.json`` (neutral grammar).

Only host-authored entries reach this converter (the hooks scanner already
dropped ``_apm_source``-marked ones). Scripts are referenced, never executed;
``--include-hook-scripts`` copies in-project scripts next to the hook file.
"""

from __future__ import annotations

import json
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from apm_cli.hook_contract import HOOK_COMMAND_KEYS, HookDocument, parse_hook_source
from apm_cli.integration.hook_command_paths import (
    UnsupportedHookCommand,
    project_script_references,
)
from apm_cli.integration.hook_native_formats import (
    _document_to_entries,
    event_portability,
    read_native_hook_document,
)
from apm_cli.security.gate import SecurityGate
from apm_cli.utils.atomic_io import write_text_lf
from apm_cli.utils.path_security import PathTraversalError, ensure_path_within

from ..model import Finding
from ..safety import approved_path
from . import ConvertContext, ConvertError, ConvertResult
from .base import read_text, refuse_credentials

_MAX_SCRIPT_BYTES = 1_048_576
_MAX_SCRIPT_TOTAL_BYTES = 10 * _MAX_SCRIPT_BYTES


@dataclass(frozen=True)
class _CheckedScript:
    """The exact admitted bytes and portable permission bits, never a reread."""

    content: bytes
    mode: int


@dataclass
class _ScriptCopies:
    """Per-conversion snapshots and an O(1) aggregate admission budget."""

    files: dict[Path, _CheckedScript] = field(default_factory=dict)
    total_bytes: int = 0


def _contained_source(path: Path, root: Path) -> Path:
    """Authorize ancestors before stat/read, and refuse source symlink leaves."""
    try:
        return approved_path(path, root, mutable=True)
    except PathTraversalError as exc:
        raise ConvertError("hook source failed scope admission; refusing to import") from exc


def _read_script(candidate: Path, limit: int) -> _CheckedScript:
    """Read a regular, bounded UTF-8 script and apply both admission checks."""
    try:
        info = candidate.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ConvertError("hook script is not a regular file; refusing to import")
        if info.st_size > limit:
            raise ConvertError("hook script exceeds the size limit; refusing to import")
        # A bounded read also limits a file that grew after stat.
        with candidate.open("rb") as stream:
            content = stream.read(limit + 1)
        if len(content) > limit:
            raise ConvertError("hook script exceeds the size limit; refusing to import")
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConvertError("hook script is not UTF-8 text; refusing to import") from exc
    except OSError as exc:
        raise ConvertError("hook script is unreadable; refusing to import") from exc
    refuse_credentials(text)
    if "\x00" in text:
        raise ConvertError("hook script is not supported text; refusing to import")
    if SecurityGate.scan_text(text, candidate.name).should_block:
        raise ConvertError("hook script blocked by the security scan; refusing to import")
    # Preserve ordinary permissions, not privileged setuid/setgid/sticky bits.
    return _CheckedScript(content=content, mode=stat.S_IMODE(info.st_mode) & 0o777)


def _rewrite_script_tokens(
    command: str,
    dest: Path,
    ctx: ConvertContext,
    result: ConvertResult,
    event: str,
    scripts: _ScriptCopies,
) -> str:
    """Plan script copies and replace only canonical lexical reference spans."""
    replacements = []
    for reference in project_script_references(command):
        candidate = _contained_source(ctx.project_root / reference.path, ctx.project_root)
        relative = "./" + reference.path.removeprefix("./")
        if ctx.include_hook_scripts:
            # The allocated hook stem reserves a whole auxiliary namespace.
            # Keeping the source-relative suffix prevents basename collisions.
            target = (
                dest.parent
                / dest.stem
                / "scripts"
                / candidate.relative_to(ctx.project_root.resolve())
            )
            ensure_path_within(target, dest.parent)
            if target not in scripts.files:
                if len(scripts.files) >= ctx.limits.max_files_per_rule:
                    raise ConvertError("hook scripts exceed the import budget")
                admitted = _read_script(
                    candidate,
                    min(
                        _MAX_SCRIPT_BYTES,
                        ctx.limits.max_file_bytes,
                        _MAX_SCRIPT_TOTAL_BYTES - scripts.total_bytes,
                    ),
                )
                scripts.files[target] = admitted
                scripts.total_bytes += len(admitted.content)
            relative = "./" + target.relative_to(dest.parent).as_posix()
            result.transform(
                f"hooks.{event}.command", "script copied into the hook's reserved script directory"
            )
        elif reference.project_relative:
            result.transform(
                f"hooks.{event}.command", "project-dir variable rewritten to a relative path"
            )
        else:
            continue
        replacements.append((reference.start, reference.end, reference.render(relative)))
    # Right-to-left replacement keeps every original offset valid. Operators,
    # redirects and unrelated variable expansions are never reconstructed.
    for start, end, replacement in reversed(replacements):
        command = command[:start] + replacement + command[end:]
    return command


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
        """Route the family; the native reader rejects unknown source formats."""
        return converter_id.endswith("->apm_hooks")

    def convert(self, finding: Finding, dest: Path, *, ctx: ConvertContext) -> ConvertResult:
        result = ConvertResult()
        if finding.abs_path is not None:
            _contained_source(finding.abs_path, ctx.project_root)
        merged = isinstance(finding.payload, dict) and "hooks" in finding.payload
        if merged:
            payload = finding.payload
        elif finding.abs_path is not None:
            payload = _load_json(finding.abs_path, ctx.limits.max_file_bytes)
        else:
            raise ConvertError("no hook data")
        # Unsupported is never an escape hatch for recognized unsafe content.
        source_text = json.dumps(payload, ensure_ascii=False)
        refuse_credentials(source_text)
        if SecurityGate.scan_text(source_text, "native hooks").should_block:
            raise ConvertError("native hooks blocked by the security scan")
        document = read_native_hook_document(
            finding.tool, payload, merged=merged, format_id=finding.format_id
        )
        if document is None:
            result.skipped_reason = "native hook format has no preserving import contract"
            return result
        if not document.bindings:
            raise ConvertError("no host-authored hook entries")

        hooks_out: dict[str, list] = {}
        scripts = _ScriptCopies()
        try:
            for binding in document.bindings:
                event = binding.event
                entries = _document_to_entries(HookDocument(bindings=(binding,)))
                for entry in entries:
                    if not isinstance(entry, dict):
                        raise UnsupportedHookCommand("unrecognized native hook entry")
                    for handler in entry.get("hooks", []):
                        for key in HOOK_COMMAND_KEYS:
                            if isinstance(handler.get(key), str):
                                handler[key] = _rewrite_script_tokens(
                                    handler[key], dest, ctx, result, event, scripts
                                )
                        if handler.get("type") not in (None, "command"):
                            raise UnsupportedHookCommand("non-command hooks are reference-only")
                if entries:
                    hooks_out.setdefault(event, []).extend(entries)
        except UnsupportedHookCommand as exc:
            return ConvertResult(skipped_reason=str(exc))

        for event in hooks_out:
            native, passthrough = event_portability(event)
            if passthrough:
                where = f"native on {', '.join(native)}" if native else "not native on any target"
                result.transform(
                    f"hooks.{event}",
                    f"{where}; passed through unmapped on {', '.join(passthrough)}",
                    "warning",
                )
        payload = {"hooks": hooks_out}
        parse_hook_source(payload)
        rendered = json.dumps(payload, indent=2) + "\n"
        refuse_credentials(rendered)
        # No executable output is written until the entire hook is admitted.
        # Parent records every returned path under the same durable source ID.
        for target, script in scripts.files.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(script.content)
            target.chmod(script.mode)
            result.written.append(target)
        dest.parent.mkdir(parents=True, exist_ok=True)
        write_text_lf(dest, rendered)
        result.written.append(dest)
        return result


CONVERTERS = (HooksConverter(),)
