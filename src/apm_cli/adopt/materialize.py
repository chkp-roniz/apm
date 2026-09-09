"""``--apply``: stage converted files, validate, commit atomically, update apm.yml."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import click

from apm_cli.constants import APM_YML_FILENAME
from apm_cli.core.command_logger import CommandLogger
from apm_cli.core.scope import USER_APM_DIR
from apm_cli.core.target_detection import manifest_targets_from_target_option
from apm_cli.hook_contract import HookContractError, parse_hook_source
from apm_cli.integration.skill_integrator import normalize_skill_name
from apm_cli.primitives.parser import parse_primitive_file, parse_skill_file
from apm_cli.utils.console import STATUS_SYMBOLS
from apm_cli.utils.path_security import ensure_path_within, safe_rmtree

from .converters import (
    CONVERTERS,
    ConvertContext,
    ConvertError,
    ConvertResult,
    register_builtin_converters,
    summarize_changes,
)
from .converters.base import NameAllocator, flatten_relative
from .manifest_edit import apply_manifest_delta
from .model import AdoptionReport, Finding, HarnessKind, Importability, Ownership, Scope
from .provenance import ImportSources, hash_source, source_identity
from .redact import Redactor
from .render import render
from .safety import approved_path

_SUFFIXES = {
    HarnessKind.INSTRUCTION: (
        "instructions",
        ".instructions.md",
        (".instructions.md", ".md", ".mdc"),
    ),
    HarnessKind.RULE: ("instructions", ".instructions.md", (".instructions.md", ".md", ".mdc")),
    HarnessKind.AGENT: ("agents", ".agent.md", (".agent.md", ".md", ".toml")),
    HarnessKind.PROMPT: ("prompts", ".prompt.md", (".prompt.md", ".md")),
    HarnessKind.COMMAND: ("prompts", ".prompt.md", (".prompt.md", ".md", ".toml")),
}
_DEFAULT_MCP_TOOL_ORDER: tuple[str, ...] = (
    "claude",
    "copilot",
    "vscode",
    "cursor",
    "gemini",
    "kiro",
    "codex",
    "opencode",
    "windsurf",
    "antigravity",
)
_VALIDATION_ADVISORIES = ("instruction will apply globally", "Missing 'description'")


@dataclass
class _CommitTxn:
    """Tracks new writes and backups of replaced destinations for rollback."""

    committed: list[str] = field(default_factory=list)
    replaced: dict[str, Path] = field(default_factory=dict)
    created_dirs: list[Path] = field(default_factory=list)


def _stdin_is_tty() -> bool:
    """Return whether sys.stdin is a TTY (patchable in tests)."""
    try:
        return bool(sys.stdin.isatty())
    except (AttributeError, ValueError):
        return False


def _confirm_apply(prompt: str, *, machine: bool) -> bool:
    """Return whether the user approved the apply prompt.

    JSON/YAML apply reads stdin directly so machine stdout stays a single
    JSON/YAML document. ``click.confirm`` echoes the response to stdout under
    Click's test runner, which breaks ``json.loads(result.stdout)``.
    """
    if not machine:
        try:
            return click.confirm(prompt, default=False, err=True)
        except click.Abort:
            return False
    click.echo(f"{prompt} [y/N]: ", err=True, nl=False)
    try:
        answer = sys.stdin.readline()
    except (KeyboardInterrupt, EOFError):
        return False
    return answer.strip().lower() in ("y", "yes")


def _backup_destination(target: Path, backup_root: Path) -> Path:
    """Copy *target* into *backup_root* so a failed import can restore it."""
    backup_root.mkdir(parents=True, exist_ok=True)
    backup = backup_root / target.name
    suffix = 0
    while backup.exists():
        suffix += 1
        backup = backup_root / f"{target.name}.{suffix}"
    if target.is_dir():
        shutil.copytree(target, backup, symlinks=False)
    else:
        shutil.copy2(target, backup)
    return backup


def _restore_destination(target: Path, backup: Path, apm_dir: Path) -> None:
    """Put a backed-up file or directory back at *target*."""
    ensure_path_within(target, apm_dir)
    if target.is_dir():
        safe_rmtree(target, apm_dir)
    else:
        target.unlink(missing_ok=True)
    if backup.is_dir():
        shutil.copytree(backup, target, symlinks=False)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup, target)


@dataclass
class WriteItem:
    finding: Finding
    converter_id: str
    dest_rel: str
    decision: str
    source_hash: str | None
    result: ConvertResult | None = None
    error: str | None = None
    expected: dict[str, str | None] = field(default_factory=dict)


@dataclass
class WritePlan:
    apm_dir: Path
    items: list[WriteItem] = field(default_factory=list)
    skipped: list[tuple[Finding, str]] = field(default_factory=list)

    @property
    def to_write(self) -> list[WriteItem]:
        return [i for i in self.items if i.decision in ("write", "refresh")]


def _source_rel(finding: Finding) -> PurePosixPath:
    path = PurePosixPath(finding.display_path)
    parts = list(path.parts)
    # Drop the harness root and primitive subdir so nested names flatten below them.
    return PurePosixPath(*parts[2:]) if len(parts) > 2 else PurePosixPath(path.name)


def plan_write(
    report: AdoptionReport, apm_dir: Path, provenance: ImportSources, allocator: NameAllocator
) -> WritePlan:
    """Decide destinations for every eligible finding without touching the disk."""
    plan = WritePlan(apm_dir=apm_dir)
    allocator.reserve(provenance.entries)
    for finding in report.findings:
        if finding.importability not in (Importability.APM_NATIVE, Importability.CONVERTIBLE):
            continue
        if finding.ownership is not Ownership.HOST_OWNED:
            plan.skipped.append((finding, f"{finding.ownership.value}; not written"))
            continue
        converter = CONVERTERS.get(finding.converter_id)
        if converter is None:
            plan.skipped.append((finding, f"no converter for {finding.converter_id}"))
            continue
        if finding.kind is HarnessKind.MCP_SERVER:
            plan.items.append(
                WriteItem(finding, converter.id, "apm.yml#dependencies.mcp", "write", None)
            )
            continue
        try:
            source_hash = hash_source(finding.abs_path, root=provenance.root)
            dest_rel = provenance.destination(finding, report.findings, converter=converter.id)
            if dest_rel is None:
                dest_rel, _renamed = _destination(finding, allocator)
            decision = provenance.decide(
                dest_rel, apm_dir / dest_rel, source_hash, identity=source_identity(finding)
            )
            item = WriteItem(finding, converter.id, dest_rel, decision, source_hash)
            outputs = provenance.outputs(dest_rel) or [dest_rel]
            for output in outputs:
                output_decision = provenance.decide(
                    output, apm_dir / output, source_hash, identity=source_identity(finding)
                )
                if output_decision in ("locally-modified", "collision"):
                    item.decision = output_decision
                item.expected[output] = hash_source(apm_dir / output, root=provenance.root)
            if item.decision == "unchanged" and finding.kind is HarnessKind.HOOK:
                item.decision = "refresh"
        except Exception as exc:
            item = WriteItem(
                finding,
                converter.id,
                "",
                "write",
                None,
                error=f"cannot verify import source or destination ({type(exc).__name__})",
            )
        plan.items.append(item)
    return plan


def _destination(finding: Finding, allocator: NameAllocator) -> tuple[str, bool]:
    if finding.kind is HarnessKind.ROOT_CONTEXT:
        nested = _source_rel(finding).parent if "/" in finding.display_path else PurePosixPath()
        stem = (
            f"{finding.tool}-root"
            if str(nested) in ("", ".")
            else f"{nested.as_posix()}-{finding.tool}-root"
        )
        return allocator.allocate("instructions", stem, ".instructions.md", finding.tool)
    if finding.kind is HarnessKind.SKILL:
        folder = normalize_skill_name(PurePosixPath(finding.display_path).name)
        return allocator.allocate("skills", folder, "", finding.tool)
    if finding.kind is HarnessKind.HOOK:
        stem = f"{finding.tool}-native"
        if finding.payload is None and finding.abs_path is not None:
            stem = f"{finding.tool}-{PurePosixPath(finding.display_path).stem}-native"
        return allocator.allocate("hooks", stem, ".json", finding.tool)
    entry = _SUFFIXES.get(finding.kind)
    if entry is None:
        raise ConvertError(f"no destination rule for {finding.kind.value}")
    subdir, suffix, strip = entry
    stem, _nested = flatten_relative(_source_rel(finding), strip)
    return allocator.allocate(subdir, stem, suffix, finding.tool)


def stage(
    plan: WritePlan, staging_apm: Path, ctx: ConvertContext
) -> list[tuple[str, Mapping[str, Any]]]:
    """Run converters into the staging directory; collect (tool, manifest fragment) pairs."""
    fragments: list[tuple[str, Mapping[str, Any]]] = []
    for item in plan.to_write:
        if item.error:
            continue
        converter = CONVERTERS.get(item.converter_id)
        if converter is None:
            item.error = "converter missing"
            continue
        dest = (
            staging_apm / item.dest_rel
            if item.finding.kind is not HarnessKind.MCP_SERVER
            else staging_apm
        )
        try:
            ensure_path_within(dest, staging_apm)
            if item.finding.abs_path is not None:
                approved_path(item.finding.abs_path, ctx.project_root, mutable=True)
            item.result = converter.convert(item.finding, dest, ctx=ctx)
            if item.result.skipped_reason:
                item.decision = "reference-only"
                plan.skipped.append((item.finding, item.result.skipped_reason))
                continue
            if item.result.manifest_fragment:
                fragments.append((item.finding.tool, item.result.manifest_fragment))
        except ConvertError as exc:
            item.error = str(exc)
        except Exception as exc:  # converter bug must not leak a traceback with paths
            item.error = f"converter failed ({type(exc).__name__})"
    return fragments


def validate_staged(staging_apm: Path) -> list[str]:
    """Parse every staged primitive with the same parsers apm install uses."""
    errors: list[str] = []
    for path in sorted(staging_apm.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(staging_apm).as_posix()
        try:
            if path.name == "SKILL.md":
                problems = parse_skill_file(path).validate()
            elif path.suffix == ".json" and rel.startswith("hooks/") and "/scripts/" not in rel:
                parse_hook_source(json.loads(path.read_text(encoding="utf-8")))
                problems = []
            elif rel.startswith(("instructions/", "agents/", "prompts/")) and path.suffix == ".md":
                problems = (
                    parse_primitive_file(path).validate() if not rel.startswith("prompts/") else []
                )
            else:
                problems = []
        except (HookContractError, ValueError, OSError) as exc:
            problems = [f"unparseable ({type(exc).__name__})"]
        except Exception as exc:
            problems = [f"unparseable ({type(exc).__name__})"]
        for problem in problems:
            if any(advisory in problem for advisory in _VALIDATION_ADVISORIES):
                continue
            errors.append(f"{rel}: {problem}")
    return errors


def _staged_entries(items: list[WriteItem], staging_apm: Path) -> list[str]:
    """Destinations plus any extra staged files (e.g. copied hook scripts)."""
    rels: list[str] = []
    for item in items:
        if (
            item.error
            or item.result is None
            or item.result.skipped_reason
            or item.finding.kind is HarnessKind.MCP_SERVER
        ):
            continue
        rels.append(item.dest_rel)
        auxiliary = staging_apm / "hooks" / Path(item.dest_rel).stem
        if item.finding.kind is HarnessKind.HOOK and auxiliary.is_dir():
            rels.append(auxiliary.relative_to(staging_apm).as_posix())
        for written in item.result.written:
            try:
                rel = written.relative_to(staging_apm).as_posix()
            except ValueError:
                continue
            if not any(rel == owned or rel.startswith(owned + "/") for owned in rels):
                rels.append(rel)
    return rels


def commit(
    staging_apm: Path,
    apm_dir: Path,
    rels: list[str],
    *,
    overwrite_rels: frozenset[str] = frozenset(),
    txn: _CommitTxn | None = None,
    backup_root: Path | None = None,
    approved_root: Path | None = None,
    expected: dict[str, str | None] | None = None,
) -> list[str]:
    """Move staged entries into place; roll back on the first failure."""
    transaction = txn or _CommitTxn()
    backups = backup_root or staging_apm.parent / ".adopt-backup"
    anchor = approved_root or apm_dir.parent
    try:
        for rel in rels:
            source = staging_apm / rel
            if not source.exists():
                continue
            approved_path(apm_dir, anchor, mutable=True)
            target = approved_path(apm_dir / rel, anchor, mutable=True)
            ensure_path_within(target, apm_dir)
            if expected is not None and hash_source(target, root=anchor) != expected.get(rel):
                raise ValueError("destination changed after approval")
            if target.exists():
                if rel not in overwrite_rels:
                    raise FileExistsError(rel)
                hash_source(target, root=anchor)
                approved_path(backups, anchor, mutable=True)
                transaction.replaced[rel] = _backup_destination(target, backups)
                if target.is_dir():
                    safe_rmtree(target, apm_dir)
                else:
                    target.unlink()
            missing = target.parent
            while not missing.exists() and missing != anchor:
                if missing not in transaction.created_dirs:
                    transaction.created_dirs.append(missing)
                missing = missing.parent
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, target)
            transaction.committed.append(rel)
    except Exception:
        _undo_commit(apm_dir, transaction)
        raise
    return transaction.committed


def _undo_commit(apm_dir: Path, txn: _CommitTxn) -> None:
    """Remove newly committed paths and restore any replaced destinations."""
    for rel in reversed(txn.committed):
        path = approved_path(apm_dir / rel, apm_dir.parent, mutable=True)
        ensure_path_within(path, apm_dir)
        if path.is_dir():
            safe_rmtree(path, apm_dir)
        else:
            path.unlink(missing_ok=True)
    for rel, backup in txn.replaced.items():
        _restore_destination(apm_dir / rel, backup, apm_dir)
    for directory in sorted(txn.created_dirs, key=lambda path: len(path.parts), reverse=True):
        approved_path(directory, apm_dir.parent, mutable=True)
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    txn.committed.clear()
    txn.replaced.clear()
    txn.created_dirs.clear()


def _tool_rank_order(preferred: tuple[str, ...]) -> dict[str, int]:
    """First occurrence wins so ``--target`` order is not overwritten by defaults."""
    seen: list[str] = []
    for tool in [*preferred, *_DEFAULT_MCP_TOOL_ORDER]:
        if tool not in seen:
            seen.append(tool)
    return {tool: index for index, tool in enumerate(seen)}


def _dedupe_mcp(
    fragments: list[tuple[str, Mapping[str, Any]]], preferred: tuple[str, ...]
) -> tuple[list[dict], list[str]]:
    """Merge MCP fragments by server name.

    Fragments are ordered by *preferred* (the ``--target`` order, then the
    default client order); the first definition of a name wins, identical
    cores merge their ``extra`` blocks, and divergent cores are reported.
    """
    order = _tool_rank_order(preferred)
    ranked = sorted(
        enumerate(fragments), key=lambda item: (order.get(item[1][0], len(order)), item[0])
    )
    notes: list[str] = []
    by_name: dict[str, dict] = {}
    owner: dict[str, str] = {}
    for _index, (tool, fragment) in ranked:
        for entry in fragment.get("dependencies", {}).get("mcp", []):
            name = str(entry.get("name"))
            if name not in by_name:
                by_name[name] = dict(entry)
                owner[name] = tool
                continue
            current = by_name[name]
            core = {k: v for k, v in entry.items() if k != "extra"}
            existing_core = {k: v for k, v in current.items() if k != "extra"}
            if core == existing_core:
                merged_extra = {**(entry.get("extra") or {}), **(current.get("extra") or {})}
                if merged_extra:
                    current["extra"] = merged_extra
                continue
            differing = sorted(
                k for k in set(core) | set(existing_core) if core.get(k) != existing_core.get(k)
            )
            notes.append(
                f"dependencies.mcp: divergent definitions for {name}; kept {owner[name]} over {tool} "
                f"(fields: {', '.join(differing)})"
            )
    return list(by_name.values()), notes


def _build_write_dict(
    *,
    status: str,
    written: list[str],
    failures: list[WriteItem],
    plan: WritePlan,
    manifest_notes: list[str],
    to_write: list[WriteItem],
    validation_problems: list[str] | None = None,
) -> dict[str, Any]:
    section: dict[str, Any] = {
        "status": status,
        "written": written,
        "failed": [{"path": i.finding.display_path, "reason": i.error} for i in failures],
        "skipped": [{"path": f.display_path, "reason": r} for f, r in plan.skipped]
        + [
            {"path": i.finding.display_path, "destination": i.dest_rel, "reason": i.decision}
            for i in plan.items
            if i.decision not in ("write", "refresh", "reference-only")
        ],
        "manifest": manifest_notes,
        "changes": {
            (i.finding.id if i.finding.kind is HarnessKind.MCP_SERVER else i.dest_rel): [
                c.to_dict() for c in i.result.changes
            ]
            for i in to_write
            if i.result is not None
        },
        "items": [
            {
                "id": i.finding.id,
                "source": i.finding.display_path,
                "tool": i.finding.tool,
                "destination": i.dest_rel,
                "decision": i.decision,
                "error": i.error,
                "changes": [c.to_dict() for c in i.result.changes] if i.result else [],
            }
            for i in plan.items
        ],
    }
    if validation_problems:
        section["validation_errors"] = validation_problems
    return section


def _emit_write_report(report: AdoptionReport, fmt: str, write_section: dict[str, Any]) -> None:
    payload = report.to_dict()
    payload["write"] = write_section
    click.echo(json.dumps(payload, indent=2, sort_keys=True) if fmt == "json" else _yaml(payload))


def _emit_machine_write_report(
    report: AdoptionReport, fmt: str, write_section: dict[str, Any]
) -> None:
    """Emit structured output on stdout after restoring the normal console."""
    if fmt != "text":
        from apm_cli.utils.console import _reset_console

        _reset_console()
    _emit_write_report(report, fmt, write_section)


def _plan_status(message: str, *, symbol: str = "info") -> None:
    """Write one migration-plan line to stderr without the global console singleton."""
    click.echo(f"{STATUS_SYMBOLS.get(symbol, '[i]')} {message}", err=True)


def _log_plan(
    plan: WritePlan,
    to_write: list[WriteItem],
    manifest_notes: list[str],
    validation_problems: list[str],
    *,
    logger: CommandLogger,
    apm_display: str,
    manifest_name: str,
    stderr_only: bool = False,
) -> None:
    """Log the migration plan; use *stderr_only* for JSON/YAML apply (xdist-safe)."""

    def info(message: str) -> None:
        if stderr_only:
            _plan_status(message, symbol="info")
        else:
            logger.info(message)

    def tree_item(message: str) -> None:
        if stderr_only:
            click.echo(message, err=True)
        else:
            logger.tree_item(message)

    def warning(message: str) -> None:
        if stderr_only:
            _plan_status(message, symbol="warning")
        else:
            logger.warning(message)

    def error(message: str) -> None:
        if stderr_only:
            _plan_status(message, symbol="error")
        else:
            logger.error(message)

    file_items = [
        i
        for i in to_write
        if i.finding.kind is not HarnessKind.MCP_SERVER
        and i.decision in ("write", "refresh")
        and not i.error
    ]
    mcp_items = [
        i
        for i in to_write
        if i.finding.kind is HarnessKind.MCP_SERVER
        and i.decision in ("write", "refresh")
        and not i.error
    ]
    failures = [i for i in to_write if i.error]
    info("Import plan")
    if file_items:
        info(f"Will write {len(file_items)} file(s) into {apm_display}/:")
        for item in file_items:
            summary = summarize_changes(item.result.changes) if item.result else ""
            tree_item(
                f"{item.finding.display_path} -> {item.dest_rel} ({item.decision}) [{summary}]"
            )
            for change in item.result.changes if item.result else ():
                if change.severity == "warning":
                    tree_item(f"    {change.path}: {change.reason}")
    if mcp_items:
        info(f"Will add {len(mcp_items)} MCP server(s) to {manifest_name}:")
        for item in mcp_items:
            tree_item(item.finding.display_path)
            for change in item.result.changes if item.result else ():
                if change.severity == "warning":
                    tree_item(f"    {change.path}: {change.reason}")
    if manifest_notes:
        info(f"{manifest_name} changes:")
        for note in manifest_notes:
            tree_item(note)
    unchanged = [i for i in plan.items if i.decision not in ("write", "refresh")]
    if unchanged or plan.skipped:
        info("Not written:")
        for item in unchanged:
            tree_item(f"{item.finding.display_path}: {item.decision}")
        for finding, reason in plan.skipped:
            tree_item(f"{finding.display_path}: {reason}")
    if failures:
        warning(f"{len(failures)} item(s) cannot be imported and will be left out:")
        for item in failures:
            tree_item(f"{item.finding.display_path}: {item.error}")
    if validation_problems:
        error("Staged files failed validation; nothing can be written:")
        for problem in validation_problems[:20]:
            tree_item(problem)


def _describe_plan(
    plan: WritePlan,
    to_write: list[WriteItem],
    manifest_notes: list[str],
    validation_problems: list[str],
    *,
    logger: CommandLogger,
    apm_display: str,
    manifest_name: str,
) -> None:
    """Print everything the user is about to approve: files, losses, skips, manifest edits."""
    click.echo()
    _log_plan(
        plan,
        to_write,
        manifest_notes,
        validation_problems,
        logger=logger,
        apm_display=apm_display,
        manifest_name=manifest_name,
    )


def _rollback(
    apm_dir: Path,
    txn: _CommitTxn,
    manifest: Path,
    manifest_before: bytes | None,
    *,
    provenance_path: Path | None = None,
    provenance_before: bytes | None = None,
) -> None:
    """Undo a partially applied import so files, provenance and apm.yml stay consistent."""
    approved_path(apm_dir, apm_dir.parent, mutable=True)
    approved_path(manifest, apm_dir.parent, mutable=True)
    if provenance_path is not None:
        approved_path(provenance_path, apm_dir.parent, mutable=True)
    if apm_dir.is_dir():
        _undo_commit(apm_dir, txn)
    if manifest_before is None:
        manifest.unlink(missing_ok=True)
    else:
        manifest.write_bytes(manifest_before)
    if provenance_path is not None and provenance_path.parent.is_dir():
        if provenance_before is None:
            provenance_path.unlink(missing_ok=True)
        else:
            provenance_path.write_bytes(provenance_before)


def _preflight(root: Path, apm_dir: Path, manifest: Path) -> None:
    """Validate mutable endpoints against the approved scope, before any reads."""
    for path in (apm_dir, manifest, apm_dir / ".import-sources.json"):
        approved_path(path, root, mutable=True)
    if apm_dir.exists() and not apm_dir.is_dir():
        raise ValueError("import directory is not a directory")
    for path in (manifest, apm_dir / ".import-sources.json"):
        if path.exists() and (not path.is_file() or path.stat().st_size > 1_048_576):
            raise ValueError("import metadata must be a bounded regular file")


def _mcp_plan(
    items: list[WriteItem], manifest: Path, preferred: tuple[str, ...]
) -> tuple[list[dict], list[str]]:
    """Preserve per-source decisions while existing declarations remain authoritative."""
    from apm_cli.utils.yaml_io import load_yaml_roundtrip

    data = load_yaml_roundtrip(manifest) if manifest.exists() else {}
    if not isinstance(data, Mapping):
        raise ValueError("manifest is not a mapping")
    dependencies = data.get("dependencies") or {}
    if not isinstance(dependencies, Mapping):
        raise ValueError("manifest dependencies is not a mapping")
    existing = dependencies.get("mcp") or []
    if not isinstance(existing, list):
        raise ValueError("manifest MCP dependencies is not a list")
    declared = {
        str(entry.get("name") if isinstance(entry, Mapping) else entry): entry for entry in existing
    }
    fragments = [
        (item.finding.tool, item.result.manifest_fragment)
        for item in items
        if not item.error and item.result and item.result.manifest_fragment
    ]
    merged, notes = _dedupe_mcp(fragments, preferred)
    selected = {entry["name"]: entry for entry in merged}
    emitted: set[str] = set()
    entries: list[dict] = []
    order = _tool_rank_order(preferred)
    for item in sorted(items, key=lambda i: order.get(i.finding.tool, len(order))):
        if item.error or not item.result or not item.result.manifest_fragment:
            continue
        entry = item.result.manifest_fragment["dependencies"]["mcp"][0]
        name = entry["name"]
        winner = selected[name]
        core = {key: value for key, value in entry.items() if key != "extra"}
        if core != {key: value for key, value in winner.items() if key != "extra"}:
            item.decision = "collision"
        elif name in declared:
            item.decision = "unchanged" if declared[name] == winner else "collision"
        elif name in emitted:
            item.decision = "unchanged"
        else:
            emitted.add(name)
            entries.append(winner)
    return entries, notes


def _check_outputs(
    plan: WritePlan, staging_apm: Path, provenance: ImportSources, root: Path
) -> None:
    """Bind auxiliary outputs and protect the complete output set before consent."""
    for item in plan.to_write:
        if item.error or item.result is None or item.finding.kind is HarnessKind.MCP_SERVER:
            continue
        outputs = _staged_entries([item], staging_apm)
        for rel in outputs:
            if rel not in item.expected:
                existing = hash_source(plan.apm_dir / rel, root=root)
                item.expected[rel] = existing
                if existing is not None:
                    item.decision = "collision"
        if item.decision == "refresh" and all(
            hash_source(staging_apm / rel, root=root) == item.expected.get(rel) for rel in outputs
        ):
            item.decision = "unchanged"


def _recheck_items(plan: WritePlan, root: Path) -> None:
    """Reject changed plans without overwriting post-plan edits."""
    for item in plan.to_write:
        if item.error:
            continue
        if any(
            hash_source(plan.apm_dir / rel, root=root) != expected
            for rel, expected in item.expected.items()
        ):
            item.decision = "locally-modified"
        elif item.finding.abs_path is not None and item.source_hash is not None:
            if hash_source(item.finding.abs_path, root=root) != item.source_hash:
                item.error = "source changed after preparation; run discovery again"


def run_write(
    report: AdoptionReport,
    *,
    root: Path,
    scope: Scope,
    fmt: str,
    logger: CommandLogger,
    yes: bool,
    target_flag: object | None,
    include_hook_scripts: bool,
) -> int:
    """Prepare, disclose, approve and commit, emitting one truthful execution result."""
    register_builtin_converters()
    root = root.resolve()
    apm_dir = root / ".apm" if scope is Scope.PROJECT else root / USER_APM_DIR
    manifest = (root if scope is Scope.PROJECT else apm_dir) / APM_YML_FILENAME
    plan = WritePlan(apm_dir=apm_dir)
    redactor = Redactor(root)
    apm_display = redactor.path(apm_dir, scope)
    staging_root: Path | None = None
    written: list[str] = []
    manifest_notes: list[str] = []
    status = "failed"
    recovery = "not-needed"
    failure_reason: str | None = None
    commit_txn = _CommitTxn()
    problems: list[str] = []

    def incomplete() -> bool:
        return bool(
            report.errors
            or any(item.error for item in plan.items)
            or any(
                item.decision in ("collision", "locally-modified", "source-missing")
                for item in plan.items
            )
            or (
                plan.skipped
                and any(
                    finding.ownership is Ownership.AMBIGUOUS for finding, _reason in plan.skipped
                )
            )
        )

    try:
        _preflight(root, apm_dir, manifest)
        provenance = ImportSources.load(apm_dir, root=root)
        plan = plan_write(report, apm_dir, provenance, NameAllocator(apm_dir))
        ctx = ConvertContext(
            project_root=root,
            scope=scope,
            redactor=redactor,
            include_hook_scripts=include_hook_scripts,
            preferred_tools=tuple(manifest_targets_from_target_option(target_flag) or ()),
        )
        if fmt == "text":
            render(report, "text", logger)
        # Read metadata even for a no-op: malformed configuration is not success.
        manifest_before = manifest.read_bytes() if manifest.is_file() else None
        provenance_before = provenance.path.read_bytes() if provenance.path.is_file() else None
        _mcp_plan([], manifest, ctx.preferred_tools)
        if not plan.to_write:
            status = "partial" if incomplete() else "complete"
            return 1 if incomplete() else 0
        staging_root = Path(tempfile.mkdtemp(prefix=".apm-adopt-", dir=root))
        staging_apm = staging_root / ".apm"
        staging_apm.mkdir()
        stage(plan, staging_apm, ctx)
        problems = validate_staged(staging_apm)
        _check_outputs(plan, staging_apm, provenance, root)
        mcp_entries, mcp_notes = _mcp_plan(plan.items, manifest, ctx.preferred_tools)
        importable = [item for item in plan.to_write if not item.error]
        targets = (
            list(dict.fromkeys([*ctx.preferred_tools, *report.proposed_targets]))
            if importable
            else []
        )
        create_config: dict[str, Any] | None = None
        if importable and not manifest.is_file():
            from apm_cli.commands._helpers import _get_default_config

            create_config = _get_default_config(root.name if scope is Scope.PROJECT else "user")
            if targets:
                create_config["targets"] = targets
        manifest_notes = mcp_notes + apply_manifest_delta(
            manifest,
            targets=targets,
            mcp_entries=mcp_entries,
            create_config=create_config,
            dry_run=True,
        )
        _log_plan(
            plan,
            plan.items,
            manifest_notes,
            problems,
            logger=logger,
            apm_display=apm_display,
            manifest_name=manifest.name,
            stderr_only=fmt != "text",
        )
        if problems:
            return 1
        if not importable:
            status = "partial" if incomplete() else "complete"
            return 1 if incomplete() else 0
        if not yes:
            if not _stdin_is_tty():
                logger.error("Non-interactive shell: pass --yes to apply")
                status = "refused"
                return 1
            prompt = f"Apply {len(importable)} change(s) and update {manifest.name}?"
            if not _confirm_apply(prompt, machine=(fmt != "text")):
                status = "cancelled"
                return 0

        _preflight(root, apm_dir, manifest)
        if (manifest.read_bytes() if manifest.is_file() else None) != manifest_before or (
            provenance.path.read_bytes() if provenance.path.is_file() else None
        ) != provenance_before:
            raise ValueError("metadata changed after preparation")
        _recheck_items(plan, root)
        importable = [item for item in plan.to_write if not item.error]
        if not importable:
            status = "partial" if incomplete() else "complete"
            return 1 if incomplete() else 0
        rels = _staged_entries(importable, staging_apm)
        expected = {rel: value for item in importable for rel, value in item.expected.items()}
        overwrite_rels = frozenset(rel for rel, value in expected.items() if value is not None)
        try:
            written = commit(
                staging_apm,
                apm_dir,
                rels,
                overwrite_rels=overwrite_rels,
                txn=commit_txn,
                backup_root=staging_root / ".adopt-backup",
                approved_root=root,
                expected=expected,
            )
            _preflight(root, apm_dir, manifest)
            manifest_notes = mcp_notes + apply_manifest_delta(
                manifest,
                targets=targets,
                mcp_entries=mcp_entries,
                create_config=create_config,
            )
            for item in importable:
                if (
                    item.result is None
                    or item.finding.kind is HarnessKind.MCP_SERVER
                    or item.dest_rel not in written
                ):
                    continue
                for rel in item.expected:
                    if rel in written:
                        provenance.record(
                            rel,
                            source=item.finding.display_path,
                            scope=scope.value,
                            converter=item.converter_id,
                            source_hash=item.source_hash or "",
                            dest_abs=apm_dir / rel,
                            identity=source_identity(item.finding),
                            primary=item.dest_rel,
                        )
            if written:
                provenance.save()
        except Exception as exc:
            failure_reason = f"import commit failed ({type(exc).__name__})"
            try:
                _preflight(root, apm_dir, manifest)
                _rollback(
                    apm_dir,
                    commit_txn,
                    manifest,
                    manifest_before,
                    provenance_path=provenance.path,
                    provenance_before=provenance_before,
                )
                recovery = "restored"
                written = []
            except Exception:
                recovery = "incomplete"
            return 1
        status = "partial" if incomplete() else "complete"
        return 1 if incomplete() else 0
    except Exception as exc:
        failure_reason = (
            f"import preparation failed ({type(exc).__name__}); review configuration and retry"
        )
        return 1
    finally:
        cleanup_failed = False
        if staging_root is not None and recovery != "incomplete":
            try:
                approved_path(staging_root, root, mutable=True)
                safe_rmtree(staging_root, root)
            except Exception:
                cleanup_failed = True
                status = "failed"
                failure_reason = "import staging cleanup failed; inspect contained recovery files"
        if fmt != "text":
            section = _build_write_dict(
                status=status,
                written=written,
                failures=[i for i in plan.items if i.error],
                plan=plan,
                manifest_notes=manifest_notes,
                to_write=plan.items,
                validation_problems=problems,
            )
            section["recovery"] = recovery
            if failure_reason:
                section["reason"] = failure_reason
            _emit_machine_write_report(report, fmt, section)
        elif status == "failed":
            logger.error(f"{failure_reason or 'Import failed'}; recovery: {recovery}")
        elif status == "partial":
            logger.warning("PARTIAL: some items were not imported; review conflicts and retry")
        elif status == "cancelled":
            logger.info("Cancelled; nothing written.")
        elif status == "complete":
            logger.success(f"Wrote {len(written)} file(s) into {apm_display}/")
            if written:
                _next_steps(logger, report, redactor, scope)
        if cleanup_failed:
            raise click.exceptions.Exit(1)


def _yaml(payload: dict) -> str:
    from apm_cli.utils.yaml_io import yaml_to_str

    return yaml_to_str(payload, sort_keys=True)


def _next_steps(
    logger: CommandLogger, report: AdoptionReport, redactor: Redactor, scope: Scope
) -> None:
    click.echo()
    logger.info("Next steps:")
    flag = " --global" if scope is Scope.USER else ""
    logger.tree_item(f"apm install{flag}                 # deploy .apm/ to the detected targets")
    logger.tree_item(
        f"apm install{flag} --target cursor # render the imported context on another harness"
    )
    logger.tree_item(
        "Import left originals unchanged. Inspect deployed outputs and reconcile selectively: "
        "source-target rules may be replaced; colliding agents and unmarked roots are retained."
    )
    if any(
        f.kind is HarnessKind.ROOT_CONTEXT and f.importability is Importability.CONVERTIBLE
        for f in report.findings
    ):
        logger.warning(
            "apm compile only overwrites root context files that carry an APM generated marker. "
            "Unmarked project-root AGENTS.md, CLAUDE.md, and GEMINI.md are retained with a warning. "
            "Review active files before retiring any original; consider managed_section mode "
            "for AGENTS.md (<!-- apm:start -->/<!-- apm:end --> markers)."
        )
    if any(f.kind is HarnessKind.MCP_SERVER for f in report.findings):
        logger.tree_item(
            "Export any ${PLACEHOLDER} variables listed above before running apm install."
        )
