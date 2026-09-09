"""Renderers for the adoption report: text table, JSON and YAML."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING, Any

import click

from apm_cli.core.command_logger import CommandLogger
from apm_cli.utils.yaml_io import yaml_to_str

from .converters import summarize_changes
from .model import AdoptionReport, Finding, HarnessKind, Importability, ScanError

if TYPE_CHECKING:
    from .materialize import WriteItem, WritePlan

_COLUMNS = ("TOOL", "SCOPE", "KIND", "PATH", "IMPORT", "OWNER", "RISK", "-> DEST")
_RISK_SHORT = {"executes-code": "exec", "network": "net", "writes-files": "write"}


def report_to_json(report: AdoptionReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def report_to_yaml(report: AdoptionReport) -> str:
    return yaml_to_str(report.to_dict(), sort_keys=True)


def _row(finding: Finding) -> tuple[str, ...]:
    return (
        finding.tool,
        finding.scope.value,
        finding.kind.value,
        finding.display_path,
        finding.importability.value,
        finding.ownership.value,
        ",".join(sorted(_RISK_SHORT.get(r.value, r.value) for r in finding.risk)) or "-",
        finding.proposed_target or "-",
    )


def _print_table(rows: Sequence[tuple[str, ...]]) -> None:
    """Print an ASCII table; Rich when available, aligned text otherwise."""
    try:
        from rich import box
        from rich.table import Table

        from apm_cli.utils.console import _get_console

        console = _get_console()
    except Exception:  # Rich missing or console unavailable
        console = None
    if console is not None and getattr(console, "is_terminal", False) and console.width >= 120:
        table = Table(
            title="Discovered agent context",
            show_header=True,
            header_style="bold cyan",
            box=box.ASCII,
        )
        for column in _COLUMNS:
            table.add_column(
                column, style="bold white" if column == "PATH" else "white", overflow="fold"
            )
        for row in rows:
            table.add_row(*row)
        console.print(table)
        return
    widths = [len(c) for c in _COLUMNS]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    click.echo("  " + fmt.format(*_COLUMNS))
    click.echo("  " + "  ".join("-" * w for w in widths))
    for row in rows:
        click.echo("  " + fmt.format(*row))


def render_text(
    report: AdoptionReport, logger: CommandLogger, next_steps: Iterable[str] = ()
) -> None:
    """Human-readable report: status lines, table, counts, next steps."""
    if not report.findings:
        logger.info("No agent-harness context files found.")
    else:
        _print_table([_row(f) for f in report.findings])
    counts = report.counts()
    click.echo()
    importable = sum(
        counts["importability"].get(k, 0)
        for k in (Importability.APM_NATIVE.value, Importability.CONVERTIBLE.value)
    )
    logger.info(
        f"{len(report.findings)} findings: {importable} importable, "
        f"{counts['importability'].get(Importability.REFERENCE_ONLY.value, 0)} reference-only, "
        f"{counts['importability'].get(Importability.IGNORED.value, 0)} ignored"
    )
    ambiguous = counts["ownership"].get("ambiguous", 0)
    if ambiguous:
        logger.warning(f"{ambiguous} ambiguous (not written); review notes before --apply")
    if report.errors:
        logger.warning(f"{len(report.errors)} paths could not be evaluated:")
        for error in report.errors[:20]:
            logger.tree_item(f"{error.display_path}: {error.reason}")
    if report.detected_tools:
        logger.info(f"Detected tools: {', '.join(report.detected_tools)}")
    if report.proposed_targets or report.proposed_mcp:
        click.echo()
        logger.info("Proposed apm.yml changes:")
        if report.proposed_targets:
            logger.tree_item(f"targets: {', '.join(report.proposed_targets)}")
        for entry in report.proposed_mcp:
            logger.tree_item(
                f"dependencies.mcp: {entry.get('name')} (from {entry.get('source', '?')})"
            )
    steps = list(next_steps)
    if steps:
        click.echo()
        logger.info("Next steps:")
        for step in steps:
            logger.tree_item(step)


def render(
    report: AdoptionReport, fmt: str, logger: CommandLogger, next_steps: Iterable[str] = ()
) -> None:
    if fmt == "json":
        click.echo(report_to_json(report))
    elif fmt == "yaml":
        click.echo(report_to_yaml(report))
    else:
        render_text(report, logger, next_steps)


def log_plan(
    plan: WritePlan,
    to_write: list[WriteItem],
    manifest_notes: list[str],
    validation_problems: list[str],
    *,
    logger: CommandLogger,
    apm_display: str,
    manifest_name: str,
    scan_errors: tuple[ScanError, ...] = (),
) -> None:
    """Disclose the import plan through the command's existing output routing."""
    info, tree_item, warning, error = (
        logger.info,
        logger.tree_item,
        logger.warning,
        logger.error,
    )
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
    if scan_errors:
        warning(f"{len(scan_errors)} scan error(s); affected configuration is not imported:")
        for problem in scan_errors[:20]:
            tree_item(f"{problem.display_path}: {problem.reason}")
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
            tree_item(f"{item.finding.display_path} -> {item.dest_rel}: {item.decision}")
            if item.decision in ("locally-modified", "collision"):
                tree_item("    Inspect and reconcile the retained output before retrying.")
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


__all__ = ["render", "render_text", "report_to_json", "report_to_yaml"]

_ = Any
