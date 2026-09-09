"""Importer provenance integrity stays separate from normalized package hashes."""

from __future__ import annotations

import ast
from collections.abc import Sequence

from scripts.architecture_linter.checks.python_semantics import binding_nodes
from scripts.architecture_linter.facts import FactsProvider
from scripts.architecture_linter.groups.common import checked_facts, violation
from scripts.architecture_linter.models import FileFacts, Rule, Violation

RULE_ID = "contracts-tooling-import-provenance"
OWNER = "src/apm_cli/adopt/provenance.py"
MATERIALIZE = "src/apm_cli/adopt/materialize.py"
ALLOCATOR = "src/apm_cli/adopt/converters/base.py"


def _scope(facts: FileFacts, name: str) -> Sequence[ast.AST]:
    """Query executable function nodes through the shared tree index."""
    index = facts.tree_index
    function = index.function(name) if index is not None else None
    return index.own_scope(function) if function is not None else ()


def _calls(nodes: Sequence[ast.AST], name: str) -> tuple[ast.Call, ...]:
    """Select a qualified callee without re-parsing or walking the AST."""
    return tuple(
        node for node in nodes if isinstance(node, ast.Call) and ast.unparse(node.func) == name
    )


def _assigned_call(
    nodes: Sequence[ast.AST], target: str, callee: str, arguments: tuple[str, ...]
) -> bool:
    """Require the owner's result to drive the named decision, not a dummy call."""
    return any(
        isinstance(node, ast.Assign)
        and any(ast.unparse(item) == target for item in node.targets)
        and isinstance(node.value, ast.Call)
        and ast.unparse(node.value.func) == callee
        and tuple(ast.unparse(arg) for arg in node.value.args) == arguments
        for node in nodes
    )


def check_import_provenance(provider: FactsProvider) -> tuple[Violation, ...]:
    """Require reservations, identity, output sets and hashes at their one owner."""
    facts: dict[str, FileFacts] = {}
    findings: list[Violation] = []
    for path in (OWNER, MATERIALIZE, ALLOCATOR):
        facts[path], failures = checked_facts(provider, path, RULE_ID, require_python=True)
        findings.extend(failures)
    if findings:
        return tuple(findings)

    def require(condition: bool, path: str, message: str) -> None:
        if not condition:
            findings.append(violation(RULE_ID, path, message))

    materialize = facts[MATERIALIZE]
    index = materialize.tree_index
    if index is None:
        return (violation(RULE_ID, MATERIALIZE, "Importer requires a Python tree index"),)
    for name in ("ImportSources", "hash_source", "source_identity"):
        bindings = binding_nodes(index, name)
        require(
            len(bindings) == 1
            and isinstance(bindings[0], ast.ImportFrom)
            and (bindings[0].level, bindings[0].module)
            in ((1, "provenance"), (0, "apm_cli.adopt.provenance"))
            and any(alias.name == name and alias.asname is None for alias in bindings[0].names),
            MATERIALIZE,
            f"{name} must be bound only by the provenance owner import",
        )
    require(
        not any(
            "content_hash" in (imp.module or "").split(".")
            or any(
                part in {"content_hash", "compute_file_hash", "hashlib"}
                for name in imp.names
                for part in name.split(".")
            )
            for imp in materialize.imports
        )
        and not any(
            call.qualname.rsplit(".", 1)[-1] in {"compute_file_hash", "content_key", "sha256"}
            for call in materialize.calls
        ),
        MATERIALIZE,
        "Materialization must not import or compute package hashes or fork local fingerprints",
    )

    plan = _scope(materialize, "plan_write")
    function = index.function("plan_write")
    statements = function.body if isinstance(function, ast.FunctionDef) else ()
    reservation = [
        node
        for node in statements
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and ast.unparse(node.value) == "allocator.reserve(provenance.entries)"
    ]
    finding_loops = [
        node
        for node in statements
        if isinstance(node, ast.For) and ast.unparse(node.iter) == "report.findings"
    ]
    require(
        len(reservation) == len(finding_loops) == 1
        and reservation[0].lineno < finding_loops[0].lineno,
        MATERIALIZE,
        "plan_write must reserve all provenance entries before allocating any finding",
    )
    require(
        _assigned_call(plan, "dest_rel", "provenance.destination", ("finding", "report.findings")),
        MATERIALIZE,
        "plan_write destinations must delegate durable source ownership to provenance.destination",
    )
    require(
        len(_calls(plan, "provenance.decide")) == 2
        and all(
            any(
                kw.arg == "identity" and ast.unparse(kw.value) == "source_identity(finding)"
                for kw in call.keywords
            )
            for call in _calls(plan, "provenance.decide")
        )
        and any(
            ast.unparse(call) == "provenance.outputs(dest_rel)"
            for call in _calls(plan, "provenance.outputs")
        ),
        MATERIALIZE,
        "Primary and auxiliary decisions must consume owner output sets and full source identity",
    )

    record_calls = [
        node
        for node in index.nodes
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "provenance.record"
    ]
    output_loops = [
        node
        for node in index.nodes
        if isinstance(node, ast.For)
        and ast.unparse(node.target) == "rel"
        and ast.unparse(node.iter) == "item.expected"
    ]
    require(
        len(record_calls) == 1
        and any(record_calls[0] in index.walk(loop) for loop in output_loops)
        and tuple(ast.unparse(arg) for arg in record_calls[0].args) == ("rel",)
        and {kw.arg: ast.unparse(kw.value) for kw in record_calls[0].keywords}.items()
        >= {
            "dest_abs": "apm_dir / rel",
            "identity": "source_identity(item.finding)",
            "primary": "item.dest_rel",
        }.items(),
        MATERIALIZE,
        "Every committed auxiliary output must be recorded with its source identity and primary",
    )

    reserve = _scope(facts[ALLOCATOR], "NameAllocator.reserve")
    require(
        any(
            isinstance(node, ast.Assign)
            and any(ast.unparse(target) == "self._taken[destination]" for target in node.targets)
            for node in reserve
        ),
        ALLOCATOR,
        "NameAllocator.reserve must retain provenance reservations in its allocation set",
    )
    owner = facts[OWNER]
    fingerprint = _scope(owner, "hash_source")
    require(
        _assigned_call(fingerprint, "entries", "admitted_entries", ("path", "anchor")),
        OWNER,
        "Local-edit fingerprints must admit the full bounded tree before reading bytes",
    )
    require(
        _assigned_call(
            _scope(owner, "ImportSources.decide"), "current", "hash_source", ("dest_abs",)
        )
        and any(
            kw.arg == "output_sha256"
            and isinstance(kw.value, ast.BoolOp)
            and isinstance(kw.value.values[0], ast.Call)
            and ast.unparse(kw.value.values[0].func) == "hash_source"
            and tuple(ast.unparse(arg) for arg in kw.value.values[0].args) == ("dest_abs",)
            for call in _calls(_scope(owner, "ImportSources.record"), "ImportRecord")
            for kw in call.keywords
        ),
        OWNER,
        "Provenance refresh and recording must use the full local-edit fingerprint authority",
    )
    return tuple(findings)


RULES = (
    Rule(
        RULE_ID,
        "contracts_tests",
        (RULE_ID,),
        "Importer source identity, reservations and full local-edit fingerprints have one owner.",
        check_import_provenance,
    ),
)
