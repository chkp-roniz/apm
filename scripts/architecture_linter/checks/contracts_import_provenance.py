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
RENDER = "src/apm_cli/adopt/render.py"
ALLOCATOR = "src/apm_cli/adopt/converters/base.py"
ROOT_CONTEXT = "src/apm_cli/adopt/converters/root_context.py"
RULE_CONVERTER = "src/apm_cli/adopt/converters/rules.py"
COMMAND_CONVERTER = "src/apm_cli/adopt/converters/commands.py"


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
    for path in (OWNER, MATERIALIZE, ALLOCATOR, ROOT_CONTEXT, RULE_CONVERTER, COMMAND_CONVERTER):
        facts[path], failures = checked_facts(provider, path, RULE_ID, require_python=True)
        findings.extend(failures)
    if findings:
        return tuple(findings)

    def require(condition: bool, path: str, message: str) -> None:
        if not condition:
            findings.append(violation(RULE_ID, path, message))

    # Import identity's display spelling must not become USER activation. Keep
    # the decision at the existing semantic Scope and all-file scope owners.
    root = facts[ROOT_CONTEXT]
    for name, level, module in (("Scope", 2, "model"), ("ALWAYS_ON", 1, "rules")):
        bindings = binding_nodes(root.tree_index, name) if root.tree_index else ()
        require(
            len(bindings) == 1
            and isinstance(bindings[0], ast.ImportFrom)
            and (bindings[0].level, bindings[0].module) == (level, module)
            and any(alias.name == name and alias.asname is None for alias in bindings[0].names),
            ROOT_CONTEXT,
            f"Root context {name} must come from its canonical owner",
        )
    convert_root = _scope(root, "RootContextConverter.convert")
    activation = [
        node
        for node in convert_root
        if isinstance(node, ast.Assign)
        and any(ast.unparse(target) == "metadata['applyTo']" for target in node.targets)
    ]
    gates = [
        node
        for node in convert_root
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.BoolOp)
        and isinstance(node.test.op, ast.And)
        and ast.unparse(node.test.values[0]) == "finding.scope is not Scope.USER"
    ]
    require(
        len(gates) == 1
        and len(activation) == 2
        and any(node in gates[0].body for node in activation)
        and any(
            node in gates[0].orelse and ast.unparse(node.value) == "ALWAYS_ON"
            for node in activation
        ),
        ROOT_CONTEXT,
        "USER root activation must use ALWAYS_ON, never its presentation-only display path",
    )
    for path, function_name in (
        (ROOT_CONTEXT, "RootContextConverter.convert"),
        (RULE_CONVERTER, "RulesConverter.convert"),
        (COMMAND_CONVERTER, "CommandsConverter.convert"),
    ):
        converter = facts[path]
        tree = converter.tree_index
        function = tree.function(function_name) if tree else None
        statements = function.body if isinstance(function, ast.FunctionDef) else ()
        nodes = _scope(converter, function_name)
        for name in ("read_text", "refuse_credentials"):
            bindings = binding_nodes(tree, name) if tree else ()
            require(
                len(bindings) == 1
                and isinstance(bindings[0], ast.ImportFrom)
                and (bindings[0].level, bindings[0].module) == (1, "base")
                and any(alias.name == name and alias.asname is None for alias in bindings[0].names),
                path,
                f"Original source admission must use canonical {name}",
            )
        reads = [
            node
            for node in statements
            if _assigned_call(
                (node,), "text", "read_text", ("finding.abs_path", "ctx.limits.max_file_bytes")
            )
        ]
        screens = [
            node
            for node in statements
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and ast.unparse(node.value) == "refuse_credentials(text)"
        ]
        edits = tuple(
            call
            for name in ("parse_markdown", "_from_gemini_toml", "strip_managed_section")
            for call in _calls(nodes, name)
        )
        require(
            len(reads) == len(screens) == 1
            and bool(edits)
            and reads[0].lineno < screens[0].lineno
            and all(screens[0].lineno < call.lineno for call in edits)
            and not any(
                isinstance(node, ast.Assign)
                and any(ast.unparse(target) == "text" for target in node.targets)
                and reads[0].lineno < node.lineno < screens[0].lineno
                for node in nodes
            ),
            path,
            "Screen the bounded ORIGINAL source before parsing or lossy edits",
        )
        if path != ROOT_CONTEXT:
            require(
                all(
                    call.args and ast.unparse(call.args[0]) == "f'frontmatter.field[{index}]'"
                    for call in _calls(nodes, "result.drop")
                ),
                path,
                "Dropped metadata diagnostics must use ordinals, never untrusted key names",
            )

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
    indexed = bool(_calls(plan, "provenance.for_plan"))
    if indexed:
        index_assignments = [
            node
            for node in statements
            if _assigned_call((node,), "ownership", "provenance.for_plan", ("report.findings",))
        ]
        require(
            len(index_assignments) == len(finding_loops) == 1
            and index_assignments[0].lineno < finding_loops[0].lineno,
            MATERIALIZE,
            "Attribution indices must consume real findings once before the finding loop",
        )
    destination_owner = "ownership" if indexed else "provenance"
    require(
        _assigned_call(
            plan,
            "dest_rel",
            f"{destination_owner}.destination",
            ("finding",) if indexed else ("finding", "report.findings"),
        ),
        MATERIALIZE,
        "plan_write destinations must delegate durable source ownership to provenance",
    )
    decision_method = "provenance.inspect" if indexed else "provenance.decide"
    require(
        len(_calls(plan, decision_method)) == 2
        and all(
            any(
                kw.arg == "identity" and ast.unparse(kw.value) == "source_identity(finding)"
                for kw in call.keywords
            )
            for call in _calls(plan, decision_method)
        )
        and any(
            ast.unparse(call) == f"{destination_owner}.outputs(dest_rel)"
            for call in _calls(plan, f"{destination_owner}.outputs")
        ),
        MATERIALIZE,
        "Primary and auxiliary decisions must consume owner output sets and full source identity",
    )
    if indexed:
        assignments = {
            ast.unparse(target): ast.unparse(node.value)
            for node in plan
            if isinstance(node, ast.Assign)
            for target in node.targets
        }
        require(
            _assigned_call(
                plan,
                "witness",
                "provenance.inspect",
                ("dest_rel", "apm_dir / dest_rel", "source_hash"),
            )
            and assignments.items()
            >= {
                "decision": "witness.decision",
                "output_witness": (
                    "witness if output == dest_rel else provenance.inspect("
                    "output, apm_dir / output, source_hash, identity=source_identity(finding))"
                ),
                "output_decision": "output_witness.decision",
                "item.expected[output]": "output_witness.current_hash",
            }.items(),
            MATERIALIZE,
            "Preparation must reuse the primary witness and consume each output's full hash",
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
            _scope(owner, "ImportSources.inspect"), "current", "hash_source", ("dest_abs",)
        )
        and any(
            isinstance(node, ast.Return)
            and node.value is not None
            and ast.unparse(node.value)
            == "self.inspect(dest_rel, dest_abs, source_hash, identity=identity).decision"
            for node in _scope(owner, "ImportSources.decide")
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


def check_import_output(provider: FactsProvider) -> tuple[Violation, ...]:
    """Import plans use CommandLogger without resetting the canonical stream mode."""
    rule_id = "contracts-tooling-import-output"
    facts, failures = checked_facts(provider, RENDER, rule_id, require_python=True)
    materialize, other_failures = checked_facts(provider, MATERIALIZE, rule_id, require_python=True)
    failures = (*failures, *other_failures)
    if failures:
        return failures
    plan = _scope(facts, "log_plan")
    aliases = [
        node
        for node in plan
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and ast.unparse(node.targets[0]) == "(info, tree_item, warning, error)"
        and ast.unparse(node.value)
        == "(logger.info, logger.tree_item, logger.warning, logger.error)"
    ]
    findings = []
    if len(aliases) != 1 or _calls(plan, "click.echo"):
        findings.append(
            violation(rule_id, RENDER, "Import plan diagnostics must use CommandLogger")
        )
    bindings = binding_nodes(materialize.tree_index, "_log_plan") if materialize.tree_index else ()
    if any(
        call.qualname.rsplit(".", 1)[-1] in {"_reset_console", "set_console_stderr"}
        for call in materialize.calls
    ) or not (
        len(bindings) == 1
        and isinstance(bindings[0], ast.ImportFrom)
        and bindings[0].module == "render"
        and any(
            alias.name == "log_plan" and alias.asname == "_log_plan" for alias in bindings[0].names
        )
    ):
        findings.append(
            violation(
                rule_id,
                MATERIALIZE,
                "Import diagnostics must use CommandLogger and preserve root output routing",
            )
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
    Rule(
        "contracts-tooling-import-output",
        "contracts_tests",
        ("contracts-tooling-import-output",),
        "Import diagnostics must retain CommandLogger and root output-mode ownership.",
        check_import_output,
    ),
)
