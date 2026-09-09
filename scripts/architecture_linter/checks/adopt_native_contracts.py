"""Importer consumers of native contracts, called by the integration guards."""

from __future__ import annotations

from scripts.architecture_linter.checks.mutation_write_shared import (
    _has_fixed,
    _has_regex,
    _read_required,
    _require,
)
from scripts.architecture_linter.facts import FactsProvider
from scripts.architecture_linter.models import Violation

_HOOKS = "src/apm_cli/adopt/converters/hooks.py"
_SCANNER = "src/apm_cli/adopt/scanners/hooks.py"
_INTEGRATOR = "src/apm_cli/integration/hook_integrator.py"
_BUNDLE = "src/apm_cli/integration/hook_bundle.py"
_AGENTS = "src/apm_cli/adopt/converters/agents.py"
_LEXER = "src/apm_cli/integration/hook_command_paths.py"
_FORMATS = "src/apm_cli/integration/hook_native_formats.py"
_AGENT_VALIDATOR = "src/apm_cli/integration/opencode_frontmatter.py"


def adopt_hook_contract(provider: FactsProvider, rule_id: str) -> tuple[Violation, ...]:
    """Require import dispatch, event identity and compatibility at their owner."""
    facts, failures = _read_required(provider, rule_id, (_HOOKS, _FORMATS, _INTEGRATOR, _BUNDLE))
    if failures:
        return failures
    checks = (
        (_HOOKS, "document = read_native_hook_document("),
        (_HOOKS, "format_id=finding.format_id"),
        (_HOOKS, "event = binding.event"),
        (_HOOKS, "hooks_out.setdefault(event, []).extend(entries)"),
        (_HOOKS, "native, passthrough = event_portability(event)"),
        (_FORMATS, "def read_native_hook_document("),
        (_FORMATS, "if mapping is None or format_id != mapping.format_id:"),
        (_FORMATS, "def canonical_hook_event("),
        (_FORMATS, "from apm_cli.integration.hook_integrator import _HOOK_EVENT_MAP"),
        (_INTEGRATOR, "local_ref = root_local_hook_reference("),
        (_BUNDLE, "source_root = _hook_source_root("),
        (_BUNDLE, "if target_path.is_relative_to(source_root):"),
    )
    result = [
        item
        for path, token in checks
        for item in _require(
            _has_fixed(facts[path], token),
            rule_id,
            path,
            "native hook adoption must delegate dispatch, event identity and portability",
        )
    ]
    result.extend(
        _require(
            not _has_regex(
                facts[_HOOKS],
                r"^(?:_?CANONICAL_EVENTS|_CANONICAL_EVENT_TARGETS|_MERGED_READERS)\s*[:=]"
                r"|^def (?:event_portability|canonical_hook_event)\(",
            ),
            rule_id,
            _HOOKS,
            "adoption must not fork the native hook vocabulary or reader registry",
        )
    )
    return tuple(result)


def adopt_hook_lexing(provider: FactsProvider, rule_id: str) -> tuple[Violation, ...]:
    """Require the same lexical owner for discovery inventory and conversion."""
    facts, failures = _read_required(provider, rule_id, (_HOOKS, _LEXER, _SCANNER))
    if failures:
        return failures
    result = []
    for path, token in (
        (_LEXER, "def project_script_references("),
        (_HOOKS, "for reference in project_script_references(command):"),
        (_HOOKS, "command = command[:start] + replacement + command[end:]"),
        (_SCANNER, "references = project_script_references(declaration.command)"),
        (_SCANNER, "except UnsupportedHookCommand:"),
        (_SCANNER, "for reference in references:"),
        (_SCANNER, "notes=notes"),
    ):
        result.extend(
            _require(
                _has_fixed(facts[path], token),
                rule_id,
                path,
                "hook discovery and adoption must consume bounded spans from hook_command_paths",
            )
        )
    for path in (_HOOKS, _SCANNER):
        result.extend(
            _require(
                not _has_regex(facts[path], r"\bshlex\b|_PROJECT_DIR_VARS"),
                rule_id,
                path,
                "adoption must not reconstruct shell programs or duplicate project lexing",
            )
        )
    return tuple(result)


def native_agent_compatibility(provider: FactsProvider) -> tuple[Violation, ...]:
    """Native compatibility must come from the existing OpenCode validator."""
    rule_id = "mutation_writes.native_agent_compatibility"
    facts, failures = _read_required(provider, rule_id, (_AGENTS, _AGENT_VALIDATOR))
    if failures:
        return failures
    result = []
    for path, token in (
        (_AGENT_VALIDATOR, "def validate_opencode_frontmatter("),
        (_AGENTS, "if validate_opencode_frontmatter(meta, finding.abs_path):"),
        (_AGENTS, 'if "tools" in meta or "permission" in meta:'),
    ):
        result.extend(
            _require(
                _has_fixed(facts[path], token),
                rule_id,
                path,
                "native agent adoption must validate through its owner and preserve policy restrictions",
            )
        )
    return tuple(result)
