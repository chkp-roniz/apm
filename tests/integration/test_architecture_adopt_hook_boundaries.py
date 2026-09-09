"""Mutation-break proof for adoption's canonical hook consumers."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from scripts.architecture_linter.runner import run_selected_rules

pytestmark = pytest.mark.component

ROOT = Path(__file__).resolve().parents[2]
HOOKS = "src/apm_cli/adopt/converters/hooks.py"
SCANNER = "src/apm_cli/adopt/scanners/hooks.py"
FORMATS = "src/apm_cli/integration/hook_native_formats.py"
INTEGRATOR = "src/apm_cli/integration/hook_integrator.py"
BUNDLE = "src/apm_cli/integration/hook_bundle.py"
AGENTS = "src/apm_cli/adopt/converters/agents.py"


@pytest.mark.parametrize(
    ("rule_id", "path", "old", "new"),
    [
        (
            "mutation_writes.neutral_hook_contract",
            HOOKS,
            "document = read_native_hook_document(",
            "document = local_hook_reader(",
        ),
        (
            "mutation_writes.neutral_hook_contract",
            HOOKS,
            "event = binding.event",
            'event = "BeforeTool"',
        ),
        (
            "mutation_writes.neutral_hook_contract",
            HOOKS,
            "native, passthrough = event_portability(event)",
            "native, passthrough = local_portability(event)",
        ),
        (
            "mutation_writes.native_agent_compatibility",
            AGENTS,
            "if validate_opencode_frontmatter(meta, finding.abs_path):",
            "if False:",
        ),
        (
            "mutation_writes.hook_command_vocabulary",
            HOOKS,
            "for reference in project_script_references(command):",
            "for reference in local_script_references(command):",
        ),
        (
            "mutation_writes.hook_command_vocabulary",
            HOOKS,
            "command = command[:start] + replacement + command[end:]",
            'command = __import__("shlex").join(command.split())',
        ),
        (
            "mutation_writes.hook_command_vocabulary",
            SCANNER,
            "references = project_script_references(declaration.command)",
            "references = local_script_references(declaration.command)",
        ),
        (
            "mutation_writes.hook_command_vocabulary",
            SCANNER,
            "for reference in references:",
            "for reference in references[:1]:",
        ),
        (
            "mutation_writes.hook_command_vocabulary",
            SCANNER,
            "import json",
            "import json\nimport shlex",
        ),
        (
            "mutation_writes.hook_command_vocabulary",
            SCANNER,
            "_EXECUTES = ",
            "_PROJECT_DIR_VARS = ()\n_EXECUTES = ",
        ),
        (
            "mutation_writes.hook_command_vocabulary",
            SCANNER,
            "except UnsupportedHookCommand:",
            "except ValueError:",
        ),
        (
            "mutation_writes.hook_command_vocabulary",
            SCANNER,
            "notes=notes",
            "notes=None",
        ),
        (
            "mutation_writes.neutral_hook_contract",
            HOOKS,
            "format_id=finding.format_id",
            "format_id=None",
        ),
        (
            "mutation_writes.neutral_hook_contract",
            FORMATS,
            "if mapping is None or format_id != mapping.format_id:",
            "if False:",
        ),
        (
            "mutation_writes.neutral_hook_contract",
            INTEGRATOR,
            "local_ref = root_local_hook_reference(",
            "local_ref = local_hook_reference(",
        ),
        (
            "mutation_writes.neutral_hook_contract",
            BUNDLE,
            "if target_path.is_relative_to(source_root):",
            "if False:",
        ),
    ],
)
def test_importer_boundary_mutations_are_rejected(
    rule_id: str, path: str, old: str, new: str
) -> None:
    baseline = run_selected_rules(ROOT, (rule_id,))
    assert baseline.violations == ()
    assert baseline.failures == ()
    source = (ROOT / path).read_text()
    assert source.count(old) == 1
    mutation = source.replace(old, new, 1)
    ast.parse(mutation)
    result = run_selected_rules(ROOT, (rule_id,), source_overrides={path: mutation})
    assert any(v.rule_id == rule_id and v.path == path for v in result.violations), (
        result.violations
    )
