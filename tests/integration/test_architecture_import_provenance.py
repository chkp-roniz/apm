"""Disk-backed mutation proof for the importer provenance authority."""

from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.architecture_linter.facts import FactsProvider
from scripts.architecture_linter.runner import registered_rules, run_selected_rules

pytestmark = pytest.mark.component

ROOT = Path(__file__).resolve().parents[2]
RULE_ID = "contracts-tooling-import-provenance"
OWNER = "src/apm_cli/adopt/provenance.py"
MATERIALIZE = "src/apm_cli/adopt/materialize.py"
RENDER = "src/apm_cli/adopt/render.py"
ALLOCATOR = "src/apm_cli/adopt/converters/base.py"
ROOT_CONTEXT = "src/apm_cli/adopt/converters/root_context.py"
RULE_CONVERTER = "src/apm_cli/adopt/converters/rules.py"
COMMAND_CONVERTER = "src/apm_cli/adopt/converters/commands.py"
IMPORT_PATHS = (OWNER, MATERIALIZE, ALLOCATOR, ROOT_CONTEXT, RULE_CONVERTER, COMMAND_CONVERTER)
GUARD = "scripts/architecture_linter/checks/contracts_import_provenance.py"
BEHAVIOR = "tests/unit/adopt/test_import_provenance.py"
PERFORMANCE = "tests/unit/adopt/test_provenance_performance.py"
SOURCE_SCOPE = "tests/unit/adopt/test_source_scope_followups.py"
SOURCE_SECRETS = "tests/unit/adopt/test_source_secret_followups.py"
BOUNDARY = "tests/integration/test_architecture_import_provenance.py"


def _current_spelling(old: str, text: str) -> str:
    """Keep the same mutation proof when materialization adopts the per-plan API."""
    if "ownership = provenance.for_plan(report.findings)" in text:
        return old.replace(
            "provenance.destination(finding, report.findings,",
            "ownership.destination(finding,",
        ).replace("provenance.outputs(dest_rel)", "ownership.outputs(dest_rel)")
    return old


def _indexed_materialize(text: str) -> str:
    """Exercise the caller integration in a sandbox, never change the real caller."""
    if "ownership = provenance.for_plan(report.findings)" in text:
        return text
    replacements = {
        "allocator.reserve(provenance.entries)": (
            "allocator.reserve(provenance.entries)\n"
            "    ownership = provenance.for_plan(report.findings)"
        ),
        "provenance.destination(finding, report.findings,": "ownership.destination(finding,",
        "decision = provenance.decide(\n": "witness = provenance.inspect(\n",
        "            item = WriteItem(finding, converter.id, dest_rel, decision, source_hash)": (
            "            decision = witness.decision\n"
            "            item = WriteItem(finding, converter.id, dest_rel, decision, source_hash)"
        ),
        "provenance.outputs(dest_rel)": "ownership.outputs(dest_rel)",
        "output_decision = provenance.decide(\n": (
            "output_witness = witness if output == dest_rel else provenance.inspect(\n"
        ),
        '                if output_decision in ("locally-modified", "collision"):': (
            "                output_decision = output_witness.decision\n"
            '                if output_decision in ("locally-modified", "collision"):'
        ),
        "item.expected[output] = hash_source(apm_dir / output, root=provenance.root)": (
            "item.expected[output] = output_witness.current_hash"
        ),
    }
    # Replace the auxiliary spelling first; it contains the primary suffix.
    for old, new in sorted(replacements.items(), key=lambda pair: -len(pair[0])):
        assert text.count(old) == 1, old
        text = text.replace(old, new, 1)
    ast.parse(text)
    return text


def test_import_provenance_owner_boundary() -> None:
    """The live registry and registered guard must accept the working tree."""
    result = run_selected_rules(ROOT, (RULE_ID,))
    assert result.failures == ()
    assert result.violations == ()


@pytest.mark.parametrize(
    ("relative", "old", "new"),
    [
        (RENDER, "logger.info,", "logger.warning,"),
        (
            MATERIALIZE,
            "_emit_write_report(report, fmt, write_section)",
            "__import__('apm_cli.utils.console', fromlist=['_reset_console'])._reset_console()\n"
            "    _emit_write_report(report, fmt, write_section)",
        ),
        (RENDER, 'info("Import plan")', 'click.echo("Import plan")'),
        (
            MATERIALIZE,
            "from .render import log_plan as _log_plan",
            "from .render import render as _log_plan",
        ),
    ],
)
def test_import_output_owner_mutations_on_disk(
    tmp_path: Path, relative: str, old: str, new: str
) -> None:
    """Restoring either parallel renderer or stream reset violates the output owner."""
    rule = next(r for r in registered_rules() if r.id == "contracts-tooling-import-output")
    paths = (MATERIALIZE, RENDER)
    for source in paths:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / source).read_text())
    path = tmp_path / relative
    original = path.read_text()
    assert rule.check(FactsProvider(tmp_path, paths, registry=None)) == ()
    assert original.count(old) == 1
    mutation = original.replace(old, new, 1)
    ast.parse(mutation)
    path.write_text(mutation)
    violations = rule.check(FactsProvider(tmp_path, paths, registry=None))
    assert any(item.rule_id == rule.id and item.path == relative for item in violations)
    path.write_text(original)
    assert rule.check(FactsProvider(tmp_path, paths, registry=None)) == ()


@pytest.mark.parametrize(
    ("path", "old", "new"),
    [
        pytest.param(
            MATERIALIZE,
            "dest_rel = provenance.destination(finding, report.findings, converter=converter.id)",
            "dest_rel = None",
            id="destination-delegation",
        ),
        pytest.param(
            MATERIALIZE,
            "allocator.reserve(provenance.entries)",
            "pass",
            id="reserve-recorded-destinations",
        ),
        pytest.param(
            MATERIALIZE,
            "allocator.reserve(provenance.entries)",
            "allocator.reserve(())",
            id="reserve-real-entries",
        ),
        pytest.param(
            ALLOCATOR,
            'self._taken[destination] = "recorded"',
            'self._by_content[destination] = "recorded"',
            id="allocator-reservation-storage",
        ),
        pytest.param(
            MATERIALIZE,
            "outputs = provenance.outputs(dest_rel) or [dest_rel]",
            "outputs = [dest_rel]",
            id="auxiliary-decision",
        ),
        pytest.param(
            MATERIALIZE,
            "for rel in item.expected:",
            "for rel in [item.dest_rel]:",
            id="auxiliary-record",
        ),
        pytest.param(
            MATERIALIZE,
            "primary=item.dest_rel,",
            'primary="",',
            id="auxiliary-primary",
        ),
        pytest.param(
            MATERIALIZE,
            "identity=source_identity(item.finding),",
            'identity="",',
            id="durable-source-identity",
        ),
        pytest.param(
            MATERIALIZE,
            "from .provenance import ImportSources, hash_source, source_identity",
            "from .provenance import ImportSources, source_identity\n"
            "from apm_cli.utils.content_hash import compute_file_hash as hash_source",
            id="external-hash-alias",
        ),
        pytest.param(
            MATERIALIZE,
            "from .provenance import ImportSources, hash_source, source_identity",
            "from .provenance import ImportSources, hash_source, source_identity\n"
            "from apm_cli.utils import content_hash as package_hash",
            id="external-hash-module",
        ),
        pytest.param(
            MATERIALIZE,
            "from .provenance import ImportSources, hash_source, source_identity",
            "from .provenance import ImportSources, hash_source, source_identity\n"
            "def hash_source(path, **kwargs):\n    return str(path)\n",
            id="local-hash-shadow",
        ),
        pytest.param(
            OWNER,
            'output_sha256=hash_source(dest_abs, root=self.root) or "",',
            "output_sha256=compute_file_hash(dest_abs),",
            id="output-fingerprint-owner",
        ),
        pytest.param(
            OWNER,
            "current = hash_source(dest_abs, root=anchor)",
            "current = compute_file_hash(dest_abs)",
            id="refresh-fingerprint-owner",
        ),
        pytest.param(
            OWNER,
            "entries = admitted_entries(path, anchor, file_limit=file_limit)",
            "entries = [path]",
            id="bounded-admission",
        ),
        pytest.param(
            ROOT_CONTEXT,
            'metadata["applyTo"] = ALWAYS_ON',
            'metadata["applyTo"] = f"{nested_dir.as_posix()}/**"',
            id="user-root-display-activation",
        ),
        pytest.param(
            ROOT_CONTEXT,
            "finding.scope is not Scope.USER",
            "True",
            id="user-root-semantic-gate",
        ),
        pytest.param(
            ROOT_CONTEXT,
            "from .rules import ALWAYS_ON",
            'ALWAYS_ON = "**"',
            id="user-root-scope-owner",
        ),
        *[
            pytest.param(
                path,
                "refuse_credentials(text)",
                "pass",
                id=f"original-source-screen-{label}",
            )
            for path, label in (
                (ROOT_CONTEXT, "root"),
                (RULE_CONVERTER, "rule"),
                (COMMAND_CONVERTER, "commands"),
            )
        ],
        *[
            pytest.param(
                path,
                'f"frontmatter.field[{index}]"',
                'f"frontmatter.{key}"',
                id=f"metadata-key-diagnostic-{label}",
            )
            for path, label in ((RULE_CONVERTER, "rule"), (COMMAND_CONVERTER, "commands"))
        ],
    ],
)
def test_import_provenance_mutations_on_disk(tmp_path: Path, path: str, old: str, new: str) -> None:
    """An actual edited file must trigger this guard, not an unrelated failure."""
    paths = IMPORT_PATHS
    for relative in paths:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8")
    rule = next(rule for rule in registered_rules() if rule.id == RULE_ID)
    assert rule.check(FactsProvider(tmp_path, paths, registry=None)) == ()
    target = tmp_path / path
    original = target.read_text(encoding="utf-8")
    old = _current_spelling(old, original)
    assert original.count(old) == 1
    mutation = original.replace(old, new, 1)
    ast.parse(mutation)
    try:
        target.write_text(mutation, encoding="utf-8")
        violations = rule.check(FactsProvider(tmp_path, paths, registry=None))
        assert any(v.rule_id == RULE_ID and v.path == path for v in violations), violations
    finally:
        target.write_text(original, encoding="utf-8")
    assert rule.check(FactsProvider(tmp_path, paths, registry=None)) == ()


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "ownership = provenance.for_plan(report.findings)",
            "ownership = provenance.for_plan(())",
        ),
        (
            "dest_rel = ownership.destination(finding, converter=converter.id)",
            "dest_rel = None",
        ),
        ("outputs = ownership.outputs(dest_rel) or [dest_rel]", "outputs = [dest_rel]"),
        ("witness if output == dest_rel else provenance.inspect", "provenance.inspect"),
        ("identity=source_identity(finding)", "identity=None"),
        ("item.expected[output] = output_witness.current_hash", "item.expected[output] = None"),
        ("output_decision = output_witness.decision", 'output_decision = "refresh"'),
    ],
)
def test_indexed_provenance_mutations_on_disk(tmp_path: Path, old: str, new: str) -> None:
    """The optimized caller must retain owner delegation and real witness consumption."""
    paths = IMPORT_PATHS
    for relative in paths:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        text = (ROOT / relative).read_text(encoding="utf-8")
        target.write_text(
            _indexed_materialize(text) if relative == MATERIALIZE else text, encoding="utf-8"
        )
    rule = next(rule for rule in registered_rules() if rule.id == RULE_ID)
    assert rule.check(FactsProvider(tmp_path, paths, registry=None)) == ()
    target = tmp_path / MATERIALIZE
    original = target.read_text(encoding="utf-8")
    match = re.search(r"\s+".join(re.escape(part) for part in old.split()), original)
    assert match is not None
    mutation = original[: match.start()] + new + original[match.end() :]
    ast.parse(mutation)
    target.write_text(mutation, encoding="utf-8")
    violations = rule.check(FactsProvider(tmp_path, paths, registry=None))
    assert any(v.rule_id == RULE_ID and v.path == MATERIALIZE for v in violations)
    target.write_text(original, encoding="utf-8")
    assert rule.check(FactsProvider(tmp_path, paths, registry=None)) == ()


@pytest.mark.parametrize(
    ("path", "old", "new", "nodeid"),
    [
        pytest.param(
            MATERIALIZE,
            "dest_rel = provenance.destination(finding, report.findings, converter=converter.id)",
            "dest_rel = None",
            BEHAVIOR + "::test_source_set_churn_retains_destinations_and_reservations[reorder]",
            id="behavior-destination",
        ),
        pytest.param(
            MATERIALIZE,
            "allocator.reserve(provenance.entries)",
            "pass",
            BEHAVIOR + "::test_source_set_churn_retains_destinations_and_reservations[remove]",
            id="behavior-reservation",
        ),
        pytest.param(
            OWNER,
            "entries = admitted_entries(path, anchor, file_limit=file_limit)",
            "entries = [path]",
            BEHAVIOR + "::test_hash_source_rejects_budget_before_any_content_read[tree-file]",
            id="behavior-bounded-hash",
        ),
        pytest.param(
            OWNER,
            "comparable = compute_file_hash(dest_abs)",
            "current = comparable = compute_file_hash(dest_abs)",
            PERFORMANCE + "::test_legacy_decision_retains_byte_exact_expected_witness",
            id="behavior-legacy-full-witness",
        ),
        pytest.param(
            OWNER,
            "return ImportSourceIndex(self.entries, findings)",
            "return ImportSourceIndex(self.entries, ())",
            PERFORMANCE + "::test_plan_index_has_linear_record_and_finding_visits[legacy]",
            id="behavior-plan-ambiguity-index",
        ),
        pytest.param(
            GUARD,
            "if not condition:",
            "if False and not condition:",
            BOUNDARY + "::test_import_provenance_mutations_on_disk[reserve-recorded-destinations]",
            id="boundary-assertion",
        ),
        pytest.param(
            ROOT_CONTEXT,
            "finding.scope is not Scope.USER",
            "True",
            SOURCE_SCOPE + "::test_native_user_root_context_is_all_file_scope[.claude/CLAUDE.md]",
            id="behavior-user-root-semantic-gate",
        ),
        *[
            pytest.param(
                path,
                "refuse_credentials(text)",
                "pass",
                SOURCE_SECRETS
                + f"::test_cli_refuses_original_metadata_credentials[key-{label}-json]",
                id=f"behavior-original-source-screen-{label}",
            )
            for path, label in (
                (RULE_CONVERTER, "rule"),
                (COMMAND_CONVERTER, "markdown-command"),
                (COMMAND_CONVERTER, "toml-command"),
            )
        ],
        *[
            pytest.param(
                path,
                'f"frontmatter.field[{index}]"',
                'f"frontmatter.{key}"',
                SOURCE_SECRETS + f"::test_cli_dropped_metadata_uses_ordinals[{label}-json]",
                id=f"behavior-metadata-key-diagnostic-{label}",
            )
            for path, label in (
                (RULE_CONVERTER, "rule"),
                (COMMAND_CONVERTER, "markdown-command"),
                (COMMAND_CONVERTER, "toml-command"),
            )
        ],
        pytest.param(
            GUARD,
            "if not condition:",
            "if False and not condition:",
            BOUNDARY + "::test_import_provenance_mutations_on_disk[user-root-display-activation]",
            id="boundary-user-root-activation",
        ),
    ],
)
def test_provenance_mutation_kills_on_disk(
    tmp_path: Path, path: str, old: str, new: str, nodeid: str
) -> None:
    """Replay maintained tests in fresh interpreters: green, mutation-kill, restored green."""
    sandbox = tmp_path / "snapshot"
    shutil.copytree(
        ROOT / "src/apm_cli",
        sandbox / "src/apm_cli",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copytree(
        ROOT / "scripts/architecture_linter",
        sandbox / "scripts/architecture_linter",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    for relative in (
        "pyproject.toml",
        "tests/__init__.py",
        "tests/unit/__init__.py",
        "tests/unit/adopt/__init__.py",
        "tests/unit/adopt/conftest.py",
        "tests/utils/__init__.py",
        "tests/utils/apm_lifecycle_runner.py",
        "tests/utils/isolated_apm_environment.py",
        BEHAVIOR,
        PERFORMANCE,
        SOURCE_SCOPE,
        SOURCE_SECRETS,
        BOUNDARY,
    ):
        target = sandbox / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    temporary = sandbox / ".pytest_cache"
    temporary.mkdir()
    env = dict(
        os.environ,
        PYTHONPATH=os.pathsep.join((str(sandbox / "src"), str(sandbox))),
        PYTHONDONTWRITEBYTECODE="1",
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        TMPDIR=str(temporary),
        UV_NO_SYNC="1",
    )
    # The sandbox source path precedes editable-install mappings; prove that the
    # subprocess tests exercise those actual bytes, not the parent checkout.
    probe = subprocess.run(
        [sys.executable, "-B", "-c", "import apm_cli.adopt.materialize as m; print(m.__file__)"],
        cwd=sandbox,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert probe.returncode == 0, probe.stderr
    assert Path(probe.stdout.strip()).resolve() == sandbox / MATERIALIZE

    def replay() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "pytest",
                "-q",
                "-o",
                "addopts=",
                "--confcutdir",
                str(sandbox),
                nodeid,
            ],
            cwd=sandbox,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    baseline = replay()
    assert baseline.returncode == 0, baseline.stdout + baseline.stderr
    target = sandbox / path
    original = target.read_text(encoding="utf-8")
    old = _current_spelling(old, original)
    assert original.count(old) == 1
    mutation = original.replace(old, new, 1)
    ast.parse(mutation)
    try:
        target.write_text(mutation, encoding="utf-8")
        killed = replay()
        assert killed.returncode == 1, killed.stdout + killed.stderr
        assert "AssertionError" in killed.stdout or "DID NOT RAISE" in killed.stdout
        assert "1 failed" in killed.stdout
    finally:
        target.write_text(original, encoding="utf-8")
    restored = replay()
    assert restored.returncode == 0, restored.stdout + restored.stderr
