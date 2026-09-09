"""Disk-backed mutation proof for the importer provenance authority."""

from __future__ import annotations

import ast
import os
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
ALLOCATOR = "src/apm_cli/adopt/converters/base.py"
GUARD = "scripts/architecture_linter/checks/contracts_import_provenance.py"
BEHAVIOR = "tests/unit/adopt/test_import_provenance.py"
BOUNDARY = "tests/integration/test_architecture_import_provenance.py"


def test_import_provenance_owner_boundary() -> None:
    """The live registry and registered guard must accept the working tree."""
    result = run_selected_rules(ROOT, (RULE_ID,))
    assert result.failures == ()
    assert result.violations == ()


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
    ],
)
def test_import_provenance_mutations_on_disk(tmp_path: Path, path: str, old: str, new: str) -> None:
    """An actual edited file must trigger this guard, not an unrelated failure."""
    paths = (OWNER, MATERIALIZE, ALLOCATOR)
    for relative in paths:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8")
    rule = next(rule for rule in registered_rules() if rule.id == RULE_ID)
    assert rule.check(FactsProvider(tmp_path, paths, registry=None)) == ()
    target = tmp_path / path
    original = target.read_text(encoding="utf-8")
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
            GUARD,
            "if not condition:",
            "if False and not condition:",
            BOUNDARY + "::test_import_provenance_mutations_on_disk[reserve-recorded-destinations]",
            id="boundary-assertion",
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
        BEHAVIOR,
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
