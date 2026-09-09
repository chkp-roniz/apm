"""Source credential regressions through the installed Python CLI, not Click mocks.

Despite the unit/ location requested for these follow-ups, every case crosses a
real process boundary. The shared lifecycle harness isolates HOME and blocks IP
network access; credentials below are deliberately synthetic.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.utils.apm_lifecycle_runner import ApmLifecycleRunner, CommandResult
from tests.utils.isolated_apm_environment import IsolatedApmEnvironment

from .conftest import write

pytestmark = pytest.mark.e2e

_TOKEN = "ghp_" + "A1b2" * 9
_MAX_BYTES = 1024 * 1024
_ROOT_DEST = ".apm/instructions/claude-root.instructions.md"
_SKILL_SOURCE = ".claude/skills/asset-demo"
_SKILL_DEST = ".apm/skills/asset-demo"


@pytest.fixture
def source_cli(tmp_path: Path) -> tuple[Path, dict[str, str], ApmLifecycleRunner]:
    """Reuse the hermetic runner with the interpreter owning the editable install."""
    isolated = IsolatedApmEnvironment.create(tmp_path / "scenario", base_env=dict(os.environ))
    project = isolated.work_root / "project"
    project.mkdir()
    env = isolated.subprocess_env()
    env["APM_E2E_TESTS"] = "1"
    runner = ApmLifecycleRunner(
        (sys.executable, "-c", "from apm_cli.cli import cli; cli()"),
        timeout_seconds=60,
    )
    return project, env, runner


def _apply(
    scenario: tuple[Path, dict[str, str], ApmLifecycleRunner], fmt: str = "json"
) -> CommandResult:
    """Exercise discovery, conversion, reporting and the actual copy transaction."""
    project, env, runner = scenario
    return runner.run(
        ("init", "--discover", "--apply", "--yes", "--format", fmt),
        scenario_id="source-credential-followup",
        cwd=project,
        env=env,
    )


def _write_report(result: CommandResult, fmt: str) -> dict[str, Any]:
    """Require exactly one machine document on stdout."""
    if fmt == "json":
        payload = json.loads(result.stdout)
    else:
        documents = list(yaml.safe_load_all(result.stdout))
        assert len(documents) == 1
        payload = documents[0]
    return payload["write"]


def _assert_no_leak(result: CommandResult, project: Path) -> None:
    """Neither stream nor any durable import/manifest may contain the source token."""
    assert _TOKEN not in result.stdout
    assert _TOKEN not in result.stderr
    assert _TOKEN not in "".join(result.stdout.split())
    assert _TOKEN not in "".join(result.stderr.split())
    assert "Traceback" not in result.stderr
    outputs = list((project / ".apm").rglob("*"))
    outputs.append(project / "apm.yml")
    for path in outputs:
        if path.is_file():
            assert _TOKEN.encode("ascii") not in path.read_bytes(), path.name


@pytest.mark.parametrize("fmt", ["json", "yaml", "text"])
@pytest.mark.parametrize("location", ["absolute", "escaping", "missing"])
def test_cli_refuses_root_source_before_lossy_rewrites(
    source_cli: tuple[Path, dict[str, str], ApmLifecycleRunner], fmt: str, location: str
) -> None:
    """Source credentials cannot disappear into dropped import references."""
    project, _, _ = source_cli
    sections = {
        "absolute": f"@/private/{_TOKEN}\n",
        "escaping": f"@../{_TOKEN}\n",
        "missing": f"@missing/{_TOKEN}\n",
    }
    source = write(project / "CLAUDE.md", "# Project\nKeep useful notes.\n" + sections[location])
    original = source.read_bytes()

    result = _apply(source_cli, fmt)

    _assert_no_leak(result, project)
    assert result.returncode == 1
    assert source.read_bytes() == original
    assert not (project / _ROOT_DEST).exists()
    if fmt != "text":
        report = _write_report(result, fmt)
        assert report["status"] == "partial"
        assert report["written"] == []
        assert len(report["failed"]) == 1
        assert report["failed"][0]["path"] == "CLAUDE.md"
        assert "possible github-token" in report["failed"][0]["reason"]
        assert "redact it first" in report["failed"][0]["reason"]
    else:
        assert "github-token" in result.stdout + result.stderr
        assert "redact it first" in " ".join((result.stdout + result.stderr).split())


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_cli_import_changes_use_ordinals_not_source_values(
    source_cli: tuple[Path, dict[str, str], ApmLifecycleRunner], fmt: str
) -> None:
    """Every branch records a field identifier, including paths below token thresholds."""
    project, _, _ = source_cli
    targets = [
        "/private/local-key",
        "~/personal-key",
        "../outside-key",
        "missing-key",
        "safe.md",
        "alias.md",
    ]
    write(project / "safe.md", "# Safe reference\n")
    (project / "alias.md").symlink_to(project / "safe.md")
    source = write(
        project / "CLAUDE.md",
        "# Project\nKeep useful notes.\n" + "".join(f"@{t}\n" for t in targets),
    )
    original = source.read_bytes()

    result = _apply(source_cli, fmt)

    assert result.returncode == 0
    report = _write_report(result, fmt)
    changes = [c for c in report["items"][0]["changes"] if c["path"].startswith("body.import[")]
    assert [c["path"] for c in changes] == [f"body.import[{i}]" for i in range(1, 7)]
    assert [c["action"] for c in changes] == [
        "dropped",
        "dropped",
        "dropped",
        "dropped",
        "transformed",
        "dropped",
    ]
    for target in targets:
        assert target not in json.dumps(changes)
        assert target not in result.stderr
    assert "See [safe.md](safe.md)." in (project / _ROOT_DEST).read_text(encoding="utf-8")
    assert source.read_bytes() == original


@pytest.mark.parametrize("fmt", ["json", "yaml"])
@pytest.mark.parametrize("placement", ["nul-prefix", "sample-boundary", "tail", "high-bit"])
def test_cli_refuses_ascii_credentials_in_binary_skill_assets(
    source_cli: tuple[Path, dict[str, str], ApmLifecycleRunner], fmt: str, placement: str
) -> None:
    """A NUL sample must not exempt copied bytes, even past the old 8192-byte sample."""
    project, _, _ = source_cli
    write(
        project / f"{_SKILL_SOURCE}/SKILL.md",
        "---\nname: asset-demo\ndescription: Safe skill\n---\n# Asset demo\n",
    )
    token = _TOKEN.encode("ascii")
    assets = {
        "nul-prefix": b"\x00" + token,
        "sample-boundary": b"\x00" * (8192 - 8) + token + b"\x00",
        "tail": b"\x00" * (_MAX_BYTES - len(token)) + token,
        "high-bit": b"\x00\xc3\xa9" + token + b"\xff",
    }
    source = project / f"{_SKILL_SOURCE}/asset.bin"
    source.write_bytes(assets[placement])

    result = _apply(source_cli, fmt)

    _assert_no_leak(result, project)
    assert result.returncode == 1
    report = _write_report(result, fmt)
    assert report["status"] == "partial"
    assert report["written"] == []
    assert len(report["failed"]) == 1
    assert report["failed"][0]["path"] == _SKILL_SOURCE
    assert "possible github-token" in report["failed"][0]["reason"]
    assert not (project / _SKILL_DEST).exists()
    assert source.read_bytes() == assets[placement]


def test_cli_preserves_safe_binary_skill_assets_byte_for_byte(
    source_cli: tuple[Path, dict[str, str], ApmLifecycleRunner],
) -> None:
    """Preserve binary support without joining non-ASCII-separated fragments into a token."""
    project, _, _ = source_cli
    write(
        project / f"{_SKILL_SOURCE}/SKILL.md",
        "---\nname: asset-demo\ndescription: Safe skill\n---\n# Asset demo\n",
    )
    assets = {
        "empty.bin": b"",
        "image.bin": bytes(range(256)) * 50,
        "limit.bin": b"\x00" * _MAX_BYTES,
        "placeholder.bin": b"\x00${GITHUB_TOKEN}\xff",
        "fragments.bin": b"\x00ghp_" + b"A1b2" * 4 + b"\xff" + b"A1b2" * 5,
    }
    for name, content in assets.items():
        (project / _SKILL_SOURCE / name).write_bytes(content)

    result = _apply(source_cli)

    assert result.returncode == 0
    report = _write_report(result, "json")
    assert report["status"] == "complete"
    assert report["failed"] == []
    for name, content in assets.items():
        assert (project / _SKILL_DEST / name).read_bytes() == content
        assert (project / _SKILL_SOURCE / name).read_bytes() == content


def test_cli_refuses_oversized_binary_skill_asset(
    source_cli: tuple[Path, dict[str, str], ApmLifecycleRunner],
) -> None:
    """Binary support must not remove the existing per-file admission bound."""
    project, _, _ = source_cli
    write(
        project / f"{_SKILL_SOURCE}/SKILL.md",
        "---\nname: asset-demo\ndescription: Safe skill\n---\n# Asset demo\n",
    )
    source = project / f"{_SKILL_SOURCE}/asset.bin"
    source.write_bytes(b"\x00" * (_MAX_BYTES + 1))

    result = _apply(source_cli)

    assert result.returncode == 1
    report = _write_report(result, "json")
    assert report["status"] == "partial"
    assert report["written"] == []
    # Provenance admission rejects oversize trees before the converter runs.
    assert len(report["failed"]) == 1
    assert report["failed"][0]["path"] == _SKILL_SOURCE
    assert report["failed"][0]["reason"] == (
        "cannot verify import source or destination (ValueError)"
    )
    assert not (project / _SKILL_DEST).exists()
