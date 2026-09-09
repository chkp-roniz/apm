"""Public CLI hook dispatch and lifecycle-lock regressions; never execute hooks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from apm_cli.adopt.provenance import hash_source
from apm_cli.cli import cli
from apm_cli.hook_contract import parse_hook_source
from apm_cli.install import locking

from .conftest import write

pytestmark = pytest.mark.component


@pytest.fixture
def hook_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep project writes and the real OS-user lifecycle lock hermetic."""
    root = tmp_path / "project"
    root.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(root)
    return root


@pytest.fixture(params=[("init", "--discover"), ("discover",)], ids=["primary", "alias"])
def entrypoint(request: pytest.FixtureRequest) -> tuple[str, ...]:
    return request.param


def _source(root: Path, hooks: dict[str, list[dict[str, str]]]) -> Path:
    """Author a per-file Copilot config on its public scanner path."""
    return write(root / ".github/hooks/check.json", json.dumps({"version": 1, "hooks": hooks}))


def test_cli_copilot_copies_and_records_safe_script(
    hook_project: Path, entrypoint: tuple[str, ...]
) -> None:
    """Classify -> native reader -> lexical copy -> provenance, not passthrough."""
    root = hook_project
    script = write(root / "scripts/check file.sh", "#!/bin/sh\ntouch executed\n")
    suffix = ' && echo "$HOME" > result.txt'
    source = _source(
        root,
        {"agentStop": [{"command": 'sh "${workspaceFolder}/scripts/check file.sh"' + suffix}]},
    )
    before = source.read_bytes(), script.read_bytes()
    result = CliRunner().invoke(
        cli, [*entrypoint, "--apply", "--yes", "--include-hook-scripts", "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["write"]["status"] == "complete"
    primary = "hooks/copilot-check-native.json"
    auxiliary = "hooks/copilot-check-native"
    copied = root / ".apm" / auxiliary / "scripts/scripts/check file.sh"
    assert set(report["write"]["written"]) == {primary, auxiliary}
    assert copied.read_bytes() == before[1]
    document = parse_hook_source(json.loads((root / ".apm" / primary).read_text()))
    assert [(item.event, item.command) for item in document.commands] == [
        ("Stop", 'sh "./copilot-check-native/scripts/scripts/check file.sh"' + suffix)
    ]
    records = json.loads((root / ".apm/.import-sources.json").read_text())["entries"]
    assert set(records) == {primary, auxiliary}
    for path, record in records.items():
        assert record["converter"] == "hooks->apm_hooks"
        assert record["primary"] == primary
        assert json.loads(record["identity"]) == [
            "copilot",
            "project",
            "hook",
            ".github/hooks/check.json",
        ]
        assert record["output_sha256"] == hash_source(root / ".apm" / path, root=root)
    assert (source.read_bytes(), script.read_bytes()) == before
    assert not (root / "executed").exists()
    assert not (root / "result.txt").exists()


@pytest.mark.parametrize(
    "unsafe",
    ["#!/bin/sh\necho \u202e\n", "#!/bin/sh\nTOKEN=" + "ghp_" + "A" * 40 + "\n"],
    ids=["security-gate", "recognizable-credential"],
)
def test_cli_copilot_refuses_unsafe_script(
    hook_project: Path, entrypoint: tuple[str, ...], unsafe: str
) -> None:
    """Unsafe executable bytes are refused even though passthrough could parse the hook."""
    script = write(hook_project / "scripts/check.sh", unsafe)
    source = _source(hook_project, {"agentStop": [{"command": "./scripts/check.sh"}]})
    before = source.read_bytes(), script.read_bytes()
    result = CliRunner().invoke(
        cli, [*entrypoint, "--apply", "--yes", "--include-hook-scripts", "--format", "json"]
    )
    assert result.exit_code == 1, result.output
    assert json.loads(result.stdout)["write"]["status"] == "partial"
    assert not (hook_project / ".apm/hooks/copilot-check-native.json").exists()
    assert not (hook_project / ".apm/hooks/copilot-check-native").exists()
    sidecar = hook_project / ".apm/.import-sources.json"
    assert not sidecar.exists() or not json.loads(sidecar.read_text())["entries"]
    assert "ghp_" + "A" * 40 not in result.stdout + result.stderr
    assert (source.read_bytes(), script.read_bytes()) == before


def test_cli_copilot_event_aliases_share_canonical_event(
    hook_project: Path, entrypoint: tuple[str, ...]
) -> None:
    """Native and neutral spellings keep both handlers under the canonical event."""
    source = _source(
        hook_project,
        {"Stop": [{"command": "echo first"}], "agentStop": [{"command": "echo second"}]},
    )
    before = source.read_bytes()
    result = CliRunner().invoke(cli, [*entrypoint, "--apply", "--yes", "--format", "json"])
    assert result.exit_code == 0, result.output
    output = json.loads((hook_project / ".apm/hooks/copilot-check-native.json").read_text())
    assert list(output["hooks"]) == ["Stop"]
    assert [(item.event, item.command) for item in parse_hook_source(output).commands] == [
        ("Stop", "echo first"),
        ("Stop", "echo second"),
    ]
    assert source.read_bytes() == before


@pytest.mark.parametrize("global_scope", [False, True], ids=["project", "user"])
@pytest.mark.parametrize("engine_code", [0, 1], ids=["success", "failure"])
def test_apply_entrypoints_acquire_one_lock_before_engine(
    hook_project: Path,
    entrypoint: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
    global_scope: bool,
    engine_code: int,
) -> None:
    """Both public callbacks acquire once before reads, and release on exit."""
    from apm_cli import adopt

    lock = locking.lifecycle_lock()
    original = locking.acquire_lifecycle_lock
    calls = []

    def acquire() -> Any:
        calls.append("acquire")
        return original()

    def engine(**kwargs: Any) -> int:
        calls.append("engine")
        assert calls == ["acquire", "engine"], "unlocked or nested lifecycle dispatch"
        assert lock.lock_counter == 1
        assert kwargs["project_root"] == hook_project
        assert kwargs["write"] is True
        assert kwargs["user_scope"] is global_scope
        return engine_code

    monkeypatch.setattr(locking, "acquire_lifecycle_lock", acquire)
    monkeypatch.setattr(adopt, "run_discover_command", engine)
    scope = ["--global"] if global_scope else []
    result = CliRunner().invoke(cli, [*entrypoint, "--apply", "--yes", *scope])
    assert result.exit_code == engine_code, result.exception
    assert calls == ["acquire", "engine"]
    assert lock.lock_counter == 0
