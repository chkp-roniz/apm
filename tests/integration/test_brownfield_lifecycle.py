"""Brownfield import, replay, consent and recovery contracts through the real CLI.

Runs the real CLI through ``ApmLifecycleRunner`` inside an ``IsolatedApmEnvironment``
with ``LifecycleStateSnapshot`` before/after captures. Boundary-fault and stdin
cases use the installed Python CLI entry point, not a packaged/frozen artifact:
the existing runner still owns process isolation, timeouts and captured streams.
"""

from __future__ import annotations

import json
import os
import stat
import textwrap
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import yaml

from apm_cli.integration.targets import KNOWN_TARGETS
from tests.utils.apm_lifecycle_runner import ApmLifecycleRunner, CommandResult
from tests.utils.isolated_apm_environment import IsolatedApmEnvironment
from tests.utils.lifecycle_state import LifecycleStateSnapshot

pytestmark = [
    pytest.mark.integration,
    pytest.mark.e2e,
    pytest.mark.lifecycle_smoke,
    pytest.mark.requires_apm_binary,
    pytest.mark.requires_e2e_mode,
]

_FAKE_TOKEN = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE12"
_APPLY_ARGS = ("init", "--discover", "--apply", "--yes", "--format", "json")

_ORIGINALS: dict[str, str] = {
    ".claude/rules/python.md": '---\npaths:\n  - "src/**/*.py"\n---\nUse type hints.\n',
    ".claude/agents/reviewer.md": (
        "---\nname: reviewer\ndescription: Reviews code\ntools: Read, Grep\ncolor: blue\n---\nYou review.\n"
    ),
    ".claude/commands/fix.md": "---\ndescription: Fix lint\n---\nRun the linter on $ARGUMENTS\n",
    ".claude/skills/deploy/SKILL.md": "---\nname: deploy\ndescription: Deploy\n---\n# Deploy\n",
    ".claude/hooks/notify.sh": "#!/bin/sh\necho hi\n",
    ".claude/settings.json": json.dumps(
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": '"$CLAUDE_PROJECT_DIR"/.claude/hooks/notify.sh',
                            }
                        ],
                    },
                    {
                        "matcher": "Write",
                        "hooks": [{"type": "command", "command": "echo apm-owned"}],
                        "_apm_source": "some-package",
                    },
                ]
            }
        },
        indent=2,
    ),
    ".mcp.json": json.dumps(
        {
            "mcpServers": {
                "fixture": {
                    "command": "printf",
                    "args": ["fixture"],
                    "env": {"FIXTURE_TOKEN": "${FIXTURE_TOKEN}", "MODE": "fast"},
                }
            }
        },
        indent=2,
    ),
    "CLAUDE.md": "# Project\nHand-authored notes for Claude.\n",
}

_IMPORTED: tuple[str, ...] = (
    ".apm/instructions/python.instructions.md",
    ".apm/instructions/claude-root.instructions.md",
    ".apm/agents/reviewer.agent.md",
    ".apm/prompts/fix.prompt.md",
    ".apm/skills/deploy/SKILL.md",
    ".apm/hooks/claude-native.json",
    ".apm/.import-sources.json",
)

_CURSOR_OUTPUTS: tuple[str, ...] = (
    ".cursor/rules/python.mdc",
    ".cursor/rules/claude-root.mdc",
    ".cursor/agents/reviewer.md",
    ".cursor/commands/fix.md",
    ".agents/skills/deploy/SKILL.md",
    ".cursor/hooks.json",
    ".cursor/mcp.json",
)


def _seed(project: Path, extra: dict[str, str] | None = None) -> None:
    for rel, content in {**_ORIGINALS, **(extra or {})}.items():
        path = project / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (project / ".cursor").mkdir(exist_ok=True)


def _snapshot(project: Path, *, imported: bool = True) -> LifecycleStateSnapshot:
    paths = (*_ORIGINALS, *_CURSOR_OUTPUTS, *(_IMPORTED if imported else ()))
    tracked = [PurePosixPath(p) for p in paths]
    return LifecycleStateSnapshot.capture(
        project, targets=("claude", "cursor"), config_paths=tracked
    )


def _evidence(result: CommandResult) -> str:
    return (
        f"command={result.command!r}\nreturncode={result.returncode}\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )


def _originals_unchanged(before: LifecycleStateSnapshot, after: LifecycleStateSnapshot) -> None:
    for rel in _ORIGINALS:
        assert after.file(rel).content == before.file(rel).content, f"{rel} was modified"
        assert after.file(rel).content is not None, f"{rel} disappeared"


def _scenario(
    tmp_path: Path, apm_binary_path: Path
) -> tuple[Path, dict[str, str], ApmLifecycleRunner]:
    isolated = IsolatedApmEnvironment.create(tmp_path / "scenario", base_env=dict(os.environ))
    environment = isolated.subprocess_env()
    environment["APM_E2E_TESTS"] = "1"
    environment["FIXTURE_TOKEN"] = "fixture-value"
    project = isolated.work_root / "project"
    project.mkdir()
    runner = ApmLifecycleRunner(
        (str(apm_binary_path),), timeout_seconds=120, scenario_timeout_seconds=600
    )
    return project, environment, runner


@pytest.mark.parametrize("target", ["cursor", "claude"], ids=["other-target", "source-target"])
def test_brownfield_preview_apply_install_rerun(
    tmp_path: Path, apm_binary_path: Path, target: str
) -> None:
    """Other targets preserve sources; source replay rewrites rules but protects collisions."""
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    _seed(project)
    before = _snapshot(project)

    preview = runner.run(
        ("init", "--discover", "--format", "json"),
        scenario_id="preview",
        cwd=project,
        env=environment,
    )
    assert preview.returncode == 0, _evidence(preview)
    inventory = json.loads(preview.stdout)
    assert inventory["schema_version"] == 1 and not inventory["apm_yml_exists"]
    assert not (project / ".apm").exists() and not (project / "apm.yml").exists()
    assert _snapshot(project) == before, "preview must not change any durable state"

    applied = runner.run(
        ("init", "--discover", "--apply", "--yes", "--format", "json"),
        scenario_id="apply",
        cwd=project,
        env=environment,
    )
    assert applied.returncode == 0, _evidence(applied)
    payload = json.loads(applied.stdout)
    assert payload["write"]["status"] == "complete", payload["write"]
    after_apply = _snapshot(project)
    _originals_unchanged(before, after_apply)
    for rel in _IMPORTED:
        assert after_apply.file(rel).content, f"{rel} missing after apply"
    provenance = json.loads(after_apply.file(".apm/.import-sources.json").content)
    written_files = {p for p in payload["write"]["written"] if not p.startswith("hooks/scripts/")}
    assert set(provenance["entries"]) == written_files
    manifest = yaml.safe_load(after_apply.manifest_bytes)
    assert manifest["targets"] == ["claude", "cursor"]
    assert [e["name"] for e in manifest["dependencies"]["mcp"]] == ["fixture"]
    assert "${FIXTURE_TOKEN}" in after_apply.manifest_bytes.decode("utf-8")
    assert after_apply.file(".apm/hooks/claude-native.json").content
    hooks = json.loads(after_apply.file(".apm/hooks/claude-native.json").content)
    commands = [h["command"] for e in hooks["hooks"]["PreToolUse"] for h in e["hooks"]]
    # Lexical conversion preserves quoting and excludes the APM-owned entry.
    assert commands == ['"./.claude/hooks/notify.sh"'], commands

    install_args = ("install", "--target", target, "--no-policy", "--parallel-downloads", "0")
    installed = runner.run(
        install_args, scenario_id=f"install-{target}", cwd=project, env=environment
    )
    assert installed.returncode == 0, _evidence(installed)
    after_install = _snapshot(project)
    if target == "cursor":
        _originals_unchanged(before, after_install)
        for rel in _CURSOR_OUTPUTS:
            assert after_install.file(rel).content, f"{rel} missing after install"
        rule = after_install.file(".cursor/rules/python.mdc").content.decode("utf-8")
        assert 'globs: "src/**/*.py"' in rule
        root_rule = after_install.file(".cursor/rules/claude-root.mdc").content.decode("utf-8")
        assert 'globs: "**"' in root_rule, "root context must stay always-on on Cursor"
        cursor_hooks = json.loads(after_install.file(".cursor/hooks.json").content)
        assert "echo apm-owned" not in json.dumps(cursor_hooks)
        mcp = json.loads(after_install.file(".cursor/mcp.json").content)
    else:
        rule = after_install.file(".claude/rules/python.md").content
        assert rule != before.file(".claude/rules/python.md").content
        assert b"Use type hints." in rule
        assert after_install.file(".claude/agents/reviewer.md") == before.file(
            ".claude/agents/reviewer.md"
        ), "an unowned native agent collision must not be replaced"
        assert after_install.file("CLAUDE.md") == before.file("CLAUDE.md"), (
            "the unmarked native root remains hand-authored"
        )
        mcp = json.loads(after_install.file(".mcp.json").content)
    assert "fixture" in mcp["mcpServers"]
    assert after_install.lockfile_bytes is not None
    lock = yaml.safe_load(after_install.lockfile_bytes)
    assert isinstance(lock, dict) and "dependencies" in lock

    rerun = runner.run(
        ("init", "--discover", "--apply", "--yes", "--format", "json"),
        scenario_id="rerun",
        cwd=project,
        env=environment,
    )
    assert rerun.returncode == 0, _evidence(rerun)
    if target == "cursor":
        assert json.loads(rerun.stdout)["write"]["written"] == []
    else:
        # Installing to the source changes the native settings document even
        # though reimporting its remaining hand-authored hooks emits identical
        # bytes. A provenance refresh here is not a new/duplicate primitive.
        assert set(json.loads(rerun.stdout)["write"]["written"]) <= {
            relative.removeprefix(".apm/") for relative in _IMPORTED
        }
    reinstalled = runner.run(
        install_args, scenario_id=f"reinstall-{target}", cwd=project, env=environment
    )
    assert reinstalled.returncode == 0, _evidence(reinstalled)
    after_rerun = _snapshot(project)
    assert after_rerun.manifest_bytes == after_install.manifest_bytes
    if target == "cursor":
        assert after_rerun.files == after_install.files, "rerun must be byte-idempotent"
        assert after_rerun.semantic_bytes == after_install.semantic_bytes
    else:
        assert [
            state
            for state in after_rerun.files
            if state.relative_path != ".apm/.import-sources.json"
        ] == [
            state
            for state in after_install.files
            if state.relative_path != ".apm/.import-sources.json"
        ]
        assert after_rerun.deployment_records == after_install.deployment_records
        settled = _full_snapshot(project)
        again = _apply(runner, project, environment)
        assert again.returncode == 0, _evidence(again)
        assert _machine(again)["write"]["written"] == []
        assert _full_snapshot(project) == settled


def test_brownfield_global_preview_apply_install_rerun(
    tmp_path: Path, apm_binary_path: Path
) -> None:
    """Global import/replay confines writes to HOME and settles without duplicate imports."""
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    home = Path(environment["HOME"])
    profile = KNOWN_TARGETS["claude"]
    # Cursor's user-scope rules are UI-only; replay the full fixture to Claude.
    assert all(profile.supports_at_user_scope(kind) for kind in profile.primitives)
    _seed(project)
    _write(project, "apm.yml", "name: invoking-project\nversion: 1.0.0\ntargets: [cursor]\n")
    _write(project, ".apm/instructions/local.instructions.md", "Project-only instructions.\n")
    home_originals = {
        **{rel: content for rel, content in _ORIGINALS.items() if rel.startswith(".claude/")},
        ".claude/CLAUDE.md": "# User\nHand-authored user context.\n",
        ".claude.json": _ORIGINALS[".mcp.json"],
    }
    sentinels = {
        "Documents/unrelated.txt": "Unrelated home content.\n",
        ".apm/personal-notes.txt": "Not an imported primitive or managed metadata.\n",
        ".claude/personal-notes.txt": "Not an APM deployment.\n",
        "CLAUDE.md": "An unmarked home-root file, not the user-context destination.\n",
    }
    for rel, content in {**home_originals, **sentinels}.items():
        _write(home, rel, content)
    (home / "Documents/empty").mkdir()
    project_before = _full_snapshot(project)
    home_before = _full_snapshot(home)

    def assert_preserved() -> None:
        """Check the invoking project and unrelated user-owned state after every command."""
        assert _full_snapshot(project) == project_before, "global command changed the project"
        for rel, content in sentinels.items():
            assert (home / rel).read_bytes() == content.encode("utf-8"), rel
        assert (home / "Documents/empty").is_dir()

    preview = runner.run(
        ("init", "--discover", "--global", "--format", "json"),
        scenario_id="global-preview",
        cwd=project,
        env=environment,
    )
    assert preview.returncode == 0, _evidence(preview)
    inventory = json.loads(preview.stdout)
    assert inventory["scopes"] == ["user"] and not inventory["apm_yml_exists"]
    assert "~/.claude/CLAUDE.md" in {finding["path"] for finding in inventory["findings"]}
    assert _full_snapshot(home) == home_before, "global preview changed durable HOME state"
    assert_preserved()

    applied = _apply(runner, project, environment, "--global")
    assert applied.returncode == 0, _evidence(applied)
    payload = _machine(applied)
    assert payload["write"]["status"] == "complete", payload
    assert_preserved()
    for rel, content in home_originals.items():
        assert (home / rel).read_bytes() == content.encode("utf-8"), rel
    imports = {
        "instructions/python.instructions.md": b"Use type hints.",
        "instructions/claude-root.instructions.md": b"Hand-authored user context.",
        "agents/reviewer.agent.md": b"You review.",
        "prompts/fix.prompt.md": b"Run the linter",
        "skills/deploy/SKILL.md": b"# Deploy",
        "hooks/claude-native.json": b"PreToolUse",
    }
    apm_home = home / ".apm"
    for rel, content in imports.items():
        assert content in (apm_home / rel).read_bytes(), rel
    source_context = (apm_home / "instructions/claude-root.instructions.md").read_text(
        encoding="utf-8"
    )
    assert yaml.safe_load(source_context.split("---", 2)[1])["applyTo"] == "**"
    # Skills are committed/provenance-tracked as whole trees, not as SKILL.md alone.
    destinations = {rel.removesuffix("/SKILL.md") for rel in imports}
    assert set(payload["write"]["written"]) == destinations
    provenance = json.loads((apm_home / ".import-sources.json").read_bytes())
    assert set(provenance["entries"]) == destinations
    manifest_bytes = (apm_home / "apm.yml").read_bytes()
    manifest = yaml.safe_load(manifest_bytes)
    assert manifest["targets"] == [profile.name]
    assert [server["name"] for server in manifest["dependencies"]["mcp"]] == ["fixture"]
    assert b"${FIXTURE_TOKEN}" in manifest_bytes
    assert not (home / "apm.yml").exists()
    assert not (apm_home / ".apm").exists(), "global primitives belong directly under ~/.apm"

    install_args = (
        "install",
        "--global",
        "--target",
        profile.name,
        "--no-policy",
        "--parallel-downloads",
        "0",
    )
    installed = runner.run(install_args, scenario_id="global-install", cwd=project, env=environment)
    assert installed.returncode == 0, _evidence(installed)
    assert_preserved()
    assert b"Use type hints." in (home / ".claude/rules/python.md").read_bytes()
    assert b"Hand-authored user context." in (home / ".claude/rules/claude-root.md").read_bytes()
    deployed_context = (home / ".claude/rules/claude-root.md").read_text(encoding="utf-8")
    assert yaml.safe_load(deployed_context.split("---", 2)[1])["paths"] == ["**"]
    for rel in (
        ".claude/agents/reviewer.md",
        ".claude/CLAUDE.md",
    ):
        assert (home / rel).read_bytes() == home_originals[rel].encode("utf-8"), rel
    # The actual native reviewer destination is an unowned collision, not a new file.
    assert not (home / ".claude/agents/agents-reviewer.md").exists()
    assert (home / ".claude/skills/deploy/SKILL.md").read_bytes() == (
        apm_home / "skills/deploy/SKILL.md"
    ).read_bytes()
    assert b"Run the linter" in (home / ".claude/commands/fix.md").read_bytes()
    assert "fixture" in json.loads((home / ".claude.json").read_bytes())["mcpServers"]
    lockfile = apm_home / "apm.lock.yaml"
    from apm_cli.deps.lockfile import LockFile

    lock = LockFile.read(lockfile)
    assert lock is not None
    assert lock.deployment_ledger.records, "global local deployment ownership must persist"
    assert ".claude/rules/python.md" in lock.local_deployed_files
    assert ".claude/rules/claude-root.md" in lock.local_deployed_files
    assert ".claude/rules/python.md" in lock.local_deployed_file_hashes
    assert ".claude/agents/reviewer.md" not in lock.local_deployed_files, (
        "a preserved native collision must not become APM-owned"
    )
    assert not (home / "apm.lock.yaml").exists()
    assert (apm_home / "apm.yml").read_bytes() == manifest_bytes

    # Source-target installation can refresh native settings/provenance once.
    # It must not allocate another primitive, and the next full cycle must settle.
    rerun = _apply(runner, project, environment, "--global")
    assert rerun.returncode == 0, _evidence(rerun)
    assert set(_machine(rerun)["write"]["written"]) <= destinations
    assert_preserved()
    reinstalled = runner.run(
        install_args, scenario_id="global-reinstall", cwd=project, env=environment
    )
    assert reinstalled.returncode == 0, _evidence(reinstalled)
    assert_preserved()
    assert (apm_home / "apm.yml").read_bytes() == manifest_bytes
    settled = _full_snapshot(home)
    again = _apply(runner, project, environment, "--global")
    assert again.returncode == 0, _evidence(again)
    assert _machine(again)["write"]["written"] == []
    assert _full_snapshot(home) == settled, "settled global apply must be byte-idempotent"
    assert_preserved()
    final_install = runner.run(
        install_args, scenario_id="global-settled-install", cwd=project, env=environment
    )
    assert final_install.returncode == 0, _evidence(final_install)
    assert _full_snapshot(home) == settled, "settled global install must be byte-idempotent"
    assert_preserved()

    stale = home / ".claude/rules/python.md"
    edited = home / ".claude/rules/claude-root.md"
    edited_bytes = edited.read_bytes() + b"\nPreserve this local user edit.\n"
    edited.write_bytes(edited_bytes)
    (apm_home / "instructions/python.instructions.md").unlink()
    (apm_home / "instructions/claude-root.instructions.md").unlink()

    contracted = runner.run(
        install_args, scenario_id="global-remove-imports", cwd=project, env=environment
    )
    assert contracted.returncode == 0, _evidence(contracted)
    assert not stale.exists(), "removed unchanged user deployment must be cleaned"
    assert edited.read_bytes() == edited_bytes, "local user edits must survive contraction"
    assert_preserved()
    contracted_lock = LockFile.read(lockfile)
    assert contracted_lock is not None
    assert ".claude/rules/python.md" not in contracted_lock.local_deployed_files
    assert ".claude/rules/claude-root.md" in contracted_lock.local_deployed_files
    assert (
        contracted_lock.local_deployed_file_hashes[".claude/rules/claude-root.md"]
        == (lock.local_deployed_file_hashes[".claude/rules/claude-root.md"])
    ), "preserved edits must retain the original deployment witness"
    contracted_snapshot = _full_snapshot(home)
    repeated_contraction = runner.run(
        install_args, scenario_id="global-repeat-removal", cwd=project, env=environment
    )
    assert repeated_contraction.returncode == 0, _evidence(repeated_contraction)
    assert _full_snapshot(home) == contracted_snapshot
    assert_preserved()


def test_brownfield_partial_apply_is_unmistakable(tmp_path: Path, apm_binary_path: Path) -> None:
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    _seed(project, {".claude/rules/leaky.md": f"Use {_FAKE_TOKEN} in CI.\n"})
    before = _snapshot(project)

    applied = runner.run(
        ("init", "--discover", "--apply", "--yes", "--format", "json"),
        scenario_id="partial-apply",
        cwd=project,
        env=environment,
    )
    assert applied.returncode == 1, _evidence(applied)
    payload = json.loads(applied.stdout)
    assert payload["write"]["status"] == "partial"
    failed = {f["path"]: f["reason"] for f in payload["write"]["failed"]}
    assert "github-token" in failed[".claude/rules/leaky.md"]
    assert _FAKE_TOKEN not in applied.stdout and _FAKE_TOKEN not in applied.stderr
    after = _snapshot(project)
    _originals_unchanged(before, after)
    assert not (project / ".apm/instructions/leaky.instructions.md").exists()
    assert after.file(".apm/instructions/python.instructions.md").content
    provenance = json.loads(after.file(".apm/.import-sources.json").content)
    for rel in provenance["entries"]:
        assert (project / ".apm" / rel).exists(), f"provenance names a missing import {rel}"
    assert _FAKE_TOKEN not in b"".join(
        p.read_bytes() for p in (project / ".apm").rglob("*") if p.is_file()
    ).decode("utf-8", errors="ignore")


def test_brownfield_failed_apply_rolls_back(tmp_path: Path, apm_binary_path: Path) -> None:
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    _seed(project)
    (project / ".apm").write_text("a file blocks the import directory\n", encoding="utf-8")
    before = _snapshot(project, imported=False)

    applied = runner.run(
        ("init", "--discover", "--apply", "--yes", "--format", "json"),
        scenario_id="failed-apply",
        cwd=project,
        env=environment,
    )
    assert applied.returncode == 1, _evidence(applied)
    payload = json.loads(applied.stdout)
    assert payload["write"]["status"] == "failed"
    after = _snapshot(project, imported=False)
    _originals_unchanged(before, after)
    assert (project / ".apm").is_file()
    assert not (project / "apm.yml").exists()
    assert after.manifest_bytes is None and after.lockfile_bytes is None


def _write(project: Path, relative: str, content: str) -> Path:
    """Plant a bounded fixture without importing any production writer."""
    path = project / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _full_snapshot(project: Path) -> LifecycleStateSnapshot:
    """Track every project entry, including hidden/empty directories, without following links.

    The parent is the capture root so malformed or symlinked apm.yml fixtures
    are opaque config entries rather than inputs to the snapshot YAML parser.
    Modes are asserted separately: LifecycleStateSnapshot does not record them.
    """
    paths = [PurePosixPath(project.name)]
    for directory, dirs, files in os.walk(project, followlinks=False):
        for name in dirs + files:
            paths.append(
                PurePosixPath((Path(directory) / name).relative_to(project.parent).as_posix())
            )
    return LifecycleStateSnapshot.capture(project.parent, config_paths=paths)


def _machine(result: CommandResult, fmt: str = "json") -> dict[str, Any]:
    """Parse exactly one machine document, leaving prompts and plans on stderr."""
    assert result.stdout.strip(), _evidence(result)
    if fmt == "json":
        payload = json.loads(result.stdout)
    else:
        documents = list(yaml.safe_load_all(result.stdout))
        assert len(documents) == 1, _evidence(result)
        payload = documents[0]
    assert isinstance(payload, dict) and isinstance(payload.get("write"), dict), _evidence(result)
    assert "Traceback" not in result.stderr, _evidence(result)
    return payload


def _apply(
    runner: ApmLifecycleRunner, project: Path, environment: dict[str, str], *extra: str
) -> CommandResult:
    """Run the public apply command; never call the materializer in process."""
    return runner.run(
        (*_APPLY_ARGS, *extra), scenario_id="brownfield-apply", cwd=project, env=environment
    )


def _engine_runner(apm_engine_command: tuple[str, ...], setup: str) -> ApmLifecycleRunner:
    """Instrument only a boundary in the installed CLI, following lifecycle fault conventions."""
    entrypoint = (
        "import os, sys, io\n"
        "from pathlib import Path\n"
        "from apm_cli.cli import cli\n"
        "import apm_cli.adopt.materialize as materialize\n" + textwrap.dedent(setup) + "\ncli()\n"
    )
    return ApmLifecycleRunner((apm_engine_command[0], "-c", entrypoint), timeout_seconds=120)


_STDIN_SETUP = """
class ControlledInput(io.StringIO):
    def isatty(self):
        return os.environ.get("W5_TTY") == "1"
    def readline(self, *args, **kwargs):
        edit = os.environ.get("W5_PROMPT_EDIT")
        if edit:
            Path(edit).write_text("local edit while deciding\\n", encoding="utf-8")
            print("W5: prompt edit made", file=sys.stderr)
        return super().readline(*args, **kwargs)
sys.stdin = ControlledInput(os.environ.get("W5_ANSWER", ""))
"""


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_brownfield_cleanup_failure_is_not_reported_as_success(
    tmp_path: Path, apm_binary_path: Path, apm_engine_command: tuple[str, ...], fmt: str
) -> None:
    project, environment, _runner = _scenario(tmp_path, apm_binary_path)
    _write(project, ".claude/rules/python.md", "Preserve completed output.\n")
    runner = _engine_runner(
        apm_engine_command,
        """
        original_cleanup = materialize.safe_rmtree
        def denied_cleanup(path, *args, **kwargs):
            if Path(path).name.startswith(".apm-adopt-"):
                raise PermissionError("contained cleanup denied")
            return original_cleanup(path, *args, **kwargs)
        materialize.safe_rmtree = denied_cleanup
        """,
    )
    result = _apply(runner, project, environment, "--format", fmt)
    assert result.returncode == 1, _evidence(result)
    write = _machine(result, fmt)["write"]
    assert write["status"] == "failed"
    assert "cleanup failed" in write["reason"]
    assert write["written"]
    assert write["recovery"] != "restored"
    assert (project / ".apm/instructions/python.instructions.md").is_file()
    assert list(project.glob(".apm-adopt-*"))


@pytest.mark.parametrize(
    "change",
    [
        "edit",
        "add",
        "remove",
        "hidden",
        pytest.param(
            "mode",
            marks=pytest.mark.skipif(os.name == "nt", reason="POSIX executable-bit contract"),
        ),
    ],
)
def test_brownfield_skill_local_change_blocks_refresh(
    tmp_path: Path, apm_binary_path: Path, change: str
) -> None:
    """A changed source cannot erase any kind of local skill-tree customization."""
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    source = _write(
        project, ".claude/skills/deploy/SKILL.md", _ORIGINALS[".claude/skills/deploy/SKILL.md"]
    )
    _write(project, ".claude/skills/deploy/helper.sh", "#!/bin/sh\necho original\n").chmod(0o644)
    first = _apply(runner, project, environment)
    assert first.returncode == 0, _evidence(first)
    adopted = project / ".apm/skills/deploy"
    helper = adopted / "helper.sh"
    if change == "edit":
        helper.write_text("#!/bin/sh\necho local\n", encoding="utf-8")
    elif change == "add":
        _write(adopted, "notes.md", "local notes\n")
    elif change == "remove":
        helper.unlink()
    elif change == "hidden":
        _write(adopted, ".local/notes", "hidden local notes\n")
        (adopted / ".empty").mkdir()
    else:
        helper.chmod(0o755)
    source.write_text(source.read_text(encoding="utf-8") + "Changed upstream.\n", encoding="utf-8")
    before = _full_snapshot(project)
    mode_before = stat.S_IMODE(helper.stat().st_mode) if helper.exists() else None

    refresh = _apply(runner, project, environment)

    assert _full_snapshot(project) == before, "protected skill refresh changed durable state"
    if helper.exists():
        assert stat.S_IMODE(helper.stat().st_mode) == mode_before
    assert refresh.returncode == 1, _evidence(refresh)
    payload = _machine(refresh)
    assert payload["write"]["status"] == "partial", payload
    assert payload["write"]["written"] == []
    assert ".claude/skills/deploy" in json.dumps(payload["write"]), payload


def test_brownfield_legacy_empty_tree_hash_is_not_refresh_authority(
    tmp_path: Path, apm_binary_path: Path
) -> None:
    """An old empty directory digest cannot authorize replacing an unverified tree."""
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    source = _write(
        project, ".claude/skills/deploy/SKILL.md", _ORIGINALS[".claude/skills/deploy/SKILL.md"]
    )
    first = _apply(runner, project, environment)
    assert first.returncode == 0, _evidence(first)
    sidecar = project / ".apm/.import-sources.json"
    recorded = json.loads(sidecar.read_text(encoding="utf-8"))["entries"]["skills/deploy"]
    legacy = {key: recorded[key] for key in ("source", "scope", "converter", "source_sha256")}
    legacy["output_sha256"] = ""
    sidecar.write_text(
        json.dumps({"version": 1, "entries": {"skills/deploy": legacy}}), encoding="utf-8"
    )
    _write(project, ".apm/skills/deploy/local.md", "unverified legacy customization\n")
    source.write_text(source.read_text(encoding="utf-8") + "Upstream changed.\n", encoding="utf-8")
    before = _full_snapshot(project)

    refresh = _apply(runner, project, environment)

    assert _full_snapshot(project) == before
    assert refresh.returncode == 1, _evidence(refresh)
    assert _machine(refresh)["write"]["status"] == "partial"


def _source_destinations(project: Path) -> dict[str, str]:
    """Read the durable source attribution, not the optional public write.items field."""
    entries = json.loads((project / ".apm/.import-sources.json").read_text(encoding="utf-8"))[
        "entries"
    ]
    return {record["source"]: destination for destination, record in entries.items()}


@pytest.mark.parametrize("churn", ["insert", "remove", "reorder"])
def test_brownfield_collision_churn_retains_source_destinations(
    tmp_path: Path, apm_binary_path: Path, apm_engine_command: tuple[str, ...], churn: str
) -> None:
    """Colliding sources keep their established destinations even when an owner disappears."""
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    first_source = ".claude/rules/a-b.md"
    second_source = ".claude/rules/a/b.md"
    _write(project, first_source, "First owner.\n")
    _write(project, second_source, "Second owner.\n")
    first = _apply(runner, project, environment)
    assert first.returncode == 0, _evidence(first)
    established = _source_destinations(project)
    assert set(established) == {first_source, second_source}
    assert len(set(established.values())) == 2
    first_bytes = (project / ".apm" / established[first_source]).read_bytes()
    _write(project, second_source, "Second owner changed upstream.\n")
    if churn == "insert":
        # Sorts before both originals, but flattens to the same a-b stem.
        _write(project, ".claude/rules/a b.md", "Inserted owner.\n")
    elif churn == "remove":
        (project / first_source).unlink()
    else:
        # Permute real discovered findings, not converter decisions or filesystem I/O.
        runner = _engine_runner(
            apm_engine_command,
            """
            import dataclasses
            import apm_cli.adopt as adopt
            original_discover = adopt.discover
            def reversed_discover(*args, **kwargs):
                report = original_discover(*args, **kwargs)
                return dataclasses.replace(report, findings=tuple(reversed(report.findings)))
            adopt.discover = reversed_discover
        """,
        )

    refresh = _apply(runner, project, environment)

    assert refresh.returncode == 0, _evidence(refresh)
    destinations = _source_destinations(project)
    assert {source: destinations[source] for source in established} == established
    assert (project / ".apm" / established[first_source]).read_bytes() == first_bytes
    assert (
        b"Second owner changed upstream."
        in (project / ".apm" / established[second_source]).read_bytes()
    )
    if churn == "insert":
        assert destinations[".claude/rules/a b.md"] not in established.values()
        assert (
            b"Inserted owner."
            in (project / ".apm" / destinations[".claude/rules/a b.md"]).read_bytes()
        )


_LATE_FAULT_SETUP = """
def after_replacement():
    target = Path(os.environ["W5_REPLACED_PATH"])
    assert b"upstream replacement" in target.read_bytes(), "fault must follow actual replacement"
    print("W5: replacement observed before late fault", file=sys.stderr)

if os.environ["W5_LATE_FAULT"] == "manifest":
    original_manifest = materialize.apply_manifest_delta
    def fail_manifest(*args, **kwargs):
        result = original_manifest(*args, **kwargs)
        if not kwargs.get("dry_run", False):
            after_replacement()
            raise OSError("W5 late manifest write failure")
        return result
    materialize.apply_manifest_delta = fail_manifest
else:
    original_save = materialize.ImportSources.save
    def fail_provenance(self, *args, **kwargs):
        result = original_save(self, *args, **kwargs)
        after_replacement()
        raise OSError("W5 late provenance write failure")
    materialize.ImportSources.save = fail_provenance

if os.environ.get("W5_FAIL_RESTORE") == "1":
    def fail_restore(*args, **kwargs):
        print("W5: automatic restore attempted", file=sys.stderr)
        raise PermissionError("W5 restore destination denied")
    materialize._restore_destination = fail_restore
"""


def _refresh_fixture(
    project: Path, environment: dict[str, str], runner: ApmLifecycleRunner
) -> None:
    """Import old bytes, then arrange a real file refresh and a real manifest delta."""
    _write(project, ".claude/rules/python.md", "Original adopted rule.\n")
    first = _apply(runner, project, environment)
    assert first.returncode == 0, _evidence(first)
    _write(project, ".claude/rules/python.md", "New upstream replacement.\n")
    _write(
        project,
        ".mcp.json",
        json.dumps({"mcpServers": {"late": {"command": "printf", "args": ["inert"]}}}),
    )
    environment["W5_REPLACED_PATH"] = str(project / ".apm/instructions/python.instructions.md")


@pytest.mark.parametrize("fault", ["manifest", "provenance"])
def test_brownfield_late_refresh_failure_automatically_restores_snapshot(
    tmp_path: Path, apm_binary_path: Path, apm_engine_command: tuple[str, ...], fault: str
) -> None:
    """A failure after replacing adopted bytes restores files, manifest and provenance."""
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    _refresh_fixture(project, environment, runner)
    before = _full_snapshot(project)
    environment["W5_LATE_FAULT"] = fault

    failed = _apply(_engine_runner(apm_engine_command, _LATE_FAULT_SETUP), project, environment)

    assert "W5: replacement observed before late fault" in failed.stderr, _evidence(failed)
    assert failed.returncode == 1, _evidence(failed)
    assert _machine(failed)["write"]["status"] == "failed"
    assert _full_snapshot(project) == before, (
        "automatic rollback did not restore the entire project"
    )


@pytest.mark.parametrize("fmt", ["text", "json", "yaml"])
def test_brownfield_incomplete_rollback_reports_recovery_truthfully(
    tmp_path: Path, apm_binary_path: Path, apm_engine_command: tuple[str, ...], fmt: str
) -> None:
    """A denied restore is not reported as successful rollback and retains recoverable bytes."""
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    _refresh_fixture(project, environment, runner)
    old_bytes = Path(environment["W5_REPLACED_PATH"]).read_bytes()
    environment.update(W5_LATE_FAULT="provenance", W5_FAIL_RESTORE="1")

    failed = _engine_runner(apm_engine_command, _LATE_FAULT_SETUP).run(
        ("init", "--discover", "--apply", "--yes", "--format", fmt),
        scenario_id=f"incomplete-recovery-{fmt}",
        cwd=project,
        env=environment,
    )

    assert "W5: replacement observed before late fault" in failed.stderr, _evidence(failed)
    assert "W5: automatic restore attempted" in failed.stderr, _evidence(failed)
    assert failed.returncode == 1, _evidence(failed)
    affected = {
        ".apm/instructions/python.instructions.md",
        "apm.yml",
        ".apm/.import-sources.json",
    }
    recovery_dirs = list(project.glob(".apm-adopt-*"))
    assert len(recovery_dirs) == 1
    recovery_dir = recovery_dirs[0]
    assert recovery_dir.is_dir() and not recovery_dir.is_symlink()
    assert not Path(environment["W5_REPLACED_PATH"]).exists()
    manifest = yaml.safe_load((project / "apm.yml").read_bytes())
    assert "late" in {server["name"] for server in manifest["dependencies"]["mcp"]}
    if fmt == "text":
        combined = failed.stdout + failed.stderr
        assert "output state is unknown" in combined
        assert "Retained recovery directory" in combined and recovery_dir.name in combined
        assert all(path in combined for path in affected)
    else:
        receipt = _machine(failed, fmt)["write"]
        assert receipt["status"] == "failed"
        assert receipt["recovery"] == "incomplete"
        assert receipt["state_known"] is False
        assert receipt["written"] == []
        assert receipt["manifest_updated"] is None
        assert receipt["mcp_imported"] is None
        assert set(receipt["affected"]) == affected
        assert receipt["recovery_directory"] == recovery_dir.name
    assert "all changes were rolled back" not in failed.stderr.lower()
    backups = [
        path
        for path in project.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path != Path(environment["W5_REPLACED_PATH"])
        and path.read_bytes() == old_bytes
    ]
    assert backups, "failed recovery must retain safely contained original bytes"


@pytest.mark.parametrize("fmt", ["json", "yaml"])
@pytest.mark.parametrize(
    ("answer", "tty", "expected_status", "expected_exit"),
    [
        pytest.param("yes\n", True, "complete", 0, id="affirmative"),
        pytest.param("no\n", True, "cancelled", 0, id="negative"),
        pytest.param("\n", True, "cancelled", 0, id="blank"),
        pytest.param("", True, "cancelled", 0, id="eof"),
        pytest.param("yes\n", False, "refused", 1, id="non-tty"),
    ],
)
def test_brownfield_consent_has_one_machine_document(
    tmp_path: Path,
    apm_binary_path: Path,
    apm_engine_command: tuple[str, ...],
    fmt: str,
    answer: str,
    tty: bool,
    expected_status: str,
    expected_exit: int,
) -> None:
    """Consent is read from controlled stdin; no prompt or answer pollutes machine stdout."""
    project, environment, _runner = _scenario(tmp_path, apm_binary_path)
    _write(project, ".claude/rules/python.md", "Use type hints.\n")
    before = _full_snapshot(project)
    environment.update(W5_TTY="1" if tty else "0", W5_ANSWER=answer)
    result = _engine_runner(apm_engine_command, _STDIN_SETUP).run(
        ("init", "--discover", "--apply", "--format", fmt),
        scenario_id=f"consent-{fmt}",
        cwd=project,
        env=environment,
    )

    assert result.returncode == expected_exit, _evidence(result)
    payload = _machine(result, fmt)
    assert payload["write"]["status"] == expected_status
    if tty:
        assert "[y/N]" in result.stderr and "[y/N]" not in result.stdout
    else:
        assert "--yes" in result.stderr and "[y/N]" not in result.stderr
    if expected_status == "complete":
        assert (project / ".apm/instructions/python.instructions.md").is_file()
        assert (project / "apm.yml").is_file()
        assert (project / ".apm/.import-sources.json").is_file()
    else:
        assert _full_snapshot(project) == before
        assert payload["write"]["written"] == []


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_brownfield_each_mcp_warning_precedes_consent_without_secrets(
    tmp_path: Path, apm_binary_path: Path, apm_engine_command: tuple[str, ...], fmt: str
) -> None:
    """A safe second server must not erase the first server's credential-setup warning."""
    project, environment, _runner = _scenario(tmp_path, apm_binary_path)
    _write(
        project,
        ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "a-needs-token": {
                        "command": "printf",
                        "env": {"W5_SERVICE_TOKEN": _FAKE_TOKEN},
                    },
                    "z-safe": {"command": "printf", "args": ["inert"]},
                }
            }
        ),
    )
    environment.update(W5_TTY="1", W5_ANSWER="yes\n")
    result = _engine_runner(apm_engine_command, _STDIN_SETUP).run(
        ("init", "--discover", "--apply", "--format", fmt),
        scenario_id=f"mcp-consent-{fmt}",
        cwd=project,
        env=environment,
    )

    assert result.returncode == 0, _evidence(result)
    payload = _machine(result, fmt)
    assert payload["write"]["status"] == "complete"
    assert _FAKE_TOKEN not in result.stdout and _FAKE_TOKEN not in result.stderr
    plan, prompt, _tail = result.stderr.partition("[y/N]")
    assert prompt, _evidence(result)
    assert "a-needs-token" in plan and "z-safe" in plan
    manifest = (project / "apm.yml").read_text(encoding="utf-8")
    assert _FAKE_TOKEN not in manifest
    entries = {entry["name"]: entry for entry in yaml.safe_load(manifest)["dependencies"]["mcp"]}
    placeholder = entries["a-needs-token"]["env"]["W5_SERVICE_TOKEN"]
    assert placeholder.startswith("${A_NEEDS_TOKEN_W5_SERVICE_TOKEN_")
    assert placeholder.endswith("}")
    assert entries["z-safe"]["args"] == ["inert"]
    assert placeholder[2:-1] in plan and "export" in plan.lower(), plan


def test_brownfield_prompt_time_edit_is_rechecked_before_replace(
    tmp_path: Path, apm_binary_path: Path, apm_engine_command: tuple[str, ...]
) -> None:
    """Approval cannot authorize overwriting bytes edited after the plan was prepared."""
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    _write(project, ".claude/rules/python.md", "Original rule.\n")
    first = _apply(runner, project, environment)
    assert first.returncode == 0, _evidence(first)
    _write(project, ".claude/rules/python.md", "Changed upstream rule.\n")
    destination = project / ".apm/instructions/python.instructions.md"
    original = destination.read_bytes()
    destination.write_text("local edit while deciding\n", encoding="utf-8")
    expected = _full_snapshot(project)
    destination.write_bytes(original)
    environment.update(W5_TTY="1", W5_ANSWER="yes\n", W5_PROMPT_EDIT=str(destination))

    result = _engine_runner(apm_engine_command, _STDIN_SETUP).run(
        ("init", "--discover", "--apply", "--format", "json"),
        scenario_id="prompt-time-edit",
        cwd=project,
        env=environment,
    )

    assert "W5: prompt edit made" in result.stderr, _evidence(result)
    assert _full_snapshot(project) == expected
    assert result.returncode == 1, _evidence(result)
    assert _machine(result)["write"]["status"] == "partial"


def test_brownfield_auxiliary_script_edit_blocks_associated_hook_refresh(
    tmp_path: Path, apm_binary_path: Path
) -> None:
    """The hook and its copied script are one protected refresh, not independent outputs."""
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    _write(project, ".claude/hooks/notify.sh", "#!/bin/sh\nprintf original\n").chmod(0o755)
    settings = _write(project, ".claude/settings.json", _ORIGINALS[".claude/settings.json"])
    first = _apply(runner, project, environment, "--include-hook-scripts")
    assert first.returncode == 0, _evidence(first)
    scripts = list((project / ".apm/hooks").rglob("notify.sh"))
    assert len(scripts) == 1
    scripts[0].write_text("#!/bin/sh\nprintf locally-edited\n", encoding="utf-8")
    native = json.loads(settings.read_text(encoding="utf-8"))
    native["hooks"]["PreToolUse"][0]["matcher"] = "Read"
    settings.write_text(json.dumps(native), encoding="utf-8")
    before = _full_snapshot(project)

    refresh = _apply(runner, project, environment, "--include-hook-scripts")

    assert _full_snapshot(project) == before, "edited script must protect its associated hook too"
    assert refresh.returncode == 1, _evidence(refresh)
    assert _machine(refresh)["write"]["status"] == "partial"


_FORBID_OUTSIDE_IO = """
# Observe actual OS-level Python opens/enumeration, without replacing the reader
# under test. resolve/readlink is allowed for admission, outside content is not.
blocked = Path(os.environ["W5_OUTSIDE"]).resolve()
def audit(event, args):
    if event not in ("open", "os.scandir", "os.listdir"):
        return
    candidate = args[0]
    if isinstance(candidate, (str, bytes, os.PathLike)):
        path = Path(os.fsdecode(candidate))
        # open's audit event omits dir_fd: a relative cleanup name is not
        # necessarily relative to cwd. All fixture readers use absolute Paths.
        if not path.is_absolute():
            return
        resolved = path.resolve()
        if resolved == blocked or blocked in resolved.parents:
            print("W5: forbidden outside I/O attempted", file=sys.stderr)
            raise PermissionError("W5 outside fixture access forbidden")
sys.addaudithook(audit)
"""


@pytest.mark.parametrize("endpoint", ["apm-directory", "manifest", "provenance"])
def test_brownfield_unsafe_output_endpoint_refuses_before_outside_io(
    tmp_path: Path, apm_binary_path: Path, apm_engine_command: tuple[str, ...], endpoint: str
) -> None:
    """Redirected mutable endpoints cannot become an authority to read or write outside scope."""
    project, environment, _runner = _scenario(tmp_path, apm_binary_path)
    _write(project, ".claude/rules/python.md", "Safe source.\n")
    outside = project.parent / "outside"
    _write(outside, "sentinel.txt", "outside untouched\n")
    if endpoint == "apm-directory":
        (project / ".apm").symlink_to(outside, target_is_directory=True)
    elif endpoint == "manifest":
        manifest = _write(outside, "manifest.yml", "name: outside\nversion: 1.0.0\n")
        (project / "apm.yml").symlink_to(manifest)
    else:
        sidecar = _write(outside, "provenance.json", '{"version": 1, "entries": {}}')
        (project / ".apm").mkdir()
        (project / ".apm/.import-sources.json").symlink_to(sidecar)
    before, outside_before = _full_snapshot(project), _full_snapshot(outside)
    environment["W5_OUTSIDE"] = str(outside)

    result = _apply(_engine_runner(apm_engine_command, _FORBID_OUTSIDE_IO), project, environment)

    assert "W5: forbidden outside I/O attempted" not in result.stderr, _evidence(result)
    assert _full_snapshot(outside) == outside_before
    assert _full_snapshot(project) == before
    assert result.returncode == 1, _evidence(result)
    assert _machine(result)["write"]["status"] == "failed"


@pytest.mark.parametrize("source", ["ancestor", "settings"])
def test_brownfield_escaped_source_is_never_read(
    tmp_path: Path, apm_binary_path: Path, apm_engine_command: tuple[str, ...], source: str
) -> None:
    """Scope admission rejects source ancestors and native settings before their content is read."""
    project, environment, _runner = _scenario(tmp_path, apm_binary_path)
    outside = project.parent / "outside"
    _write(outside, "rules/private.md", "Outside private content.\n")
    settings = _write(
        outside, "settings.json", '{"hooks":{"PreToolUse":[{"command":"echo inert"}]}}'
    )
    if source == "ancestor":
        (project / ".claude").symlink_to(outside, target_is_directory=True)
    else:
        (project / ".claude").mkdir()
        (project / ".claude/settings.json").symlink_to(settings)
    before, outside_before = _full_snapshot(project), _full_snapshot(outside)
    environment["W5_OUTSIDE"] = str(outside)

    result = _apply(_engine_runner(apm_engine_command, _FORBID_OUTSIDE_IO), project, environment)

    assert "W5: forbidden outside I/O attempted" not in result.stderr, _evidence(result)
    assert _full_snapshot(outside) == outside_before
    assert _full_snapshot(project) == before
    assert result.returncode == 1, _evidence(result)
    assert _machine(result)["write"]["status"] == "partial"


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_brownfield_malformed_manifest_has_structured_preparation_failure(
    tmp_path: Path, apm_binary_path: Path, fmt: str
) -> None:
    """Invalid existing configuration fails through the machine envelope without durable writes."""
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    _write(project, ".claude/rules/python.md", "Use type hints.\n")
    _write(project, "apm.yml", "name: [unterminated\n")
    before = _full_snapshot(project)

    result = runner.run(
        ("init", "--discover", "--apply", "--yes", "--format", fmt),
        scenario_id=f"malformed-manifest-{fmt}",
        cwd=project,
        env=environment,
    )

    assert _full_snapshot(project) == before
    assert result.returncode == 1, _evidence(result)
    assert _machine(result, fmt)["write"]["status"] == "failed"


def test_brownfield_reference_only_plan_makes_no_writes(
    tmp_path: Path, apm_binary_path: Path
) -> None:
    """Excluded native permission maps remain reference-only, not an empty package creation."""
    project, environment, runner = _scenario(tmp_path, apm_binary_path)
    _write(
        project,
        ".opencode/agents/reviewer.md",
        "---\ndescription: Review\ntools:\n  read: true\n  write: false\n---\nReview.\n",
    )
    before = _full_snapshot(project)

    result = _apply(runner, project, environment)

    assert result.returncode == 0, _evidence(result)
    payload = _machine(result)
    assert payload["write"]["status"] == "complete"
    assert payload["write"]["written"] == []
    assert _full_snapshot(project) == before
