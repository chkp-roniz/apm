"""Local deployment persistence uses the same ledger in project and user scope."""

from pathlib import Path
from unittest.mock import patch

import pytest

from apm_cli.adopt.model import Scope
from apm_cli.adopt.ownership import OwnershipIndex
from apm_cli.core.deployment_ledger import DeploymentLedgerCodec
from apm_cli.core.scope import InstallScope
from apm_cli.deps.lockfile import LockFile, get_lockfile_path
from apm_cli.install.context import InstallContext
from apm_cli.install.phases import post_deps_local
from apm_cli.install.phases.lockfile import compute_deployed_hashes
from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.utils.diagnostics import DiagnosticCollector


@pytest.fixture(params=[InstallScope.PROJECT, InstallScope.USER], ids=["project", "global"])
def ctx(request: pytest.FixtureRequest, tmp_path: Path) -> InstallContext:
    scope = request.param
    root = tmp_path / "deploy"
    root.mkdir()
    apm_dir = root / ".apm" if scope is InstallScope.USER else root
    apm_dir.mkdir(exist_ok=True)
    return InstallContext(
        scope=scope,
        project_root=root,
        apm_dir=apm_dir,
        targets=[KNOWN_TARGETS["claude"].for_scope(user_scope=scope is InstallScope.USER)],
        diagnostics=DiagnosticCollector(),
    )


def _write(ctx: InstallContext, rel: str, content: str = "Deployed content.\n") -> None:
    path = ctx.project_root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_local_files_persist_as_owned_hashed_deployments(ctx: InstallContext) -> None:
    files = [
        ".claude/agents/reviewer.md",
        ".claude/commands/fix.md",
        ".claude/rules/python.md",
        ".claude/skills/deploy/SKILL.md",
    ]
    for rel in files:
        _write(ctx, rel)
    DeploymentLedgerCodec.replace_context_local_files(ctx, files)
    lock_path = get_lockfile_path(ctx.apm_dir)
    post_deps_local.run(ctx)

    lock = LockFile.read(lock_path)
    assert lock is not None
    assert lock.local_deployed_files == sorted(files)
    assert lock.local_deployed_file_hashes == compute_deployed_hashes(files, ctx.project_root)
    assert set(DeploymentLedgerCodec.legacy_deployed_file_claims(lock)) == set(files)
    assert lock.deployment_ledger.records
    scope = Scope.USER if ctx.scope is InstallScope.USER else Scope.PROJECT
    index = OwnershipIndex.build(ctx.project_root, scope)
    assert index.lockfile_present
    assert index.managed_files == frozenset(files)
    assert index.file_hashes == lock.local_deployed_file_hashes
    if ctx.scope is InstallScope.USER:
        assert not (ctx.project_root / "apm.lock.yaml").exists()

    before = lock_path.read_bytes()
    ctx.old_local_deployed = list(lock.local_deployed_files)
    with patch.object(LockFile, "save", wraps=lock.save) as save:
        post_deps_local.run(ctx)
    save.assert_not_called()
    assert lock_path.read_bytes() == before


def test_local_cleanup_preserves_edits_and_unmanaged_paths(ctx: InstallContext) -> None:
    stale = ".claude/rules/stale.md"
    edited = ".claude/rules/edited.md"
    unmanaged = "Documents/notes.md"
    collision = ".claude/agents/personal.md"
    for rel in (stale, edited, unmanaged, collision):
        _write(ctx, rel)
    files = [stale, edited, unmanaged]
    hashes = compute_deployed_hashes(files, ctx.project_root)
    lock = LockFile()
    DeploymentLedgerCodec.replace_legacy_owner(lock, ".", files, hashes)
    lock_path = get_lockfile_path(ctx.apm_dir)
    lock.save(lock_path)
    _write(ctx, edited, "User changed this.\n")
    ctx.old_local_deployed = files

    post_deps_local.run(ctx)

    assert not (ctx.project_root / stale).exists()
    assert (ctx.project_root / edited).read_text() == "User changed this.\n"
    assert (ctx.project_root / unmanaged).read_text() == "Deployed content.\n"
    assert (ctx.project_root / collision).read_text() == "Deployed content.\n"
    persisted = LockFile.read(lock_path)
    assert persisted is not None
    assert stale not in persisted.local_deployed_files
    assert edited in persisted.local_deployed_files
    assert persisted.local_deployed_file_hashes[edited] == hashes[edited]
    assert collision not in persisted.local_deployed_files


def test_local_cleanup_retains_prior_files_on_integration_errors(ctx: InstallContext) -> None:
    stale = ".claude/rules/stale.md"
    _write(ctx, stale)
    lock = LockFile()
    DeploymentLedgerCodec.replace_legacy_owner(
        lock, ".", [stale], compute_deployed_hashes([stale], ctx.project_root)
    )
    lock_path = get_lockfile_path(ctx.apm_dir)
    lock.save(lock_path)
    before = lock_path.read_bytes()
    ctx.old_local_deployed = [stale]
    # An error recorded after the local integration baseline makes this run untrusted.
    ctx.diagnostics.error("Local primitive integration failed")

    post_deps_local.run(ctx)

    assert (ctx.project_root / stale).is_file()
    assert ctx.local_deployed_files == [stale]
    assert lock_path.read_bytes() == before


def test_local_cleanup_does_not_follow_escaping_parent_symlinks(ctx: InstallContext) -> None:
    outside = ctx.project_root.parent / "outside"
    outside.mkdir()
    sentinel = outside / "notes.md"
    sentinel.write_text("User-owned outside content.\n")
    rules = ctx.project_root / ".claude/rules"
    rules.mkdir(parents=True)
    (rules / "linked").symlink_to(outside, target_is_directory=True)
    files = [".claude/rules/linked/notes.md", "../outside/notes.md"]
    lock = LockFile()
    DeploymentLedgerCodec.replace_legacy_owner(lock, ".", files, {})
    lock.save(get_lockfile_path(ctx.apm_dir))
    ctx.old_local_deployed = files

    post_deps_local.run(ctx)

    assert sentinel.read_text() == "User-owned outside content.\n"
    assert (rules / "linked").is_symlink()


@pytest.mark.parametrize(
    "target_servers", [{}, {"claude": ["fixture"]}], ids=["explicit-empty", "owned-server"]
)
def test_local_persistence_preserves_existing_mcp_metadata(
    ctx: InstallContext, target_servers: dict[str, list[str]]
) -> None:
    lock = LockFile(
        mcp_servers=["fixture"],
        mcp_configs={"fixture": {"command": "printf", "args": ["fixture"]}},
    )
    DeploymentLedgerCodec.replace_mcp_target_servers(lock, target_servers)
    lock_path = get_lockfile_path(ctx.apm_dir)
    lock.save(lock_path)
    rel = ".claude/rules/local.md"
    _write(ctx, rel)
    DeploymentLedgerCodec.replace_context_local_files(ctx, [rel])

    post_deps_local.run(ctx)

    persisted = LockFile.read(lock_path)
    assert persisted is not None
    assert persisted.local_deployed_files == [rel]
    assert persisted.mcp_servers == lock.mcp_servers
    assert persisted.mcp_configs == lock.mcp_configs
    assert persisted.mcp_target_servers == target_servers
    assert persisted._mcp_target_servers_present


def test_empty_local_phase_does_not_create_metadata(ctx: InstallContext) -> None:
    post_deps_local.run(ctx)
    assert not get_lockfile_path(ctx.apm_dir).exists()
