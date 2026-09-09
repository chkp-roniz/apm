"""Optional native import conformance tests for PR #2857 requirements."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from apm_cli.adopt.converters import ConvertContext, ConvertResult
from apm_cli.adopt.converters.hooks import HooksConverter
from apm_cli.adopt.model import Finding, HarnessKind, Importability, Ownership, Scope
from apm_cli.adopt.redact import Redactor
from apm_cli.adopt.registry import ScanContext
from apm_cli.adopt.scanners.mcp import McpScanner
from apm_cli.cli import cli
from apm_cli.core.deployment_ledger import DeploymentLedgerCodec
from apm_cli.core.scope import InstallScope
from apm_cli.deps.lockfile import LockFile, get_lockfile_path
from apm_cli.factory import ClientFactory
from apm_cli.install.context import InstallContext
from apm_cli.install.mcp import ownership as mcp_ownership
from apm_cli.install.phases import post_deps_local
from apm_cli.install.phases.lockfile import compute_deployed_hashes
from apm_cli.integration.hook_integrator import HookIntegrator
from apm_cli.integration.targets import KNOWN_TARGETS
from apm_cli.models.apm_package import APMPackage, PackageInfo
from apm_cli.models.dependency.mcp import MCPDependency
from apm_cli.utils.diagnostics import DiagnosticCollector
from tests.spec_conformance._helpers import load_json_fixture

pytestmark = pytest.mark.component

BASELINE_MCP: dict[str, Any] = {
    "name": "shared",
    "registry": False,
    "transport": "stdio",
    "command": "echo",
    "args": ["managed"],
}


def _write(path: Path, text: str) -> Path:
    """Write UTF-8 text after creating parents."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _bytes(root: Path) -> dict[str, bytes]:
    """Return stable bytes for all regular files below *root*."""
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def _seed_import_project(root: Path) -> dict[str, bytes]:
    """Create native import sources that include rules, hooks, scripts and MCP."""
    _write(
        root / ".cursor/rules/global.mdc",
        "---\ndescription: Global\nglobs: src/**\nalwaysApply: true\n---\nUse strict types.\n",
    )
    _write(root / "scripts/check.py", "print('hook command must not execute')\n")
    _write(
        root / ".claude/settings.json",
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Write",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": 'python "$CLAUDE_PROJECT_DIR/scripts/check.py"',
                                }
                            ],
                        }
                    ]
                }
            },
            indent=2,
        ),
    )
    _write(
        root / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "shared": {
                        "command": "python",
                        "args": ["-c", "raise SystemExit('must not execute')"],
                    }
                }
            },
            indent=2,
        ),
    )
    return _bytes(root)


def _block_process_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if import discovery tries to execute native commands."""

    def fail_process(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("native import executed a process")

    monkeypatch.setattr(subprocess, "run", fail_process)
    monkeypatch.setattr(subprocess, "Popen", fail_process)


def _json_run(root: Path, args: list[str]) -> dict[str, Any]:
    """Run the Click CLI in-process and parse stdout as JSON."""
    result = CliRunner().invoke(cli, args)
    assert result.stdout, result.output
    payload = json.loads(result.stdout)
    payload["_exit_code"] = result.exit_code
    return payload


@pytest.mark.req("req-pr-008")
def test_native_import_preview_is_non_mutating_and_identifies_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Preview reports source path, tool, primitive kind and scope without writes."""
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.chdir(root)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    before = _seed_import_project(root)
    _block_process_execution(monkeypatch)

    payload = _json_run(root, ["init", "--discover", "--format", "json"])

    assert payload["_exit_code"] == 0
    by_path = {item["path"]: item for item in payload["findings"]}
    assert by_path[".cursor/rules/global.mdc"]["tool"] == "cursor"
    assert by_path[".cursor/rules/global.mdc"]["kind"] == "rule"
    assert by_path[".cursor/rules/global.mdc"]["scope"] == "project"
    assert by_path[".claude/settings.json"]["tool"] == "claude"
    assert by_path[".claude/settings.json"]["kind"] == "hook"
    assert by_path[".mcp.json#shared"]["kind"] == "mcp-server"
    assert _bytes(root) == before
    assert not (root / ".apm").exists()
    assert not (root / "apm.yml").exists()


@pytest.mark.req("req-pr-008")
def test_native_import_preview_identifies_user_scope_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apm_cli.utils import version_checker

    home = tmp_path / "home"
    project = tmp_path / "project"
    project.mkdir()
    _write(home / ".claude/agents/helper.md", "---\ndescription: Helper\n---\nHelp.\n")
    before = _bytes(home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(project)
    monkeypatch.setattr(version_checker, "should_check_for_updates", lambda: False)
    _block_process_execution(monkeypatch)

    payload = _json_run(project, ["init", "--discover", "--global", "--format", "json"])

    assert payload["_exit_code"] == 0
    finding = next(f for f in payload["findings"] if f["path"] == "~/.claude/agents/helper.md")
    assert (finding["tool"], finding["kind"], finding["scope"]) == ("claude", "agent", "user")
    assert _bytes(home) == before
    assert _bytes(project) == {}


@pytest.mark.req("req-pr-008")
@pytest.mark.parametrize(
    ("monkey_tty", "stdin", "expected_status"),
    [(False, "", "refused"), (True, "n\n", "cancelled")],
    ids=["no-tty-refusal", "interactive-cancel"],
)
def test_native_import_requires_opt_in_and_discloses_warnings_before_consent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    monkey_tty: bool,
    stdin: str,
    expected_status: str,
) -> None:
    """Apply without consent writes nothing while the machine report includes losses."""
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.chdir(root)
    before = _seed_import_project(root)
    _block_process_execution(monkeypatch)
    if monkey_tty:
        from apm_cli.adopt import materialize

        monkeypatch.setattr(materialize, "_stdin_is_tty", lambda: True)

    result = CliRunner().invoke(
        cli, ["init", "--discover", "--apply", "--format", "json"], input=stdin
    )
    payload = json.loads(result.stdout)

    assert result.exit_code == (0 if expected_status == "cancelled" else 1)
    assert payload["write"]["status"] == expected_status
    assert payload["write"]["written"] == []
    assert _bytes(root) == before
    warning_changes = [
        change
        for item in payload["write"]["items"]
        for change in item["changes"]
        if change["severity"] == "warning"
    ]
    assert warning_changes
    if monkey_tty:
        plan, prompt, _tail = result.stderr.partition("[y/N]")
        assert prompt, result.stderr
        assert "alwaysApply is not preserved" in plan, plan
        assert ".cursor/rules/global.mdc" in plan, plan


@pytest.mark.req("req-pr-008")
def test_native_import_success_preserves_sources_and_does_not_deploy_or_approve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Successful import preserves original bytes and creates no install state."""
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.chdir(root)
    before = _seed_import_project(root)
    _block_process_execution(monkeypatch)

    result = CliRunner().invoke(cli, ["init", "--discover", "--apply", "--yes", "--format", "json"])
    payload = json.loads(result.stdout)
    after = _bytes(root)

    assert result.exit_code == 0, result.output
    assert payload["write"]["status"] == "complete"
    assert ".apm/instructions/global.instructions.md" in after
    assert ".apm/hooks/claude-native.json" in after
    assert "apm.yml" in after
    for rel, content in before.items():
        assert after[rel] == content
    manifest = yaml.safe_load((root / "apm.yml").read_text(encoding="utf-8"))
    assert "allowExecutables" not in manifest
    assert "executables" not in manifest
    assert not (root / "apm.lock.yaml").exists()
    assert not any(rel.startswith(".claude/hooks/") for rel in after)


def _hook_finding(tool: str, payload: dict[str, Any], *, format_id: str | None = None) -> Finding:
    """Return a host-owned native hook finding for direct converter tests."""
    return Finding(
        id=f"{tool}-hook",
        tool=tool,
        scope=Scope.PROJECT,
        kind=HarnessKind.HOOK,
        display_path=f"{tool}.json",
        importability=Importability.CONVERTIBLE,
        ownership=Ownership.HOST_OWNED,
        converter_id="hooks->apm_hooks",
        payload=payload,
        format_id=format_id,
    )


def _convert_hooks(root: Path, finding: Finding, *, copy_scripts: bool = False) -> ConvertResult:
    """Convert native hooks through the maintained HooksConverter."""
    ctx = ConvertContext(root, Scope.PROJECT, Redactor(root), include_hook_scripts=copy_scripts)
    return HooksConverter().convert(finding, root / ".apm/hooks/native.json", ctx=ctx)


@pytest.mark.req("req-pr-009")
def test_native_hook_import_preserves_alias_order_matcher_timeout_and_script_spans(
    tmp_path: Path,
) -> None:
    """Gemini native hooks round-trip through APM and the Gemini renderer."""
    _write(tmp_path / "scripts/check.py", "print('ok')\n")
    fixture = load_json_fixture("optional-import", "native-hook-gemini.json")
    payload = fixture["source"]
    expected_neutral = fixture["expected_neutral"]
    expected_native = fixture["expected_native"]

    result = _convert_hooks(tmp_path, _hook_finding("gemini", payload))
    hook_file = tmp_path / ".apm/hooks/native.json"
    neutral = json.loads(hook_file.read_text(encoding="utf-8"))

    assert result.written == [hook_file]
    entries = neutral["hooks"][expected_neutral["event"]]
    assert [entry["matcher"] for entry in entries] == expected_neutral["matchers"]
    commands = [handler["command"] for entry in entries for handler in entry["hooks"]]
    assert commands == expected_neutral["commands"]
    assert entries[0]["hooks"][0]["timeout"] == expected_neutral["timeout_seconds"]

    package = PackageInfo(package=APMPackage(name="local", version="1.0.0"), install_path=tmp_path)
    project = tmp_path / "target"
    (project / ".gemini").mkdir(parents=True)
    HookIntegrator().integrate_hooks_for_target(KNOWN_TARGETS["gemini"], package, project)
    native = json.loads((project / ".gemini/settings.json").read_text(encoding="utf-8"))
    native_entries = native["hooks"][expected_native["event"]]
    assert [entry["matcher"] for entry in native_entries] == expected_native["matchers"]
    assert native_entries[0]["hooks"][0]["timeout"] == expected_native["timeout_milliseconds"]


@pytest.mark.req("req-pr-009")
@pytest.mark.parametrize(
    ("payload", "format_id"),
    [
        ({"hooks": {"PreToolUse": [{"hooks": [{"command": "echo ok"}]}]}}, "future_hooks"),
        ({"hooks": {"PreToolUse": [{"hooks": [{"type": "prompt", "prompt": "ask"}]}]}}, None),
        (
            {
                "hooks": {
                    "PreToolUse": [
                        {"hooks": [{"command": 'sh "$CLAUDE_PROJECT_DIR/scripts/$NAME.sh"'}]}
                    ]
                }
            },
            None,
        ),
    ],
    ids=["unknown-format", "non-command-handler", "dynamic-script"],
)
def test_unrepresentable_native_hooks_nonconvert_without_writes_or_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, Any],
    format_id: str | None,
) -> None:
    """Unsupported native hook input produces no APM hook or auxiliary script."""
    _block_process_execution(monkeypatch)
    _write(tmp_path / "scripts/name.sh", "#!/bin/sh\nexit 0\n")

    result = _convert_hooks(
        tmp_path, _hook_finding("claude", payload, format_id=format_id), copy_scripts=True
    )

    assert result.skipped_reason
    assert result.written == []
    assert not (tmp_path / ".apm").exists()


class _FakeAdapter:
    """Small MCP adapter double used only behind the canonical factory."""

    mcp_servers_key = "mcpServers"

    def __init__(
        self,
        config_path: Path,
        servers: dict[str, dict[str, Any]],
        rendered: dict[str, Any],
        *,
        legacy_path: Path | None = None,
        legacy_servers: dict[str, dict[str, Any]] | None = None,
        legacy_error: Exception | None = None,
    ) -> None:
        self.config_path = config_path
        self.servers = servers
        self.rendered = rendered
        self.legacy_path = legacy_path
        self.legacy_servers = legacy_servers
        self.legacy_error = legacy_error
        self.native_reads: list[bool] = []

    def get_config_path(self) -> str:
        """Return the current native config path."""
        return str(self.config_path)

    def get_legacy_config_path(self) -> str | None:
        """Return the legacy native config path."""
        return str(self.legacy_path) if self.legacy_path is not None else None

    def get_legacy_current_config(self) -> dict[str, Any]:
        return {self.mcp_servers_key: self.get_native_server_configs(legacy=True)}

    def get_native_server_configs(self, **kwargs: Any) -> dict[str, dict[str, Any]]:
        """Return fake native servers after recording current/legacy reads."""
        self.native_reads.append(bool(kwargs.get("legacy")))
        if kwargs.get("legacy"):
            if self.legacy_error is not None:
                raise self.legacy_error
            return self.legacy_servers or {}
        return self.servers

    def render_server_config(self, _server: object, **_kwargs: Any) -> dict[str, Any]:
        """Return the runtime's canonical rendering for the stored baseline."""
        return dict(self.rendered)


def _baseline_render(root: Path) -> dict[str, Any]:
    """Render the baseline with the real Claude adapter."""
    adapter = ClientFactory.create_client("claude", project_root=root)
    dependency = MCPDependency.from_dict(dict(BASELINE_MCP))
    return adapter.render_server_config(HooklessMCP.build(dependency))


class HooklessMCP:
    """Isolate the canonical self-defined info call for type checkers."""

    @staticmethod
    def build(dependency: MCPDependency) -> object:
        """Build the same info object used by the canonical MCP resolver."""
        from apm_cli.integration.mcp_integrator import MCPIntegrator

        return MCPIntegrator._build_self_defined_info(dependency)


@pytest.mark.req("req-pr-010")
def test_mcp_import_ownership_is_runtime_and_scope_bound(tmp_path: Path) -> None:
    """Recorded ownership is target-specific, scope-specific and not name-only."""
    project_lock = LockFile()
    project_lock.mcp_servers = ["shared"]
    project_lock.mcp_configs = {"shared": dict(BASELINE_MCP)}
    DeploymentLedgerCodec.replace_mcp_target_servers(project_lock, {"claude": ["shared"]})
    project_lock.write(tmp_path / "apm.lock.yaml")

    user_dir = tmp_path / ".apm"
    user_dir.mkdir()
    user_lock = LockFile()
    user_lock.mcp_servers = ["shared"]
    user_lock.mcp_configs = {"shared": dict(BASELINE_MCP)}
    DeploymentLedgerCodec.replace_mcp_target_servers(user_lock, {"cursor": ["shared"]})
    user_lock.write(user_dir / "apm.lock.yaml")

    from apm_cli.adopt.model import RawFinding
    from apm_cli.adopt.ownership import OwnershipIndex

    def raw(tool: str, scope: Scope) -> RawFinding:
        return RawFinding(
            tool, scope, HarnessKind.MCP_SERVER, f"{tool}#shared", payload={"name": "shared"}
        )

    project_index = OwnershipIndex.build(tmp_path, Scope.PROJECT)
    user_index = OwnershipIndex.build(tmp_path, Scope.USER)
    assert project_index.decide(raw("claude", Scope.PROJECT))[0] is Ownership.APM_OWNED
    assert project_index.decide(raw("cursor", Scope.PROJECT))[0] is Ownership.HOST_OWNED
    assert project_index.decide(raw("claude", Scope.USER))[0] is Ownership.HOST_OWNED
    assert user_index.decide(raw("cursor", Scope.USER))[0] is Ownership.APM_OWNED


@pytest.mark.req("req-pr-010")
def test_mcp_explicit_empty_target_map_disables_legacy_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An explicit empty ownership map is authoritative."""
    monkeypatch.setattr(
        mcp_ownership,
        "adopt_legacy_mcp_target_servers",
        lambda **_kwargs: pytest.fail("explicit empty map invoked fallback inference"),
    )

    result = mcp_ownership.resolve_mcp_target_servers(
        recorded_target_servers={},
        ownership_present=True,
        server_names={"shared"},
        stored_configs={"shared": dict(BASELINE_MCP)},
        project_root=tmp_path,
        user_scope=False,
        approved_root=tmp_path,
    )

    assert result == {}


@pytest.mark.req("req-pr-010")
def test_mcp_legacy_inference_requires_exact_canonical_runtime_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing target maps can infer ownership only from exact rendered config."""
    expected = _baseline_render(tmp_path)
    matching = _FakeAdapter(tmp_path / "claude.json", {"shared": expected}, expected)
    name_only = _FakeAdapter(
        tmp_path / "cursor.json", {"shared": {"command": "user-edited"}}, expected
    )
    outside = _FakeAdapter(tmp_path.parent / "outside.json", {"shared": expected}, expected)
    adapters = {"claude": matching, "cursor": name_only, "vscode": outside}
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: list(adapters))
    monkeypatch.setattr(
        ClientFactory, "create_client", lambda runtime, **_kwargs: adapters[runtime]
    )

    result = mcp_ownership.resolve_mcp_target_servers(
        recorded_target_servers={},
        ownership_present=False,
        server_names={"shared"},
        stored_configs={"shared": dict(BASELINE_MCP)},
        project_root=tmp_path,
        user_scope=False,
        approved_root=tmp_path,
        non_interactive=True,
    )

    assert result == {"claude": {"shared"}}
    assert matching.native_reads == [False]
    assert name_only.native_reads == [False]
    assert outside.native_reads == []


@pytest.mark.req("req-pr-010")
def test_mcp_scanner_authorizes_current_path_before_native_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Current native paths require selected-scope admission before reads."""
    root = tmp_path / "selected"
    root.mkdir()
    adapter = _FakeAdapter(tmp_path / "outside-current.json", {}, {})
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: ["fake"])
    monkeypatch.setattr(ClientFactory, "create_client", lambda *_args, **_kwargs: adapter)

    scanner_ctx = ScanContext(root, Scope.PROJECT, (), Redactor(root))
    assert list(McpScanner().scan(scanner_ctx)) == []
    assert scanner_ctx.errors
    assert adapter.native_reads == []


@pytest.mark.req("req-pr-010")
@pytest.mark.parametrize(
    ("adapter_factory", "expected_reads"),
    [
        (lambda root, expected: _FakeAdapter(root / "current.json", {}, expected), [False]),
        (
            lambda root, expected: _FakeAdapter(
                root / "current.json",
                {},
                expected,
                legacy_path=root / "legacy.json",
                legacy_servers={"other": expected},
            ),
            [False, True],
        ),
        (
            lambda root, expected: _FakeAdapter(
                root / "current.json",
                {},
                expected,
                legacy_path=root / "legacy.json",
                legacy_error=ValueError("invalid legacy evidence"),
            ),
            [False, True],
        ),
        (
            lambda root, expected: _FakeAdapter(
                root / "current.json",
                {},
                expected,
                legacy_path=root.parent / "outside-legacy.json",
            ),
            [False],
        ),
    ],
    ids=["absent", "unknown", "failed", "unauthorized"],
)
def test_mcp_failed_absent_unknown_or_unauthorized_legacy_evidence_does_not_infer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    adapter_factory: Callable[[Path, dict[str, Any]], _FakeAdapter],
    expected_reads: list[bool],
) -> None:
    """Bad legacy evidence adds no inferred MCP ownership claim."""
    root = tmp_path / "selected"
    root.mkdir()
    expected = _baseline_render(root)
    adapter = adapter_factory(root, expected)
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: ["fake"])
    monkeypatch.setattr(ClientFactory, "create_client", lambda *_args, **_kwargs: adapter)

    result = mcp_ownership.resolve_mcp_target_servers(
        recorded_target_servers={},
        ownership_present=False,
        server_names={"shared"},
        stored_configs={"shared": dict(BASELINE_MCP)},
        project_root=root,
        user_scope=False,
        approved_root=root,
    )

    assert result == {}
    assert adapter.native_reads == expected_reads


@pytest.mark.req("req-lk-023")
def test_user_scope_local_deploy_persists_only_actual_outputs_and_hashes(
    tmp_path: Path,
) -> None:
    """First user-scope local deploy writes only actual outputs to the user lockfile."""
    root = tmp_path / "project"
    root.mkdir()
    apm_dir = root / ".apm"
    apm_dir.mkdir()
    ctx = InstallContext(
        scope=InstallScope.USER,
        project_root=root,
        apm_dir=apm_dir,
        targets=[KNOWN_TARGETS["claude"].for_scope(user_scope=True)],
        diagnostics=DiagnosticCollector(),
    )
    own_files = [".claude/agents/reviewer.md", ".claude/rules/imported.md"]
    source_only = [".mcp.json", ".claude/settings.json"]
    for rel in [*own_files, *source_only]:
        _write(root / rel, f"{rel}\n")
    DeploymentLedgerCodec.replace_context_local_files(ctx, own_files)

    post_deps_local.run(ctx)

    lock_path = get_lockfile_path(apm_dir)
    assert lock_path == apm_dir / "apm.lock.yaml"
    assert lock_path.is_file()
    assert not (root / "apm.lock.yaml").exists()
    lock = LockFile.read(lock_path)
    assert lock is not None
    assert lock.local_deployed_files == sorted(own_files)
    assert lock.local_deployed_file_hashes == compute_deployed_hashes(own_files, root)
    assert all(value.startswith("sha256:") for value in lock.local_deployed_file_hashes.values())
    assert not (set(source_only) & set(lock.local_deployed_files))
    raw = yaml.safe_load(lock_path.read_text(encoding="ascii"))
    dependencies = raw.get("dependencies") or []
    assert not any(
        entry.get("repo_url") == "." for entry in dependencies if isinstance(entry, dict)
    )
