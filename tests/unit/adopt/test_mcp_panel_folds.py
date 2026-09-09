"""Public discovery regressions for credential identity and bounded native reads."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml
from click.testing import CliRunner
from rich.prompt import Prompt

from apm_cli.adapters.client.base import MCPClientAdapter
from apm_cli.adopt import discover
from apm_cli.adopt.converters import ConvertResult
from apm_cli.adopt.converters.mcp import placeholder_name, to_manifest_entry
from apm_cli.adopt.model import Scope
from apm_cli.adopt.ownership import OwnershipIndex
from apm_cli.adopt.registry import ScanLimits
from apm_cli.cli import cli
from apm_cli.factory import ClientFactory
from apm_cli.integration.mcp_integrator import MCPIntegrator
from apm_cli.models.dependency.mcp import MCPDependency

pytestmark = pytest.mark.component

_LIMIT = 1_048_576
_TOKEN = "ghp_" + "SYNTHETIC1234" * 4
_BASELINE = {
    "name": "shared",
    "registry": False,
    "transport": "stdio",
    "command": "echo",
    "env": {"TOKEN": "${MISSING_REVIEW_TOKEN}"},
}


def _legacy_lock(root: Path, baseline: dict) -> None:
    """Seed the actual pre-target-ownership wire format (no new marker)."""
    (root / "apm.lock.yaml").write_text(
        yaml.safe_dump(
            {
                "lockfile_version": "1",
                "mcp_servers": ["shared"],
                "mcp_configs": {"shared": baseline},
            }
        )
    )


def _native(root: Path, runtime: str, servers: dict) -> Path:
    adapter = ClientFactory.create_client(runtime, project_root=root)
    path = Path(adapter.get_config_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({adapter.native_mcp_servers_key: servers}))
    return path


def test_public_apply_keeps_normalized_server_credentials_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    servers = {
        name: {
            "type": "http",
            "url": f"https://{host}.example.test/mcp",
            "headers": {"Authorization": _TOKEN + host},
        }
        for name, host in (("demo-api", "alpha"), ("demo_api", "beta"))
    }
    source = _native(tmp_path, "cursor", servers)
    before = source.read_bytes()
    runner = CliRunner()
    args = ["init", "--discover", "--apply", "--yes", "--format", "json"]
    first = runner.invoke(cli, args)
    assert first.exit_code == 0, first.output
    manifest = (tmp_path / "apm.yml").read_text()
    entries = yaml.safe_load(manifest)["dependencies"]["mcp"]
    refs = {entry["name"]: entry["headers"]["Authorization"] for entry in entries}
    assert len(set(refs.values())) == 2
    assert all(re.fullmatch(r"\$\{[A-Z_][A-Z0-9_]*\}", ref) for ref in refs.values())
    assert _TOKEN not in first.output + manifest
    assert source.read_bytes() == before
    second = runner.invoke(cli, args)
    assert second.exit_code == 0, second.output
    assert (tmp_path / "apm.yml").read_text() == manifest
    for entry in entries:
        expected = "synthetic-" + entry["name"]
        monkeypatch.setenv(refs[entry["name"]][2:-1], expected)
    adapter = ClientFactory.create_client("cursor", project_root=tmp_path)
    for entry in entries:
        rendered = adapter.render_server_config(
            MCPIntegrator._build_self_defined_info(MCPDependency.from_dict(entry))
        )
        assert urlsplit(rendered["url"]).hostname == urlsplit(entry["url"]).hostname
        assert rendered["headers"]["Authorization"] == "synthetic-" + entry["name"]


@pytest.mark.parametrize("field", ["headers", "env"])
def test_field_identity_survives_normalization_and_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    config = (
        {"type": "http", "url": "https://alpha.example.test/mcp"}
        if field == "headers"
        else {"command": "echo"}
    )
    keys = ("X-API-Key", "X_API_Key", "x_api_key", "DEMO_X_API_KEY")
    config[field] = dict.fromkeys(keys, _TOKEN)
    first = to_manifest_entry("cursor", "demo", config, ConvertResult())[field]
    config[field] = dict.fromkeys(reversed(keys), _TOKEN + "rotated")
    second = to_manifest_entry("cursor", "demo", config, ConvertResult())[field]
    assert len(set(first.values())) == len(keys)
    assert first == second
    for key, reference in first.items():
        monkeypatch.setenv(reference[2:-1], "synthetic-" + key)
    entry = to_manifest_entry("cursor", "demo", config, ConvertResult())
    adapter = ClientFactory.create_client("cursor", project_root=tmp_path)
    rendered = adapter.render_server_config(
        MCPIntegrator._build_self_defined_info(MCPDependency.from_dict(entry))
    )
    assert rendered[field] == {key: "synthetic-" + key for key in keys}


@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("runtime", ["cursor", "gemini"])
def test_public_discovery_never_prompts_for_legacy_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, present: bool, runtime: str
) -> None:
    monkeypatch.chdir(tmp_path)
    _legacy_lock(tmp_path, _BASELINE)
    if present:
        _native(tmp_path, runtime, {"shared": {"command": "echo", "env": {"TOKEN": "host-value"}}})
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: [runtime])
    monkeypatch.delenv("APM_E2E_TESTS")
    monkeypatch.delenv("MISSING_REVIEW_TOKEN", raising=False)
    renders: list[str] = []
    prompts: list[str] = []
    original_render = MCPClientAdapter.render_server_config

    def render(self, *args, **kwargs):
        # CliRunner replaces streams: model TTYs at the real render boundary.
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        renders.append(runtime)
        return original_render(self, *args, **kwargs)

    def ask(text, **kwargs):
        prompts.append(text)
        return "should-not-be-collected"

    monkeypatch.setattr(MCPClientAdapter, "render_server_config", render)
    monkeypatch.setattr(Prompt, "ask", ask)
    result = CliRunner().invoke(cli, ["init", "--discover", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert prompts == []
    assert renders == ([runtime] if present else [])
    assert not (tmp_path / "apm.yml").exists()


@pytest.mark.parametrize("runtime", ["copilot", "codex"])
@pytest.mark.parametrize("factor", [1, 10])
@pytest.mark.parametrize("entrypoint", ["cli", "ownership"])
def test_real_oversize_native_files_are_never_parsed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime: str,
    factor: int,
    entrypoint: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    baseline = {k: v for k, v in _BASELINE.items() if k != "env"}
    _legacy_lock(tmp_path, baseline)
    adapter = ClientFactory.create_client(runtime, project_root=tmp_path)
    path = Path(adapter.get_config_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    if runtime == "codex":
        text = (
            "# padding\n" * (_LIMIT * factor // 10 + 1) + '[mcp_servers.shared]\ncommand="echo"\n'
        )
    else:
        text = json.dumps(
            {
                "padding": "x" * (_LIMIT * factor),
                adapter.native_mcp_servers_key: {"shared": {"command": "echo"}},
            }
        )
    path.write_text(text)
    assert path.stat().st_size > _LIMIT * factor
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: [runtime])
    original = type(adapter)._read_config
    reads: list[Path] = []

    def counted(self, config_path):
        reads.append(config_path)
        return original(self, config_path)

    monkeypatch.setattr(type(adapter), "_read_config", counted)
    if entrypoint == "cli":
        result = CliRunner().invoke(cli, ["init", "--discover", "--format", "json"])
        assert result.exit_code == 0, result.output
        assert "oversize; not parsed" in result.output
        assert json.loads(result.output)["findings"] == []
    else:
        assert OwnershipIndex.build(tmp_path, Scope.PROJECT).mcp_owned == {}
    assert reads == []


def test_custom_budget_reaches_ownership_before_scanners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _legacy_lock(tmp_path, _BASELINE)
    _native(tmp_path, "cursor", {"shared": {"command": "echo"}})
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: ["cursor"])
    monkeypatch.setattr(
        MCPClientAdapter, "_read_config", lambda *args: pytest.fail("over-budget parser entered")
    )
    report = discover(tmp_path, Scope.PROJECT, limits=ScanLimits(max_file_bytes=1))
    assert not report.findings
    assert report.errors


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX special file")
def test_nonregular_native_file_never_reaches_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _legacy_lock(tmp_path, _BASELINE)
    adapter = ClientFactory.create_client("cursor", project_root=tmp_path)
    path = Path(adapter.get_config_path())
    path.parent.mkdir()
    os.mkfifo(path)
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: ["cursor"])
    reads: list[Path] = []

    def counted(self, path):
        reads.append(path)
        return {}

    monkeypatch.setattr(MCPClientAdapter, "_read_config", counted)
    report = discover(tmp_path, Scope.PROJECT)
    assert not report.findings
    assert report.errors
    assert reads == []


@pytest.mark.parametrize("size", [_LIMIT, _LIMIT + 1, 10 * _LIMIT + 1])
def test_obsolete_native_path_uses_same_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, size: int
) -> None:
    from apm_cli.adapters.client.intellij import IntelliJClientAdapter

    baseline = {k: v for k, v in _BASELINE.items() if k != "env"}
    _legacy_lock(tmp_path, baseline)
    legacy = tmp_path / "obsolete.json"
    adapter = ClientFactory.create_client("intellij", project_root=tmp_path)
    native = adapter.render_server_config(
        MCPIntegrator._build_self_defined_info(MCPDependency.from_dict(baseline))
    )
    text = json.dumps({"servers": {"shared": native}})
    legacy.write_text(text + " " * (size - len(text)))
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: ["intellij"])
    monkeypatch.setattr(
        IntelliJClientAdapter, "get_config_path", lambda self: str(tmp_path / "absent.json")
    )
    monkeypatch.setattr(IntelliJClientAdapter, "get_legacy_config_path", lambda self: str(legacy))
    original = IntelliJClientAdapter._read_config
    reads: list[Path] = []

    def counted(self, path):
        reads.append(path)
        return original(self, path)

    monkeypatch.setattr(IntelliJClientAdapter, "_read_config", counted)
    result = OwnershipIndex.build(tmp_path, Scope.PROJECT).mcp_owned
    assert reads == ([legacy] if size <= _LIMIT else [])
    assert result == ({"intellij": frozenset({"shared"})} if size <= _LIMIT else {})


@pytest.mark.parametrize("runtime", ["copilot", "codex", "opencode"])
def test_server_enumeration_budget_keeps_adapter_shapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runtime: str
) -> None:
    adapter = ClientFactory.create_client(runtime, project_root=tmp_path)
    path = Path(adapter.get_config_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    if runtime == "codex":
        path.write_text('[mcp_servers.one]\ncommand="echo"\n[mcp_servers.two]\ncommand="echo"\n')
    else:
        servers = {name: {"command": "echo"} for name in ("one", "two")}
        if runtime == "opencode":
            servers = {name: {"type": "local", "command": ["echo"]} for name in ("one", "two")}
        _native(tmp_path, runtime, servers)
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: [runtime])
    report = discover(tmp_path, Scope.PROJECT, limits=ScanLimits(max_entries_per_rule=1))
    assert report.findings == ()
    assert report.errors
    # Ordinary native reads keep install defaults and parser-owned shapes.
    assert set(adapter.get_native_server_configs()) == {"one", "two"}


@pytest.mark.parametrize("runtime", ["cursor", "gemini"])
@pytest.mark.parametrize("fail_render", [False, True])
def test_noninteractive_render_restores_ordinary_prompt_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runtime: str, fail_render: bool
) -> None:
    adapter = ClientFactory.create_client(runtime, project_root=tmp_path)
    info = MCPIntegrator._build_self_defined_info(MCPDependency.from_dict(_BASELINE))
    monkeypatch.delenv("APM_E2E_TESTS")
    monkeypatch.delenv("MISSING_REVIEW_TOKEN", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    prompts: list[str] = []

    def ask(text, **kwargs):
        prompts.append(text)
        return "ordinary-install-value"

    monkeypatch.setattr(Prompt, "ask", ask)
    original = adapter._format_server_config
    if fail_render:

        def fail(*args, **kwargs):
            raise ValueError("render failure")

        monkeypatch.setattr(adapter, "_format_server_config", fail)
        with pytest.raises(ValueError, match="render failure"):
            adapter.render_server_config(info, non_interactive=True)
        monkeypatch.setattr(adapter, "_format_server_config", original)
    else:
        rendered = adapter.render_server_config(info, non_interactive=True)
        assert rendered["env"]["TOKEN"] == "${MISSING_REVIEW_TOKEN}"
    assert prompts == []
    rendered = adapter.render_server_config(info)
    assert rendered["env"]["TOKEN"] == "ordinary-install-value"
    assert len(prompts) == 1


def test_identity_hash_uses_original_names_and_field_namespace() -> None:
    identities = [
        ("demo-api", "Authorization", "headers"),
        ("demo_api", "Authorization", "headers"),
        ("DEMO_API", "Authorization", "headers"),
        ("demo api", "Authorization", "headers"),
        ("a_b", "c", "env"),
        ("a", "b_c", "env"),
        ("a", "b_c", "headers"),
    ]
    names = {placeholder_name(server, key, field=field) for server, key, field in identities}
    assert len(names) == len(identities)
    for server, key, field in identities[:4]:
        result = to_manifest_entry(
            "cursor",
            server,
            {"url": "https://alpha.example.test/mcp", "headers": {key: _TOKEN}},
            ConvertResult(),
        )
        assert result["headers"][key] == placeholder_name(server, key, field=field)


def test_discovery_skips_baseline_name_absent_from_existing_native_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _legacy_lock(tmp_path, _BASELINE)
    _native(tmp_path, "cursor", {"other": {"command": "echo"}})
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: ["cursor"])
    monkeypatch.setattr(
        MCPClientAdapter,
        "render_server_config",
        lambda *args, **kwargs: pytest.fail("absent legacy name was rendered"),
    )
    assert OwnershipIndex.build(tmp_path, Scope.PROJECT).mcp_owned == {}


def test_real_cli_process_preserves_generated_identities_on_reimport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    source = _native(
        tmp_path,
        "cursor",
        {
            name: {
                "url": f"https://{host}.example.test/mcp",
                "headers": {"Authorization": _TOKEN + host},
            }
            for name, host in (("demo-api", "alpha"), ("demo_api", "beta"))
        },
    )
    before = source.read_bytes()
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "APM_E2E_TESTS": "1"}
    command = [
        sys.executable,
        "-c",
        "from apm_cli.cli import main; main()",
        "init",
        "--discover",
        "--apply",
        "--yes",
        "--format",
        "json",
    ]
    manifests: list[bytes] = []
    for _ in range(2):
        result = subprocess.run(
            command, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert _TOKEN not in result.stdout + result.stderr
        manifests.append((tmp_path / "apm.yml").read_bytes())
    assert manifests[0] == manifests[1]
    entries = yaml.safe_load(manifests[0])["dependencies"]["mcp"]
    assert len({entry["headers"]["Authorization"] for entry in entries}) == 2
    assert source.read_bytes() == before
