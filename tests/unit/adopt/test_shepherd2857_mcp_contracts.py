"""Hermetic W3 MCP regressions: no server execution or network access."""

from __future__ import annotations

import builtins
import importlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

import pytest

from apm_cli.adopt.converters import ConvertContext, ConvertError, ConvertResult
from apm_cli.adopt.converters.mcp import McpConverter, to_manifest_entry
from apm_cli.adopt.model import HarnessKind, Ownership, RawFinding, Scope
from apm_cli.adopt.ownership import OwnershipIndex
from apm_cli.adopt.redact import Redactor, contains_credential
from apm_cli.adopt.registry import ScanContext
from apm_cli.adopt.scanners.mcp import McpScanner
from apm_cli.deps.lockfile import LockFile
from apm_cli.factory import ClientFactory
from apm_cli.install.mcp import ownership as canonical
from apm_cli.integration.mcp_integrator import MCPIntegrator
from apm_cli.models.dependency.mcp import MCPDependency
from apm_cli.utils.path_security import PathTraversalError

pytestmark = pytest.mark.component

TOKEN = "ghp_" + "SYNTHETIC1234" * 4
BASELINE = {
    "name": "shared",
    "registry": False,
    "transport": "stdio",
    "command": "echo",
    "args": ["managed"],
}


def _read_mcp(root: Path, scope: Scope, reader: str) -> object:
    if reader == "scanner":
        ctx = ScanContext(root, scope, (), Redactor(root, root))
        assert list(McpScanner().scan(ctx)) == []
        return ctx
    if reader == "ownership":
        return canonical.resolve_mcp_target_servers(
            recorded_target_servers={},
            ownership_present=False,
            server_names={"shared"},
            stored_configs={"shared": dict(BASELINE)},
            project_root=root,
            user_scope=scope is Scope.USER,
            approved_root=root,
        )
    for runtime in ClientFactory.supported_clients():
        adapter = ClientFactory.create_client(
            runtime, project_root=root, user_scope=scope is Scope.USER
        )
        assert adapter.get_native_server_configs(approved_root=root) == {}
    return {}


@pytest.mark.parametrize("scope", [Scope.PROJECT, Scope.USER])
@pytest.mark.parametrize("reader", ["scanner", "ownership", "native"])
def test_empty_mcp_discovery_never_creates_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    scope: Scope,
    reader: str,
) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    monkeypatch.setattr(Path, "home", lambda: root)
    for name in (
        "COPILOT_HOME",
        "CODEX_HOME",
        "CLAUDE_CONFIG_DIR",
        "HERMES_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(root))
    monkeypatch.setattr(
        os, "mkdir", lambda *args, **kwargs: pytest.fail("read discovery attempted mkdir")
    )
    _read_mcp(root, scope, reader)
    assert list(root.iterdir()) == []
    assert capsys.readouterr() == ("", "")
    assert caplog.text == ""


@pytest.mark.parametrize("dangling", [False, True])
@pytest.mark.parametrize("reader", ["scanner", "ownership", "native"])
def test_redirected_vscode_parent_is_rejected_before_probes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    reader: str,
    dangling: bool,
) -> None:
    root = tmp_path / "selected"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / ".vscode"
    link.symlink_to(outside / "missing" if dangling else outside, target_is_directory=True)
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: ["vscode"])

    def guard_probe(method):
        def guarded(path: Path, *args: object, **kwargs: object):
            if path == link or path.is_relative_to(link) or path.is_relative_to(outside):
                pytest.fail("redirected MCP path was probed before authorization")
            return method(path, *args, **kwargs)

        return guarded

    for name in ("exists", "is_file", "open"):
        monkeypatch.setattr(Path, name, guard_probe(getattr(Path, name)))
    original_open = builtins.open
    monkeypatch.setattr(
        builtins,
        "open",
        lambda path, *args, **kwargs: guard_probe(original_open)(Path(path), *args, **kwargs),
    )
    monkeypatch.setattr(
        os, "mkdir", lambda *args, **kwargs: pytest.fail("read discovery attempted mkdir")
    )
    if reader == "native":
        with pytest.raises(PathTraversalError):
            _read_mcp(root, Scope.PROJECT, reader)
    else:
        result = _read_mcp(root, Scope.PROJECT, reader)
        if reader == "scanner":
            assert result.errors
        else:
            assert result == {}
    assert list(outside.iterdir()) == []
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("runtime", ["vscode", "codex", "gemini", "kiro"])
@pytest.mark.parametrize("contents", [b"\xff", b"{malformed"])
def test_native_discovery_is_silent_on_unreadable_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    runtime: str,
    contents: bytes,
) -> None:
    adapter = ClientFactory.create_client(runtime, project_root=tmp_path)
    config_path = Path(adapter.get_config_path())
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_bytes(contents)
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: [runtime])
    ctx = ScanContext(tmp_path, Scope.PROJECT, (), Redactor(tmp_path))
    assert list(McpScanner().scan(ctx)) == []
    assert ctx.errors
    assert capsys.readouterr() == ("", "")
    assert caplog.text == ""


@pytest.mark.parametrize("runtime", ["vscode", "copilot", "codex"])
def test_registry_clients_are_lazy_and_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runtime: str
) -> None:
    module = importlib.import_module(f"apm_cli.adapters.client.{runtime}")
    calls: list[tuple[str, object]] = []

    def factory(name: str):
        def create(url):
            calls.append((name, url))
            return object()

        return create

    monkeypatch.setattr(module, "SimpleRegistryClient", factory("client"))
    monkeypatch.setattr(module, "RegistryIntegration", factory("integration"))
    adapter = ClientFactory.create_client(runtime, project_root=tmp_path)
    assert adapter.get_native_server_configs(approved_root=tmp_path) == {}
    assert calls == []
    assert adapter.registry_client is adapter.registry_client
    assert adapter.registry_integration is adapter.registry_integration
    assert calls == [("client", None), ("integration", None)]


@pytest.mark.parametrize(
    "runtime,document",
    [
        ("codex", '[mcp_servers.shared]\ncommand = "echo"\n'),
        ("intellij", '{"servers": {"shared": {"command": "echo",},},} // native JSONC\n'),
        ("hermes", "mcp_servers:\n  shared:\n    command: echo\n"),
    ],
)
def test_native_read_keeps_adapter_owned_parsers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runtime: str, document: str
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / ".config"))
    adapter = ClientFactory.create_client(runtime, project_root=tmp_path)
    path = Path(adapter.get_config_path())
    path.parent.mkdir(parents=True)
    path.write_text(document)
    monkeypatch.setattr(
        adapter,
        "get_current_config",
        lambda: pytest.fail("native discovery used the write-oriented reader"),
    )
    assert adapter.get_native_server_configs(approved_root=tmp_path) == {
        "shared": {"command": "echo"}
    }


def test_vscode_write_still_creates_config_directory(tmp_path: Path) -> None:
    adapter = ClientFactory.create_client("vscode", project_root=tmp_path)
    path = Path(adapter.get_config_path())
    assert not path.parent.exists()
    assert adapter.update_config({"servers": {"shared": {"command": "echo"}}}) is True
    assert adapter.get_native_server_configs(approved_root=tmp_path) == {
        "shared": {"command": "echo"}
    }


def _raw(tool: str, scope: Scope = Scope.PROJECT) -> RawFinding:
    return RawFinding(
        tool=tool,
        scope=scope,
        kind=HarnessKind.MCP_SERVER,
        display_path=f"{tool}#shared",
        payload={"name": "shared"},
    )


def _lock(root: Path, scope: Scope, **kwargs: object) -> None:
    directory = root if scope is Scope.PROJECT else root / ".apm"
    directory.mkdir(parents=True, exist_ok=True)
    lock = LockFile()
    lock.mcp_servers = ["shared"]
    lock.mcp_configs = {"shared": dict(BASELINE)}
    for key, value in kwargs.items():
        setattr(lock, key, value)
    lock.write(directory / "apm.lock.yaml")


@pytest.mark.parametrize("scope", [Scope.PROJECT, Scope.USER])
def test_target_ownership_does_not_hide_another_client(
    tmp_path: Path,
    scope: Scope,
) -> None:
    _lock(tmp_path, scope, mcp_target_servers={"claude": ["shared"]})
    index = OwnershipIndex.build(tmp_path, scope)
    assert index.decide(_raw("claude", scope))[0] is Ownership.APM_OWNED
    assert index.decide(_raw("cursor", scope))[0] is Ownership.HOST_OWNED
    other_scope = Scope.USER if scope is Scope.PROJECT else Scope.PROJECT
    assert index.decide(_raw("claude", other_scope))[0] is Ownership.HOST_OWNED


def test_explicit_empty_does_not_adopt_legacy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _lock(tmp_path, Scope.PROJECT, _mcp_target_servers_present=True)
    monkeypatch.setattr(
        canonical,
        "adopt_legacy_mcp_target_servers",
        lambda **kwargs: pytest.fail("explicit-empty ownership must not inspect native files"),
    )
    assert (
        OwnershipIndex.build(tmp_path, Scope.PROJECT).decide(_raw("claude"))[0]
        is Ownership.HOST_OWNED
    )


def test_adoption_delegates_to_canonical_resolver(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _lock(tmp_path, Scope.PROJECT)
    calls: list[dict] = []

    def resolve(**kwargs: object) -> dict[str, set[str]]:
        calls.append(kwargs)
        return {"cursor": {"shared"}}

    monkeypatch.setattr(canonical, "resolve_mcp_target_servers", resolve)
    index = OwnershipIndex.build(tmp_path, Scope.PROJECT)
    assert index.decide(_raw("cursor"))[0] is Ownership.APM_OWNED
    assert index.decide(_raw("claude"))[0] is Ownership.HOST_OWNED
    assert len(calls) == 1
    assert calls[0]["approved_root"] == tmp_path
    assert calls[0]["ownership_present"] is False


@pytest.mark.parametrize("matching", [True, False])
def test_legacy_exact_native_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    matching: bool,
) -> None:
    _lock(tmp_path, Scope.PROJECT)
    adapter = ClientFactory.create_client("claude", project_root=tmp_path)
    native = adapter.render_server_config(
        MCPIntegrator._build_self_defined_info(MCPDependency.from_dict(dict(BASELINE)))
    )
    if not matching:
        native["command"] = "user-edited"
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"shared": native}}))
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: ["claude"])
    index = OwnershipIndex.build(tmp_path, Scope.PROJECT)
    expected = Ownership.APM_OWNED if matching else Ownership.HOST_OWNED
    assert index.decide(_raw("claude"))[0] is expected


@pytest.mark.parametrize("scope", [Scope.PROJECT, Scope.USER])
def test_current_native_read_is_authorized_before_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope: Scope,
) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    link = root / "native.json"
    link.symlink_to(outside)
    adapter = ClientFactory.create_client("cursor", project_root=root, user_scope=False)
    monkeypatch.setattr(adapter, "get_config_path", lambda: str(link))
    monkeypatch.setattr(
        adapter,
        "get_current_config",
        lambda: pytest.fail("outside current config was read"),
    )
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: ["cursor"])
    monkeypatch.setattr(ClientFactory, "create_client", lambda *args, **kwargs: adapter)
    ctx = ScanContext(root, scope, (), Redactor(root, root))
    assert list(McpScanner().scan(ctx)) == []
    assert ctx.errors


@pytest.mark.parametrize("legacy", [False, True])
def test_legacy_ownership_authorizes_every_native_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    legacy: bool,
) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    adapter = ClientFactory.create_client("cursor", project_root=root, user_scope=False)
    monkeypatch.setattr(
        adapter, "get_config_path", lambda: str(root / "native.json") if legacy else str(outside)
    )
    if legacy:
        monkeypatch.setattr(adapter, "get_current_config", lambda: {"mcpServers": {}})
        monkeypatch.setattr(adapter, "get_legacy_config_path", lambda: str(outside), raising=False)
        monkeypatch.setattr(
            adapter,
            "get_legacy_current_config",
            lambda: pytest.fail("outside legacy config was read"),
            raising=False,
        )
    else:
        monkeypatch.setattr(
            adapter, "get_current_config", lambda: pytest.fail("outside current config was read")
        )
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: ["cursor"])
    monkeypatch.setattr(ClientFactory, "create_client", lambda *args, **kwargs: adapter)
    result = canonical.resolve_mcp_target_servers(
        recorded_target_servers={},
        ownership_present=False,
        server_names={"shared"},
        stored_configs={"shared": dict(BASELINE)},
        project_root=root,
        user_scope=False,
        approved_root=root,
    )
    assert result == {}


@pytest.mark.parametrize("sidecar", ["apm.lock.yaml", "apm.lock", ".apm/.import-sources.json"])
def test_ownership_sidecars_cannot_read_outside_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sidecar: str,
) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    link = root / sidecar
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside)
    original = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object):
        if path.resolve() == outside:
            pytest.fail("outside sidecar was opened")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    index = OwnershipIndex.build(root, Scope.PROJECT)
    assert index.import_sources == frozenset()
    assert index.decide(_raw("cursor"))[0] is Ownership.HOST_OWNED


def test_opencode_native_document_is_discovered_through_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = {"type": "local", "command": ["echo", "hello"], "environment": {"MODE": "dev"}}
    (tmp_path / "opencode.json").write_text(json.dumps({"mcp": {"shared": native}}))
    monkeypatch.setattr(ClientFactory, "supported_clients", lambda: ["opencode"])
    ctx = ScanContext(tmp_path, Scope.PROJECT, (), Redactor(tmp_path))
    findings = list(McpScanner().scan(ctx))
    assert len(findings) == 1
    assert findings[0].payload["config"] == native
    adapter = ClientFactory.create_client("opencode", project_root=tmp_path)
    assert adapter.mcp_servers_key == "mcpServers"  # compatibility metadata is unchanged
    assert adapter.get_native_server_configs(approved_root=tmp_path) == {"shared": native}


@pytest.mark.parametrize(
    "argument",
    [
        TOKEN,
        "--token=" + TOKEN,
        "TOKEN=" + TOKEN,
        "--token=" + TOKEN + "${SUFFIX}",
        "--token=synthetic-password",
    ],
)
def test_unreplayable_argument_credentials_are_refused(argument: str) -> None:
    with pytest.raises(ConvertError, match=r"args\[0\]") as exc:
        to_manifest_entry(
            "cursor", "demo", {"command": "echo", "args": [argument]}, ConvertResult()
        )
    assert TOKEN not in str(exc.value)


@pytest.mark.parametrize("field", ["env", "headers"])
def test_mixed_placeholder_literals_are_scrubbed_and_replayable(
    tmp_path: Path,
    field: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEMO_CUSTOM", "synthetic-resolved")
    config = {"command": "echo"} if field == "env" else {"url": "https://example.test/mcp"}
    config[field] = {"CUSTOM": TOKEN + "${SUFFIX}"}
    result = ConvertResult()
    entry = to_manifest_entry("cursor", "demo", config, result)
    assert entry[field] == {"CUSTOM": "${DEMO_CUSTOM}"}
    assert contains_credential(json.dumps(entry)) is None
    adapter = ClientFactory.create_client("cursor", project_root=tmp_path)
    rendered = adapter.render_server_config(
        MCPIntegrator._build_self_defined_info(MCPDependency.from_dict(entry))
    )
    assert rendered[field]["CUSTOM"] == "synthetic-resolved"
    assert TOKEN not in str(result.changes)


@pytest.mark.parametrize(
    "config",
    [
        {"command": "echo", "oauth": {"clientSecret": TOKEN}},
        {"command": "echo", "oauth": {"nested": ["prefix " + TOKEN + "${SUFFIX}"]}},
        {"command": "echo", "cwd": "/folder/" + TOKEN},
        {"command": "echo", "tools": [TOKEN]},
    ],
)
def test_entire_outgoing_entry_is_credential_checked(config: dict) -> None:
    with pytest.raises(ConvertError) as exc:
        to_manifest_entry("claude", "demo", config, ConvertResult())
    assert TOKEN not in str(exc.value)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:synthetic-password@example.test/mcp",
        "https://example.test/mcp?token=synthetic-password",
        "https://example.test/" + TOKEN,
        "https://example.test/mcp?other=" + TOKEN + "${SUFFIX}",
    ],
)
def test_unreplayable_url_credentials_are_refused(url: str) -> None:
    with pytest.raises(ConvertError, match="url") as exc:
        to_manifest_entry("cursor", "demo", {"url": url}, ConvertResult())
    assert TOKEN not in str(exc.value)
    assert "synthetic-password" not in str(exc.value)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test/a%2Fb?resource=a%26b%3Dc&scope=a%2Bb&x=&x=two&bare#f%20g",
        "http://[::1]:3000/mcp?x=&x=two",
        "https://example.test/mcp?",
    ],
)
def test_clean_url_is_preserved_through_existing_renderer(tmp_path: Path, url: str) -> None:
    entry = to_manifest_entry("cursor", "demo", {"url": url}, ConvertResult())
    assert urlsplit(entry["url"]) == urlsplit(url)
    assert entry["url"].encode() == url.encode()
    assert parse_qsl(urlsplit(entry["url"]).query, keep_blank_values=True) == parse_qsl(
        urlsplit(url).query,
        keep_blank_values=True,
    )
    adapter = ClientFactory.create_client("cursor", project_root=tmp_path)
    rendered = adapter.render_server_config(
        MCPIntegrator._build_self_defined_info(MCPDependency.from_dict(entry))
    )
    assert urlsplit(rendered["url"]) == urlsplit(url)


@pytest.mark.parametrize(
    "reference",
    [
        {"bearer_token_env_var": "DEMO_TOKEN"},
        {"env_http_headers": {"Authorization": "DEMO_TOKEN"}},
        {"http_headers": {"Authorization": "Bearer ${DEMO_TOKEN}"}},
        {"env_vars": ["DEMO_TOKEN"]},
    ],
)
def test_codex_unsupported_native_references_produce_no_fragment(
    tmp_path: Path,
    reference: dict,
) -> None:
    finding = SimpleNamespace(
        payload={
            "tool": "codex",
            "name": "demo",
            "config": {"url": "https://example.test/mcp", **reference},
        }
    )
    ctx = ConvertContext(tmp_path, Scope.PROJECT, Redactor(tmp_path))
    result = McpConverter().convert(finding, tmp_path / ".apm", ctx=ctx)
    assert result.manifest_fragment is None
    assert result.skipped_reason
    assert next(iter(reference)) in result.skipped_reason
    assert result.written == []


def test_plain_mcp_remains_supported(tmp_path: Path) -> None:
    finding = SimpleNamespace(
        payload={
            "tool": "cursor",
            "name": "demo",
            "config": {"command": "echo", "args": ["hello"]},
        }
    )
    result = McpConverter().convert(
        finding,
        tmp_path / ".apm",
        ctx=ConvertContext(tmp_path, Scope.PROJECT, Redactor(tmp_path)),
    )
    assert result.skipped_reason is None
    assert result.manifest_fragment["dependencies"]["mcp"][0]["args"] == ["hello"]


@pytest.mark.parametrize(
    "config",
    [
        {"command": "echo", "args": ["${REFERENCE}", TOKEN]},
        {"command": "echo", "args": ["${REFERENCE}"], "oauth": {"secret": TOKEN}},
        {"url": "https://example.test/${REFERENCE}", "oauth": {"secret": TOKEN}},
    ],
)
def test_literal_refusal_takes_priority_over_reference_only(
    tmp_path: Path,
    config: dict,
) -> None:
    finding = SimpleNamespace(payload={"tool": "cursor", "name": "demo", "config": config})
    with pytest.raises(ConvertError) as exc:
        McpConverter().convert(
            finding,
            tmp_path / ".apm",
            ctx=ConvertContext(tmp_path, Scope.PROJECT, Redactor(tmp_path)),
        )
    assert TOKEN not in str(exc.value)


def test_native_codex_nested_and_dotted_tables_are_adapter_owned(tmp_path: Path) -> None:
    adapter = ClientFactory.create_client("codex", project_root=tmp_path)
    config_path = Path(adapter.get_config_path())
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        '[mcp_servers.nested]\ncommand = "echo"\n["mcp_servers.flat"]\ncommand = "other"\n'
    )
    native = adapter.get_native_server_configs(approved_root=tmp_path)
    assert native["nested"]["command"] == "echo"
    assert native["flat"]["command"] == "other"


def test_supported_opencode_native_roundtrip(tmp_path: Path) -> None:
    native = {
        "type": "local",
        "command": ["echo", "hello"],
        "environment": {"MODE": "dev"},
        "enabled": True,
    }
    entry = to_manifest_entry("opencode", "demo", native, ConvertResult())
    adapter = ClientFactory.create_client("opencode", project_root=tmp_path)
    compatible = adapter.render_server_config(
        MCPIntegrator._build_self_defined_info(MCPDependency.from_dict(entry))
    )
    rendered = adapter._to_opencode_format(compatible)
    assert rendered["command"] == native["command"]
    assert rendered["environment"] == native["environment"]
    assert rendered["type"] == native["type"]
    assert rendered["enabled"] is True


@pytest.mark.parametrize("field", ["env", "headers"])
def test_supported_bearer_reference_keeps_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    monkeypatch.setenv("DEMO_TOKEN", "synthetic-resolved")
    config = {"command": "echo"} if field == "env" else {"url": "https://example.test/mcp"}
    config[field] = {"Authorization": "Bearer ${env:DEMO_TOKEN}"}
    entry = to_manifest_entry("cursor", "demo", config, ConvertResult())
    adapter = ClientFactory.create_client("cursor", project_root=tmp_path)
    native = adapter.render_server_config(
        MCPIntegrator._build_self_defined_info(MCPDependency.from_dict(entry))
    )
    assert native[field]["Authorization"] == "Bearer synthetic-resolved"


def test_user_ownership_does_not_follow_redirected_apm_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "selected"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / ".import-sources.json").write_text("{}")
    (outside / "apm.lock.yaml").write_text("{}")
    (root / ".apm").symlink_to(outside, target_is_directory=True)
    original = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object):
        if path.resolve().is_relative_to(outside):
            pytest.fail("outside user-scope sidecar was opened")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    index = OwnershipIndex.build(root, Scope.USER)
    assert index.lockfile_present is False
    assert index.import_sources == frozenset()
