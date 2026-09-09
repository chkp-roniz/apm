"""Native MCP entries -> bounded, credential-safe ``dependencies.mcp`` entries.

Only renderer-supported env/header values can become credential placeholders.
Unreplayable literal credentials are refused; unsupported native references
remain reference-only. Outgoing URLs are never reconstructed.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from apm_cli.adapters.client.base import (
    _ENV_PLACEHOLDER_RE,
    _has_env_placeholder,
    _translate_env_placeholder,
)
from apm_cli.models.dependency.mcp import _NAME_REGEX, MCPDependency

from ..model import Finding
from ..redact import contains_credential, looks_like_secret
from . import ConvertContext, ConvertError, ConvertResult

_HTTP_TRANSPORTS = frozenset({"http", "sse", "streamable-http"})
_PASSTHROUGH_TO_EXTRA: dict[str, tuple[str, ...]] = {
    "gemini": ("includeTools", "excludeTools", "trust", "timeout"),
    "antigravity": ("includeTools", "excludeTools", "trust", "timeout"),
    "kiro": ("autoApprove", "disabledTools", "disabled"),
    "codex": ("startup_timeout_sec", "tool_timeout_sec", "enabled_tools", "disabled_tools"),
    "claude": ("oauth",),
    "cursor": ("oauth",),
}
_REFERENCE_RE = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_]\w*|\{env:[^}]*\}|<[A-Z_][A-Z0-9_]*>")


class _ReferenceOnly(ConvertError):
    """A native reference cannot be preserved through the existing renderer."""


def _field(parent: str, key: object) -> str:
    """Return a field path without echoing credential-shaped key material."""
    name = str(key)
    return f"{parent}.{name if contains_credential(name) is None else '<redacted-key>'}"


def _literal_secret(text: str, key: str | None = None) -> bool:
    """Inspect literals even when the same value also contains a placeholder."""
    if contains_credential(text):
        return True
    literal = _REFERENCE_RE.sub("", text).strip()
    if not literal or (_REFERENCE_RE.search(text) and literal.lower() in {"bearer", "basic"}):
        return False
    return looks_like_secret(key, literal)


def _check_fragment(value: Any, path: str = "entry") -> None:
    """Check every emitted scalar and key, including retained nested extras."""
    if isinstance(value, Mapping):
        for key, child in value.items():
            field = _field(path, key)
            if contains_credential(str(key)):
                raise ConvertError(f"{field}: credential-shaped field name; refusing import")
            if (
                path.startswith("entry.extra")
                and isinstance(child, str)
                and _literal_secret(child, str(key))
            ):
                raise ConvertError(f"{field}: literal credential has no safe replay conversion")
            _check_fragment(child, field)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _check_fragment(child, f"{path}[{index}]")
    elif isinstance(value, str) and contains_credential(value):
        raise ConvertError(f"{path}: literal credential has no safe replay conversion")


def placeholder_name(server: str, key: str) -> str:
    """Allocate an environment identifier accepted by existing renderers."""
    server_slug = re.sub(r"[^A-Z0-9]+", "_", server.upper()).strip("_")
    key_slug = re.sub(r"[^A-Z0-9]+", "_", key.upper()).strip("_")
    slug = key_slug if key_slug.startswith(server_slug + "_") else f"{server_slug}_{key_slug}"
    slug = slug.strip("_") or "MCP_VALUE"
    if slug[0].isdigit():
        slug = "MCP_" + slug
    return "${" + slug + "}"


def _sanitize_name(name: str, result: ConvertResult) -> str:
    if _NAME_REGEX.match(name):
        return name
    cleaned = re.sub(r"[^a-zA-Z0-9._@/:=-]", "-", name).strip("-") or "mcp-server"
    result.transform("name", "server name sanitised for apm.yml")
    return cleaned[:128]


def _scrub_map(
    values: Mapping[str, Any],
    server: str,
    field: str,
    result: ConvertResult,
    *,
    references: list[str],
    allow_placeholders: bool = True,
) -> dict[str, str]:
    """Scrub literals before interpreting any native placeholder spelling."""
    out: dict[str, str] = {}
    for key, raw in values.items():
        text = str(raw)
        path = _field(field, key)
        if _literal_secret(text, str(key)):
            if not allow_placeholders:
                raise ConvertError(f"{path}: literal credential has no safe replay conversion")
            out[str(key)] = placeholder_name(server, str(key))
            result.redacted(
                path,
                f"literal replaced by environment reference; export {out[str(key)][2:-1]} "
                "before apm install",
            )
        elif _has_env_placeholder(text):
            if not allow_placeholders:
                references.append(
                    f"{path}: environment reference is unsupported by existing renderer"
                )
            if _REFERENCE_RE.search(_ENV_PLACEHOLDER_RE.sub("", text)):
                references.append(f"{path}: unsupported native environment reference")
            translated = _translate_env_placeholder(text)
            if translated != text:
                result.transform(path, "placeholder spelling normalised to ${VAR}")
            out[str(key)] = translated
        elif _REFERENCE_RE.search(text):
            references.append(f"{path}: unsupported native environment reference")
            out[str(key)] = text
        else:
            out[str(key)] = text
    return out


def _looks_like_path_token(text: str) -> bool:
    """Return whether *text* is clearly a filesystem path, not an opaque token."""
    if text.startswith(("/", "./", "../", "~")):
        return True
    if len(text) >= 3 and text[1] == ":" and text[0].isalpha():
        return True
    if "/" in text and "://" not in text:
        last = text.rsplit("/", 1)[-1]
        if "." in last and not last.startswith("."):
            return True
    return False


def _scrub_url(url: str, references: list[str]) -> str:
    """Inspect decoded components, but preserve the original URL byte-for-byte."""
    try:
        parts = urlsplit(url)
    except ValueError:
        raise ConvertError("url: invalid URL") from None
    if contains_credential(unquote(url)):
        raise ConvertError("url: literal credential has no safe replay conversion")
    if parts.password or _literal_secret(unquote(parts.username or "")):
        raise ConvertError("url.userinfo: literal credential has no safe replay conversion")
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if _literal_secret(value, key):
            raise ConvertError(
                f"{_field('url.query', key)}: literal credential has no safe replay conversion"
            )
    if _REFERENCE_RE.search(url):
        references.append("url: environment references are unsupported by existing renderer")
    return url


def _scrub_args(args: Any, references: list[str]) -> list[str]:
    """Refuse credential assignments and unsupported argument interpolation."""
    if not isinstance(args, list):
        return []
    out: list[str] = []
    for index, item in enumerate(args):
        text = str(item)
        key, separator, value = text.partition("=")
        if contains_credential(text) or (
            _literal_secret(value, key)
            if separator
            else _literal_secret(text) and not _looks_like_path_token(text)
        ):
            raise ConvertError(f"args[{index}]: literal credential has no safe replay conversion")
        if _REFERENCE_RE.search(text):
            references.append(
                f"args[{index}]: environment references are unsupported by existing renderer"
            )
        out.append(text)
    return out


def _transport_for(
    tool: str, config: Mapping[str, Any], result: ConvertResult
) -> tuple[str, str | None]:
    """Return (transport, url_key) for the source config."""
    kind = str(config.get("type", "")).strip().lower()
    if tool in ("gemini", "antigravity"):
        if config.get("httpUrl"):
            return "http", "httpUrl"
        if config.get("url"):
            return "sse", "url"
        return "stdio", None
    if tool == "opencode":
        return (
            ("stdio", None)
            if kind == "local" or isinstance(config.get("command"), list)
            else ("http", "url")
        )
    if config.get("command"):
        if kind and kind not in ("stdio", "local"):
            result.drop("type", "type inconsistent with command; stdio assumed")
        return "stdio", None
    if kind in _HTTP_TRANSPORTS:
        return kind, "url"
    if config.get("url"):
        result.default("transport", "no type given; http assumed")
        return "http", "url"
    raise ConvertError("server has neither command nor url")


def to_manifest_entry(
    tool: str, name: str, config: Mapping[str, Any], result: ConvertResult
) -> dict[str, Any]:
    """Build a credential-screened entry, or refuse an unpreservable source."""
    server = _sanitize_name(name, result)
    transport, url_key = _transport_for(tool, config, result)
    entry: dict[str, Any] = {"name": server, "registry": False, "transport": transport}
    references: list[str] = []
    consumed: set[str] = {"type"}
    if transport == "stdio":
        command = config.get("command")
        args = config.get("args", [])
        if tool == "opencode" and isinstance(command, list):
            command, args = (command[0] if command else ""), list(command[1:])
            result.transform("command", "OpenCode command array split into command + args")
            consumed.add("environment")
        if isinstance(command, str) and " " in command.strip() and not args:
            try:
                parts = shlex.split(command)
            except ValueError:
                raise ConvertError("command: invalid command string") from None
            command, args = parts[0], parts[1:]
            result.transform("command", "command string split into command + args")
        if not command:
            raise ConvertError("stdio server without a command")
        entry["command"] = str(command)
        consumed.update({"command", "args"})
        scrubbed_args = _scrub_args(args, references)
        if scrubbed_args:
            entry["args"] = scrubbed_args
        env = config.get("environment") if tool == "opencode" else config.get("env")
        consumed.add("env")
        if isinstance(env, Mapping) and env:
            entry["env"] = _scrub_map(env, server, "env", result, references=references)
        if config.get("cwd"):
            entry["cwd"] = str(config["cwd"])
            consumed.add("cwd")
    else:
        url = str(config.get(url_key or "url", ""))
        consumed.update({"url", "httpUrl"})
        entry["url"] = _scrub_url(url, references)
        raw_headers = config.get("headers") or config.get("http_headers")
        consumed.update({"headers", "http_headers"})
        if isinstance(raw_headers, Mapping) and raw_headers:
            entry["headers"] = _scrub_map(
                raw_headers,
                server,
                "headers" if config.get("headers") else "http_headers",
                result,
                references=references,
                allow_placeholders=tool != "codex",
            )
    tools = config.get("tools")
    consumed.add("tools")
    if isinstance(tools, list) and tools and tools != ["*"]:
        entry["tools"] = [str(t) for t in tools]
    extra: dict[str, Any] = {}
    for key in _PASSTHROUGH_TO_EXTRA.get(tool, ()):
        if key in config:
            extra[key] = config[key]
            consumed.add(key)
    for key in config:
        if key in consumed:
            continue
        if key in ("id", "enabled", "inputs", "envFile", "dev", "environment"):
            result.drop(_field("config", key), "client-specific key not carried into apm.yml")
        else:
            result.drop(_field("config", key), "unknown client key not carried into apm.yml")
    if extra:
        entry["extra"] = extra
        result.keep("extra", "client passthrough keys kept under extra")
    _check_fragment(entry)
    if tool == "codex":
        for field in ("bearer_token_env_var", "env_http_headers", "env_vars"):
            if config.get(field):
                references.append(
                    f"{field}: native environment reference is unsupported by existing renderer"
                )
    if references:
        raise _ReferenceOnly("; ".join(references))
    try:
        MCPDependency.from_dict(dict(entry))
    except ValueError as exc:
        # Never echo the message: MCPDependency interpolates command/url values.
        raise ConvertError(f"entry rejected by MCP validation ({type(exc).__name__})") from None
    return entry


class McpConverter:
    """Produce a manifest fragment or reference-only disposition; write no files."""

    id = "mcp->dependencies.mcp"

    def handles(self, converter_id: str) -> bool:
        return converter_id == self.id

    def convert(self, finding: Finding, dest: Path, *, ctx: ConvertContext) -> ConvertResult:
        payload = finding.payload if isinstance(finding.payload, dict) else None
        if not payload or "config" not in payload:
            raise ConvertError("no MCP payload")
        result = ConvertResult()
        try:
            entry = to_manifest_entry(
                str(payload["tool"]), str(payload["name"]), payload["config"], result
            )
        except _ReferenceOnly as exc:
            result.skipped_reason = str(exc)
            return result
        result.manifest_fragment = {"dependencies": {"mcp": [entry]}}
        return result


CONVERTERS = (McpConverter(),)
