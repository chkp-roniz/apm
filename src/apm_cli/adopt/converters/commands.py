"""Slash commands and workflows -> ``.apm/prompts/<name>.prompt.md``.

``CommandIntegrator`` deploys ``.apm/prompts/*.prompt.md`` as commands and
preserves only ``_PRESERVED_COMMAND_KEYS``; the import keeps the same set.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from apm_cli.integration.command_integrator import _PRESERVED_COMMAND_KEYS

from ..model import Finding
from . import ConvertContext, ConvertError, ConvertResult
from .base import derive_description, emit_markdown, parse_markdown, read_text, refuse_credentials

_GEMINI_ARGS_PREFIX = re.compile(r"^Arguments:\s*\{\{args\}\}\s*\n+")
_CLAUDE_ONLY = (("!`", "inline shell (Claude-only syntax)"), ("@", "file reference"))


def _from_gemini_toml(text: str, result: ConvertResult) -> tuple[dict[str, Any], str]:
    import tomlkit

    try:
        document = tomlkit.parse(text).unwrap()
    except Exception as exc:
        raise ConvertError(f"invalid TOML: {type(exc).__name__}") from exc
    if not isinstance(document, dict):
        raise ConvertError("TOML command must be a table")
    prompt = str(document.pop("prompt", "") or "")
    stripped = _GEMINI_ARGS_PREFIX.sub("", prompt)
    if stripped != prompt:
        result.transform("toml.prompt", "removed injected 'Arguments: {{args}}' prefix")
    if "{{args}}" in stripped:
        stripped = stripped.replace("{{args}}", "$ARGUMENTS")
        result.transform("toml.prompt", "{{args}} -> $ARGUMENTS")
    for marker in ("!{", "@{"):
        if marker in stripped:
            result.keep("toml.prompt", f"Gemini '{marker}...}}' injection kept verbatim")
    return document, stripped


class CommandsConverter:
    """Convert markdown or TOML commands into APM prompts."""

    id = "commands->prompt"

    def handles(self, converter_id: str) -> bool:
        return converter_id.removesuffix("->prompt") in {
            "claude_command",
            "gemini_command",
            "opencode_command",
            "windsurf_workflow",
        }

    def convert(self, finding: Finding, dest: Path, *, ctx: ConvertContext) -> ConvertResult:
        if finding.abs_path is None:
            raise ConvertError("no source path")
        text = read_text(finding.abs_path, ctx.limits.max_file_bytes)
        # Screen both native syntaxes before parsing or filtering unknown keys.
        refuse_credentials(text)
        result = ConvertResult()
        if finding.abs_path.suffix == ".toml":
            meta, body = _from_gemini_toml(text, result)
        else:
            meta, body = parse_markdown(text, result)
            for marker, label in _CLAUDE_ONLY:
                if marker == "@" and not re.search(r"(^|\s)@[\w./-]+", body):
                    continue
                if marker in body:
                    result.keep("body", f"{label} kept verbatim")
        out: dict[str, Any] = {}
        for index, (key, value) in enumerate(meta.items(), 1):
            if key in _PRESERVED_COMMAND_KEYS and value not in (None, ""):
                out[key] = value
                result.keep(f"frontmatter.{key}")
            elif key not in _PRESERVED_COMMAND_KEYS:
                result.drop(f"frontmatter.field[{index}]", "not in the portable command key set")
        if not out.get("description"):
            derived = derive_description(body)
            if derived:
                out = {"description": derived, **out}
                result.default("frontmatter.description", "derived from first sentence")
        if not body.strip():
            raise ConvertError("command body is empty")
        emit_markdown(dest, out, body)
        result.written.append(dest)
        return result


CONVERTERS = (CommandsConverter(),)
