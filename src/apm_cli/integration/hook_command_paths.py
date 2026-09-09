"""Canonical parsing for plugin-root paths in hook commands."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

PLUGIN_ROOT_NAMES = (
    "CLAUDE_PLUGIN_ROOT",
    "CURSOR_PLUGIN_ROOT",
    "KIRO_PLUGIN_ROOT",
    "PLUGIN_ROOT",
)

_PLUGIN_ROOT_TOKEN = rf"\$\{{(?:{'|'.join(map(re.escape, PLUGIN_ROOT_NAMES))})\}}"
_PLUGIN_ROOT_PATH = r"[\\/](?:\\[ \t;&|<>()]|[^\s\"';&|<>()])+"
_QUOTED_PLUGIN_ROOT_SPLIT = re.compile(
    rf"(?P<quote>[\"'])(?P<var>{_PLUGIN_ROOT_TOKEN})"
    rf"(?P=quote)(?P<path>{_PLUGIN_ROOT_PATH})"
)
_PLUGIN_ROOT_PATH_REFERENCE = re.compile(rf"{_PLUGIN_ROOT_TOKEN}({_PLUGIN_ROOT_PATH})")
_PLUGIN_ROOT_REFERENCE = re.compile(rf"{_PLUGIN_ROOT_TOKEN}[^\s\"']*")
_RELATIVE_SCRIPT_PATH = re.compile(
    r"""(?<![.$])((?:(?<=")\.[\\/][^"\n]+(?=")|(?<=')\.[\\/][^'\n]+(?=')|\.[\\/][^\s"';&|<>()]+))"""
)


def normalize_quoted_plugin_root(command: str) -> str:
    """Move a split closing quote after its plugin-relative path."""
    return _QUOTED_PLUGIN_ROOT_SPLIT.sub(lambda match: f'"{match["var"]}{match["path"]}"', command)


def iter_plugin_root_paths(command: str) -> Iterator[re.Match[str]]:
    """Yield supported plugin-root references that include a path."""
    return iter(_PLUGIN_ROOT_PATH_REFERENCE.finditer(command))


def plugin_root_relative_path(path: str) -> str:
    """Decode shell-escaped separators and spaces into a package-relative path."""
    unescaped = re.sub(r"\\([ \t;&|<>()])", r"\1", path)
    return unescaped.replace("\\", "/").lstrip("/")


def unresolved_plugin_root_references(command: str) -> tuple[str, ...]:
    """Return residual supported references once each, preserving command order.

    Detection is diagnostic only; containment enforcement remains with the caller.
    """
    return tuple(dict.fromkeys(_PLUGIN_ROOT_REFERENCE.findall(command)))


def residual_plugin_root_has_path(command: str, reference: str) -> bool:
    """Return whether a residual is followed by a direct or split-quoted path."""
    suffix = rf"{re.escape(reference)}(?:[\\/]|[\"'][\\/])"
    return re.search(suffix, command) is not None


def iter_relative_script_paths(command: str) -> Iterator[re.Match[str]]:
    """Yield relative script references without re-matching plugin-root paths."""
    return iter(_RELATIVE_SCRIPT_PATH.finditer(command))


# This lexer deliberately supports path words, not arbitrary shell evaluation.
# Its offsets let consumers replace references without rebuilding a program.
_PROJECT_ROOT_NAMES = ("CLAUDE_PROJECT_DIR", "workspaceFolder")
_PROJECT_ROOT = re.compile(
    r"^(?:\$(?:env:)?(?:" + "|".join(_PROJECT_ROOT_NAMES) + r")"
    r"|\$\{(?:" + "|".join(_PROJECT_ROOT_NAMES) + r")\})(?=/|$)"
)
_SCRIPT_SUFFIX = re.compile(r"\.(?:sh|bash|zsh|py|js|mjs|cjs|ps1)$", re.IGNORECASE)
_SHELL_META = frozenset(";&|<>()")


class UnsupportedHookCommand(ValueError):
    """A command cannot be imported with the bounded, preserving path contract."""


@dataclass(frozen=True)
class HookScriptReference:
    """A path word and its exact source span, with no shell evaluation."""

    start: int
    end: int
    path: str
    project_relative: bool = False
    quote: str = ""

    def render(self, relative: str) -> str:
        """Encode a replacement path using the original word's quoting style."""
        if self.quote == '"' or (not self.quote and any(c.isspace() for c in relative)):
            return '"' + relative.replace("\\", "\\\\").replace('"', '\\"') + '"'
        if self.quote == "'":
            return "'" + relative.replace("'", "'\\''") + "'"
        return _escape_path(relative)


def _escape_path(value: str) -> str:
    """Quote only path characters with shell significance in an unquoted word."""
    return re.sub(r"([^A-Za-z0-9_./-])", r"\\\1", value)


def _shell_path_words(command: str) -> Iterator[tuple[int, int]]:
    """Locate whole words while retaining shell operators, redirects and quotes."""
    i = 0
    redirect = False
    while i < len(command):
        char = command[i]
        if char.isspace():
            i += 1
            continue
        if char == "#":
            newline = command.find("\n", i)
            i = len(command) if newline < 0 else newline + 1
            continue
        if char in _SHELL_META:
            if command[i : i + 2] == "<<":
                raise UnsupportedHookCommand("here-documents are reference-only")
            redirect = char in "<>"
            i += 1
            continue
        start = i
        quote = ""
        while i < len(command):
            char = command[i]
            if not quote and (char.isspace() or char in _SHELL_META):
                break
            if char == "\\" and quote != "'":
                if i + 1 == len(command) or command[i + 1] == "\n":
                    raise UnsupportedHookCommand("shell continuations are reference-only")
                i += 2
                continue
            if char in "\"'":
                if not quote:
                    quote = char
                elif quote == char:
                    quote = ""
            i += 1
        if quote:
            raise UnsupportedHookCommand("unclosed shell quote")
        if not redirect:
            yield start, i
        redirect = False


def _script_reference(word: str, start: int, end: int) -> HookScriptReference | None:
    """Recognize a single literal path or project-root reference."""
    quote = ""
    value = word
    if word[0] in "\"'":
        quote = word[0]
        if word[-1] == quote:
            value = word[1:-1]
        else:
            close = word.find(quote, 1)
            if close < 0 or not word[close + 1 :].startswith("/"):
                raise UnsupportedHookCommand("concatenated shell words are reference-only")
            root = word[1:close]
            if not _PROJECT_ROOT.fullmatch(root):
                raise UnsupportedHookCommand("concatenated shell paths are reference-only")
            value = root + word[close + 1 :]
    project = _PROJECT_ROOT.match(value)
    if any(name in value for name in _PROJECT_ROOT_NAMES) and project is None:
        raise UnsupportedHookCommand("unsupported project-directory expression")
    if project and quote == "'":
        raise UnsupportedHookCommand("literal project-directory variables are reference-only")
    path = value[project.end() :].removeprefix("/") if project else value
    if not project and not (
        path.startswith(("./", "../", "/", "~")) or "/" in path or _SCRIPT_SUFFIX.search(path)
    ):
        return None
    if any(char in path for char in "$`*?[]{}\"'") or path.startswith(("/", "~")):
        raise UnsupportedHookCommand("dynamic or machine-local script paths are reference-only")
    if quote != "'":
        # Only escaped whitespace and shell punctuation are supported; Windows
        # backslash paths and general escape processing need a native reader.
        if re.search(r"\\[^ \t;&|<>()]", path):
            raise UnsupportedHookCommand("unsupported script path escape")
        path = re.sub(r"\\([ \t;&|<>()])", r"\1", path)
    if not path:
        raise UnsupportedHookCommand("project directory without a script path")
    return HookScriptReference(start, end, path, project is not None, quote)


def project_script_references(command: str) -> tuple[HookScriptReference, ...]:
    """Return bounded path spans or reject unsupported syntax, without I/O.

    Unrelated variable words and shell control/redirection syntax are retained.
    Command substitutions and here-documents are deliberately reference-only:
    copying a subset of their referenced scripts would misrepresent the hook.
    """
    if "$(" in command or "`" in command:
        raise UnsupportedHookCommand("command substitutions are reference-only")
    references = []
    for start, end in _shell_path_words(command):
        reference = _script_reference(command[start:end], start, end)
        if reference is not None:
            references.append(reference)
    return tuple(references)
