"""Native hook schema adapters around the vendor-neutral hook IR."""

from __future__ import annotations

from typing import Any

from apm_cli.hook_contract import (
    HookDocument,
    HookHandler,
    _entries_to_ir,
    _handler_to_ir,
)

_ANTIGRAVITY_NESTED_EVENTS: frozenset[str] = frozenset({"PreToolUse", "PostToolUse"})


def _handler_from_ir(handler: HookHandler, *, timeout_milliseconds: bool) -> dict[str, Any]:
    """Render a portable handler into one native command object."""
    result = dict(handler.metadata)
    if handler.command is not None:
        result["command"] = handler.command
    if handler.timeout_seconds is not None:
        result["timeout"] = (
            handler.timeout_seconds * 1000 if timeout_milliseconds else handler.timeout_seconds
        )
    if handler.provenance:
        result["_apm_source"] = handler.provenance
    return result


def _render_nested_document(
    document: HookDocument,
    *,
    timeout_milliseconds: bool,
    default_matcher: str | None = None,
) -> list:
    """Render neutral bindings into a matcher plus nested-handlers schema."""
    result: list = []
    for binding in document.bindings:
        if "raw_entry" in binding.metadata:
            result.append(binding.metadata["raw_entry"])
            continue
        outer = dict(binding.metadata)
        if binding.matcher is not None or default_matcher is not None:
            outer["matcher"] = binding.matcher or default_matcher
        outer["hooks"] = [
            _handler_from_ir(handler, timeout_milliseconds=timeout_milliseconds)
            for handler in binding.handlers
        ]
        provenance = binding.provenance or next(
            (handler.provenance for handler in binding.handlers if handler.provenance is not None),
            None,
        )
        if provenance:
            outer["_apm_source"] = provenance
            for handler in outer["hooks"]:
                handler.pop("_apm_source", None)
        result.append(outer)
    return result


def _copilot_keys_to_gemini(hook: dict) -> None:
    """Compatibility edge helper backed by the neutral handler model."""
    rendered = _handler_from_ir(
        _handler_to_ir(hook, None),
        timeout_milliseconds=True,
    )
    hook.clear()
    hook.update(rendered)


def _to_gemini_hook_entries(entries: list) -> list:
    """Render portable bindings in Gemini's nested millisecond schema."""
    return _render_nested_document(
        _entries_to_ir(entries),
        timeout_milliseconds=True,
    )


def _to_claude_hook_entries(entries: list) -> list:
    """Render portable bindings in Claude's nested matcher schema."""
    return _render_nested_document(
        _entries_to_ir(entries),
        timeout_milliseconds=False,
        default_matcher="*",
    )


def _to_antigravity_hook_entries(entries: list, event_name: str) -> list:
    """Render portable bindings in Antigravity's event-dependent schema."""
    document = _entries_to_ir(entries, event_name)
    if event_name in _ANTIGRAVITY_NESTED_EVENTS:
        return _render_nested_document(
            document,
            timeout_milliseconds=False,
            default_matcher="*",
        )

    flat: list[dict[str, Any]] = []
    for binding in document.bindings:
        if "raw_entry" in binding.metadata:
            flat.append(binding.metadata["raw_entry"])
            continue
        for handler in binding.handlers:
            rendered = _handler_from_ir(handler, timeout_milliseconds=False)
            if binding.provenance and "_apm_source" not in rendered:
                rendered["_apm_source"] = binding.provenance
            flat.append(rendered)
    return flat


# ---------------------------------------------------------------------------
# Inverse direction: native hook documents -> neutral bindings
# (used by ``apm init --discover --write``).
# ---------------------------------------------------------------------------

_CURSOR_TO_CANONICAL: dict[str, str] = {
    "beforeSubmitPrompt": "UserPromptSubmit",
    "stop": "Stop",
    "sessionStart": "SessionStart",
}
_WINDSURF_TO_CANONICAL: dict[str, str] = {
    "pre_user_prompt": "UserPromptSubmit",
}
_CANONICAL_EVENT_TARGETS = frozenset(
    {"claude", "cursor", "codex", "windsurf", "antigravity", "vscode"}
)


def _copilot_to_canonical() -> dict[str, str]:
    """camelCase Copilot event names -> Claude PascalCase canonical names."""
    from apm_cli.integration.hook_integrator import _HOOK_EVENT_MAP

    inverse: dict[str, str] = {}
    for source, target in _HOOK_EVENT_MAP["copilot"].items():
        if source[0].isupper():
            inverse.setdefault(target, source)
    return inverse


def canonical_hook_event(tool: str, event: str) -> str:
    """Invert the deployment owner, preferring its first portable spelling.

    In particular ``Stop`` wins over ``AgentStop`` and ``PreTaskExecution``
    wins over ``PreTaskExec``. Reader-only aliases live at this native edge;
    adoption must not maintain its own vocabulary.
    """
    from apm_cli.integration.hook_integrator import _HOOK_EVENT_MAP

    portable = set(_copilot_to_canonical().values())
    inverse: dict[str, str] = {}
    for source, native in _HOOK_EVENT_MAP.get(tool, {}).items():
        if source in portable:
            inverse.setdefault(native, source)
    if tool == "cursor":
        inverse.update(_CURSOR_TO_CANONICAL)
    elif tool == "windsurf":
        inverse.update(_WINDSURF_TO_CANONICAL)
    return inverse.get(event, event)


def event_portability(event: str) -> tuple[list[str], list[str]]:
    """Return native and unmapped deployment targets from the hook owner."""
    from apm_cli.integration.hook_integrator import (
        _HOOK_EVENT_EXPECTED_CASING,
        _HOOK_EVENT_MAP,
    )

    portable = set(_copilot_to_canonical().values())
    native: list[str] = []
    passthrough: list[str] = []
    for target in sorted(_HOOK_EVENT_EXPECTED_CASING):
        mapped = event in _HOOK_EVENT_MAP.get(target, {})
        identity = target in _CANONICAL_EVENT_TARGETS and event in portable
        (native if mapped or identity else passthrough).append(target)
    return native, passthrough


def _from_claude_hook_entries(entries: list, event: str) -> HookDocument:
    """Claude / Codex / Cursor / Windsurf entries are already the neutral shape."""
    return _entries_to_ir(entries, canonical_hook_event("claude", event))


def _from_gemini_hook_entries(entries: list, event: str) -> HookDocument:
    """Gemini stores millisecond timeouts and its own event vocabulary."""
    from dataclasses import replace

    document = _entries_to_ir(entries, canonical_hook_event("gemini", event))
    bindings = []
    for binding in document.bindings:
        handlers = tuple(
            replace(h, timeout_seconds=h.timeout_seconds / 1000)
            if isinstance(h.timeout_seconds, (int, float))
            else h
            for h in binding.handlers
        )
        bindings.append(replace(binding, handlers=handlers))
    return HookDocument(bindings=tuple(bindings))


def _from_antigravity_hook_entries(entries: list, event: str) -> HookDocument:
    """Antigravity nests Pre/PostToolUse and flattens every other event."""
    return _entries_to_ir(entries, event)


def _from_copilot_hook_file(payload: dict) -> dict[str, HookDocument]:
    """Copilot per-file hook document -> canonical event -> bindings."""
    inverse = _copilot_to_canonical()
    hooks = payload.get("hooks") if isinstance(payload, dict) else None
    result: dict[str, HookDocument] = {}
    if not isinstance(hooks, dict):
        return result
    for event, entries in hooks.items():
        if isinstance(entries, list):
            canonical = inverse.get(event, event)
            document = _entries_to_ir(entries, canonical)
            previous = result.get(canonical, HookDocument(bindings=()))
            result[canonical] = HookDocument(bindings=previous.bindings + document.bindings)
    return result


def _from_kiro_hook_docs(payload: dict) -> dict[str, HookDocument]:
    """Kiro v1 ``{"version": "v1", "hooks": [{trigger, matcher, action}]}`` -> bindings."""
    from apm_cli.hook_contract import HookBinding

    result: dict[str, list[HookBinding]] = {}
    hooks = payload.get("hooks") if isinstance(payload, dict) else None
    if str(payload.get("version", "")).lower() != "v1" or not isinstance(hooks, list):
        return {}
    for hook in hooks:
        if not isinstance(hook, dict):
            continue
        trigger = str(hook.get("trigger", "")).strip()
        action = hook.get("action")
        if not trigger or not isinstance(action, dict):
            continue
        canonical = canonical_hook_event("kiro", trigger)
        metadata: dict[str, Any] = {}
        if action.get("type") == "command" and action.get("command"):
            command = str(action["command"])
        else:
            command = None
            metadata = {"type": "prompt", "prompt": action.get("prompt", "")}
        handler = HookHandler(
            command=command,
            timeout_seconds=action.get("timeout"),
            metadata=metadata,
        )
        result.setdefault(canonical, []).append(
            HookBinding(event=canonical, handlers=(handler,), matcher=hook.get("matcher"))
        )
    return {event: HookDocument(bindings=tuple(b)) for event, b in result.items()}


def _from_cursor_hook_entries(entries: list, event: str) -> HookDocument:
    return _entries_to_ir(entries, canonical_hook_event("cursor", event))


def _from_windsurf_hook_entries(entries: list, event: str) -> HookDocument:
    return _entries_to_ir(entries, canonical_hook_event("windsurf", event))


def read_native_hook_document(
    tool: str, payload: dict, *, merged: bool, format_id: str | None = None
) -> HookDocument | None:
    """Read explicitly supported native shapes; unknown formats have no fallback.

    Merged payloads are the host-authored event slices from discovery. Native
    named containers are flattened into bindings without treating the container
    name as an executable event. Event grouping uses ``HookBinding.event``.
    """
    if format_id is not None:
        from apm_cli.integration.targets import KNOWN_TARGETS

        profile = KNOWN_TARGETS.get(tool)
        mapping = profile.primitives.get("hooks") if profile is not None else None
        if mapping is None or format_id != mapping.format_id:
            return None
    if not merged:
        if tool == "copilot":
            documents = _from_copilot_hook_file(payload)
        elif tool == "kiro":
            documents = _from_kiro_hook_docs(payload)
            if not documents:
                return None
        else:
            return None
        return HookDocument(bindings=tuple(b for d in documents.values() for b in d.bindings))
    readers = {
        "claude": _from_claude_hook_entries,
        "codex": _from_claude_hook_entries,
        "cursor": _from_cursor_hook_entries,
        "windsurf": _from_windsurf_hook_entries,
        "gemini": _from_gemini_hook_entries,
        "antigravity": _from_antigravity_hook_entries,
    }
    reader = readers.get(tool)
    if reader is None or not isinstance(payload.get("hooks"), dict):
        return None
    bindings = []
    for key, entries in payload["hooks"].items():
        if not isinstance(key, str) or not isinstance(entries, list):
            return None
        event = key.rpartition(":")[2] if tool == "antigravity" else key
        bindings.extend(reader(entries, event).bindings)
    return HookDocument(bindings=tuple(bindings))


def _document_to_entries(document: HookDocument) -> list:
    """Render neutral bindings as the wrapped Claude-shaped source grammar."""
    entries = _render_nested_document(document, timeout_milliseconds=False)
    for entry in entries:
        if isinstance(entry, dict):
            entry.pop("_apm_source", None)
            for handler in entry.get("hooks", []):
                if isinstance(handler, dict):
                    handler.pop("_apm_source", None)
    return entries
