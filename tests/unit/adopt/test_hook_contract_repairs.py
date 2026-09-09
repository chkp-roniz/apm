"""Import-and-render contract regressions; no imported code is executed."""

from __future__ import annotations

import json
import stat
from dataclasses import replace
from pathlib import Path
from typing import IO, Any

import pytest

from apm_cli.adopt.converters import ConvertContext, ConvertError
from apm_cli.adopt.converters.agents import AgentsConverter
from apm_cli.adopt.converters.hooks import HooksConverter
from apm_cli.adopt.model import Finding, HarnessKind, Importability, Ownership, Scope
from apm_cli.adopt.redact import Redactor
from apm_cli.adopt.registry import ScanContext
from apm_cli.adopt.scanners.hooks import HooksScanner
from apm_cli.hook_contract import parse_hook_source
from apm_cli.integration.hook_integrator import HookIntegrator
from apm_cli.integration.hook_native_formats import _to_gemini_hook_entries
from apm_cli.integration.opencode_frontmatter import validate_opencode_frontmatter
from apm_cli.models.apm_package import APMPackage, PackageInfo
from apm_cli.security.gate import ScanVerdict
from apm_cli.utils.yaml_io import loads_frontmatter

from .conftest import write

pytestmark = pytest.mark.component


def _context(root: Path, *, copy_scripts: bool = False) -> ConvertContext:
    return ConvertContext(root, Scope.PROJECT, Redactor(root), include_hook_scripts=copy_scripts)


def _finding(tool: str, payload: dict | None = None, path: Path | None = None) -> Finding:
    return Finding(
        id="native-hook",
        tool=tool,
        scope=Scope.PROJECT,
        kind=HarnessKind.HOOK if payload is not None else HarnessKind.AGENT,
        display_path="native.json" if payload is not None else "reviewer.md",
        importability=Importability.CONVERTIBLE,
        ownership=Ownership.HOST_OWNED,
        payload=payload,
        abs_path=path,
        format_id=f"{tool}_agent" if payload is None else None,
    )


def _hooks(command: str, event: str = "PreToolUse") -> dict:
    return {"hooks": {event: [{"matcher": "Read", "hooks": [{"command": command}]}]}}


@pytest.mark.parametrize(
    ("tool", "event", "canonical", "timeout", "expected_timeout"),
    [
        ("gemini", "BeforeTool", "PreToolUse", 2500, 2.5),
        ("cursor", "beforeSubmitPrompt", "UserPromptSubmit", 2, 2),
        ("windsurf", "pre_user_prompt", "UserPromptSubmit", 2, 2),
    ],
)
def test_native_aliases_merge_without_losing_handlers(
    tmp_path: Path, tool: str, event: str, canonical: str, timeout: int, expected_timeout: float
) -> None:
    payload = _hooks("echo first", event)
    payload["hooks"][event][0]["hooks"][0]["timeout"] = timeout
    payload["hooks"][canonical] = [{"hooks": [{"command": "echo second"}]}]
    dest = tmp_path / ".apm/hooks/native.json"
    result = HooksConverter().convert(_finding(tool, payload), dest, ctx=_context(tmp_path))
    output = json.loads(dest.read_text())
    assert result.written == [dest]
    assert list(output["hooks"]) == [canonical]
    entries = output["hooks"][canonical]
    assert [h["command"] for e in entries for h in e["hooks"]] == ["echo first", "echo second"]
    assert entries[0]["matcher"] == "Read"
    assert entries[0]["hooks"][0]["timeout"] == expected_timeout
    assert len(parse_hook_source(output).commands) == 2
    if tool == "gemini":
        assert _to_gemini_hook_entries(entries)[0]["hooks"][0]["timeout"] == timeout
    rewritten, copies = HookIntegrator()._rewrite_hooks_data(
        output, tmp_path, "fixture", "claude", hook_file_dir=dest.parent
    )
    assert list(rewritten["hooks"]) == [canonical]
    assert copies == []


def test_project_path_rewrite_preserves_shell_program(tmp_path: Path) -> None:
    command = 'python "$CLAUDE_PROJECT_DIR/scripts/check.py" && echo "$HOME" > result.txt'
    dest = tmp_path / ".apm/hooks/native.json"
    HooksConverter().convert(_finding("claude", _hooks(command)), dest, ctx=_context(tmp_path))
    output = json.loads(dest.read_text())
    assert output["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == (
        'python "./scripts/check.py" && echo "$HOME" > result.txt'
    )


@pytest.mark.parametrize(
    "command",
    [
        'python "${CLAUDE_PROJECT_DIR:-/elsewhere}/check.py"',
        'python "$CLAUDE_PROJECT_DIR/$(echo script).py"',
        'python "$CLAUDE_PROJECT_DIR/scripts/$SCRIPT.py"',
        'python "$CLAUDE_PROJECT_DIR/scripts/check.py',
    ],
)
def test_unsupported_shell_forms_produce_no_partial_output(tmp_path: Path, command: str) -> None:
    write(tmp_path / "scripts/ok.sh", "#!/bin/sh\nexit 0\n")
    payload = _hooks("./scripts/ok.sh")
    payload["hooks"]["Stop"] = [{"hooks": [{"command": command}]}]
    dest = tmp_path / ".apm/hooks/native.json"
    result = HooksConverter().convert(
        _finding("claude", payload), dest, ctx=_context(tmp_path, copy_scripts=True)
    )
    assert result.skipped_reason
    assert result.written == []
    assert not dest.parent.exists()


def test_unknown_native_reader_is_reference_only(tmp_path: Path) -> None:
    dest = tmp_path / ".apm/hooks/native.json"
    result = HooksConverter().convert(
        _finding("future-tool", _hooks("echo test")), dest, ctx=_context(tmp_path)
    )
    assert result.skipped_reason
    assert not dest.exists()


@pytest.mark.parametrize("format_id", ["unknown", "future_hooks", "claude_hooks_v2"])
def test_unknown_hook_format_for_known_tool_is_reference_only(
    tmp_path: Path, format_id: str
) -> None:
    dest = tmp_path / ".apm/hooks/native.json"
    finding = replace(_finding("claude", _hooks("echo test")), format_id=format_id)
    result = HooksConverter().convert(finding, dest, ctx=_context(tmp_path))
    assert result.skipped_reason
    assert result.written == []
    assert not dest.parent.exists()


def test_hook_inventory_keeps_every_lexical_reference(tmp_path: Path) -> None:
    for name in ("one.py", "two file.sh", "three.js", "redirect.sh", "comment.sh"):
        write(tmp_path / "scripts" / name, "# fixture\n")
    payload = _hooks(
        'python "$CLAUDE_PROJECT_DIR"/scripts/one.py && '
        'sh "${workspaceFolder}/scripts/two file.sh"; '
        'node ./scripts/three.js ./scripts/one.py > "./scripts/redirect.sh" '
        "# ./scripts/comment.sh"
    )
    write(tmp_path / ".claude/settings.json", json.dumps(payload))
    ctx = ScanContext(tmp_path, Scope.PROJECT, (), Redactor(tmp_path))
    findings = list(HooksScanner().scan(ctx))
    scripts = [f for f in findings if f.kind is HarnessKind.HOOK_SCRIPT]
    assert [f.display_path for f in scripts] == [
        "scripts/one.py",
        "scripts/two file.sh",
        "scripts/three.js",
    ]
    assert all(
        f.size_bytes and f.notes == ("referenced by .claude/settings.json",) for f in scripts
    )
    assert ctx.errors == []


@pytest.mark.parametrize(
    "unsupported",
    [
        'sh "$CLAUDE_PROJECT_DIR/scripts/$(echo private-value).sh"',
        'sh "$CLAUDE_PROJECT_DIR/scripts/private-value.sh',
        "sh ./scripts/ok.sh <<private-value",
    ],
)
def test_unsupported_hook_inventory_has_safe_reference_note(
    tmp_path: Path, unsupported: str
) -> None:
    write(tmp_path / "scripts/ok.sh", "#!/bin/sh\nexit 0\n")
    payload = _hooks(unsupported)
    payload["hooks"]["Stop"] = [{"command": "./scripts/ok.sh"}]
    write(tmp_path / ".claude/settings.json", json.dumps(payload))
    ctx = ScanContext(tmp_path, Scope.PROJECT, (), Redactor(tmp_path))
    findings = list(HooksScanner().scan(ctx))
    hook = next(f for f in findings if f.kind is HarnessKind.HOOK)
    assert any("reference-only" in note and "script inventory" in note for note in hook.notes)
    assert "private-value" not in " ".join(hook.notes)
    assert [f.display_path for f in findings if f.kind is HarnessKind.HOOK_SCRIPT] == [
        "scripts/ok.sh"
    ]
    assert ctx.errors == []


@pytest.mark.parametrize("copy_scripts", [False, True])
def test_source_target_hook_replay_never_copies_its_own_output(
    tmp_path: Path, copy_scripts: bool
) -> None:
    original = write(tmp_path / ".claude/hooks/notify.sh", "#!/bin/sh\nexit 0\n")
    payload = _hooks('"$CLAUDE_PROJECT_DIR"/.claude/hooks/notify.sh')
    dest = tmp_path / ".apm/hooks/claude-native.json"
    HooksConverter().convert(
        _finding("claude", payload), dest, ctx=_context(tmp_path, copy_scripts=copy_scripts)
    )
    package = PackageInfo(
        package=APMPackage(name="project", version="1.0.0"), install_path=tmp_path
    )
    before = original.read_bytes()
    integrator = HookIntegrator()
    first = integrator.integrate_package_hooks_claude(package, tmp_path)
    settings = (tmp_path / ".claude/settings.json").read_bytes()
    deployed = {p.relative_to(tmp_path): p.read_bytes() for p in first.target_paths}
    second = integrator.integrate_package_hooks_claude(package, tmp_path)
    assert (tmp_path / ".claude/settings.json").read_bytes() == settings
    assert {p.relative_to(tmp_path): p.read_bytes() for p in second.target_paths} == deployed
    assert original.read_bytes() == before
    if not copy_scripts:
        command = parse_hook_source(json.loads(settings)).commands[0].command
        assert command == '"${CLAUDE_PROJECT_DIR}/.claude/hooks/notify.sh"'
        assert first.scripts_copied == second.scripts_copied == 0
        assert deployed == {}
        assert not (tmp_path / ".claude/hooks/project").exists()
    else:
        assert first.scripts_copied == 1
        assert deployed


def test_dependency_native_script_bundle_still_deploys(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / ".claude").mkdir(parents=True)
    package_root = tmp_path / "dependency"
    source = write(package_root / ".claude/hooks/notify.sh", "#!/bin/sh\nexit 0\n")
    write(package_root / ".apm/hooks/native.json", json.dumps(_hooks("./.claude/hooks/notify.sh")))
    package = PackageInfo(
        package=APMPackage(name="dependency", version="1.0.0"), install_path=package_root
    )
    result = HookIntegrator().integrate_package_hooks_claude(package, project)
    assert result.scripts_copied == 1
    assert (project / ".claude/hooks/dependency/.claude/hooks/notify.sh").read_bytes() == (
        source.read_bytes()
    )


@pytest.mark.parametrize("target", ["vscode", "cursor", "codex", "windsurf", "kiro"])
@pytest.mark.parametrize("reference", ["./notify.sh", "${PLUGIN_ROOT}/notify.sh"])
def test_root_local_executable_keeps_explicit_relative_path(
    tmp_path: Path, target: str, reference: str
) -> None:
    source = write(tmp_path / "notify.sh", "#!/bin/sh\nexit 0\n")
    rewritten, copies = HookIntegrator()._rewrite_command_for_target(
        reference,
        tmp_path,
        "project",
        target,
        hook_file_dir=tmp_path / ".apm/hooks",
        project_root=tmp_path,
    )
    assert rewritten == "./notify.sh", "a bare filename would become a PATH lookup"
    assert copies == []
    assert source.read_text() == "#!/bin/sh\nexit 0\n"


def test_script_copy_refuses_recognizable_credentials(tmp_path: Path) -> None:
    token = "ghp_" + "A" * 40
    write(tmp_path / "scripts/check.sh", f"#!/bin/sh\nTOKEN={token}\n")
    dest = tmp_path / ".apm/hooks/native.json"
    with pytest.raises(ConvertError, match="refusing") as caught:
        HooksConverter().convert(
            _finding("claude", _hooks("./scripts/check.sh")),
            dest,
            ctx=_context(tmp_path, copy_scripts=True),
        )
    assert token not in str(caught.value)
    assert not dest.parent.exists()


@pytest.mark.parametrize("data", [b"#!/bin/sh\n\xff", b"#!/bin/sh\n\x00"])
def test_non_text_script_is_not_copied(tmp_path: Path, data: bytes) -> None:
    script = tmp_path / "check.sh"
    script.write_bytes(data)
    dest = tmp_path / ".apm/hooks/native.json"
    with pytest.raises(ConvertError):
        HooksConverter().convert(
            _finding("claude", _hooks("./check.sh")),
            dest,
            ctx=_context(tmp_path, copy_scripts=True),
        )
    assert not dest.parent.exists()


def test_script_containment_checked_before_content_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = write(tmp_path / "outside/check.sh", "#!/bin/sh\nexit 0\n")
    (root / "scripts").symlink_to(outside.parent, target_is_directory=True)
    original = Path.open
    reads = []

    def open_file(path: Path, *args: Any, **kwargs: Any) -> IO[Any]:
        reads.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_file)
    dest = root / ".apm/hooks/native.json"
    with pytest.raises(ConvertError):
        HooksConverter().convert(
            _finding("claude", _hooks("./scripts/check.sh")),
            dest,
            ctx=_context(root, copy_scripts=True),
        )
    assert reads == []
    assert not dest.parent.exists()


def test_copied_scripts_have_source_scoped_destinations_and_checked_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write(tmp_path / "scripts/check.sh", f'#!/bin/sh\ntouch "{tmp_path / "executed"}"\n')
    source.chmod(0o751)
    checked = source.read_bytes()
    from apm_cli.adopt.converters import hooks

    original = hooks.SecurityGate.scan_text

    def mutate_after_scan(text: str, name: str) -> ScanVerdict:
        verdict = original(text, name)
        if name == source.name:
            source.write_bytes(b"changed after admission\n")
        return verdict

    monkeypatch.setattr(hooks.SecurityGate, "scan_text", mutate_after_scan)
    dest = tmp_path / ".apm/hooks/claude-native.json"
    result = HooksConverter().convert(
        _finding("claude", _hooks("./scripts/check.sh")),
        dest,
        ctx=_context(tmp_path, copy_scripts=True),
    )
    copies = [p for p in result.written if p != dest]
    assert len(copies) == 1
    assert copies[0].is_relative_to(dest.parent / dest.stem / "scripts")
    assert copies[0].read_bytes() == checked
    assert stat.S_IMODE(copies[0].stat().st_mode) == 0o751
    command = json.loads(dest.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert command == "./" + copies[0].relative_to(dest.parent).as_posix()
    assert not (tmp_path / "executed").exists()


@pytest.mark.parametrize("variant", ["leaf-symlink", "directory", "oversize", "hidden"])
def test_unsafe_script_admission_is_explicit_refusal(tmp_path: Path, variant: str) -> None:
    script = tmp_path / "check.sh"
    if variant == "leaf-symlink":
        script.symlink_to(write(tmp_path / "real.sh", "#!/bin/sh\nexit 0\n"))
    elif variant == "directory":
        script.mkdir()
    else:
        script.write_bytes(b"x" * 1_048_577 if variant == "oversize" else b"echo \xe2\x80\xae\n")
    dest = tmp_path / ".apm/hooks/native.json"
    with pytest.raises(ConvertError):
        HooksConverter().convert(
            _finding("claude", _hooks("./check.sh")),
            dest,
            ctx=_context(tmp_path, copy_scripts=True),
        )
    assert not dest.parent.exists()


def test_contained_directory_alias_is_admitted(tmp_path: Path) -> None:
    source = write(tmp_path / "real/check.sh", "#!/bin/sh\nexit 0\n")
    (tmp_path / "scripts").symlink_to(source.parent, target_is_directory=True)
    dest = tmp_path / ".apm/hooks/native.json"
    result = HooksConverter().convert(
        _finding("claude", _hooks("./scripts/check.sh")),
        dest,
        ctx=_context(tmp_path, copy_scripts=True),
    )
    copies = [p for p in result.written if p != dest]
    assert copies[0].read_bytes() == source.read_bytes()


def test_sources_and_same_basenames_never_share_script_outputs(tmp_path: Path) -> None:
    first = write(tmp_path / "one/check.sh", "#!/bin/sh\nexit 0\n")
    second = write(tmp_path / "two/check.sh", "#!/bin/sh\nexit 1\n")
    payload = _hooks('./one/check.sh && ./two/check.sh > "./not-an-input.sh"')
    results = []
    for tool in ("claude", "cursor"):
        dest = tmp_path / f".apm/hooks/{tool}-native.json"
        result = HooksConverter().convert(
            _finding(tool, payload), dest, ctx=_context(tmp_path, copy_scripts=True)
        )
        scripts = [p for p in result.written if p != dest]
        assert [p.read_bytes() for p in scripts] == [first.read_bytes(), second.read_bytes()]
        assert len(set(scripts)) == 2
        results.append(set(scripts))
    assert results[0].isdisjoint(results[1])


@pytest.mark.parametrize(
    "reference",
    [
        '"$CLAUDE_PROJECT_DIR/scripts/check file.sh"',
        '"$CLAUDE_PROJECT_DIR"/scripts/check\\ file.sh',
        "$CLAUDE_PROJECT_DIR/scripts/check\\ file.sh",
    ],
)
def test_copied_quoted_scripts_replay_through_existing_renderer(
    tmp_path: Path, reference: str
) -> None:
    source = write(tmp_path / "scripts/check file.sh", "#!/bin/sh\nexit 0\n")
    suffix = ' && echo "$HOME" > result.txt'
    dest = tmp_path / ".apm/hooks/native.json"
    result = HooksConverter().convert(
        _finding("claude", _hooks(f"sh {reference}{suffix}")),
        dest,
        ctx=_context(tmp_path, copy_scripts=True),
    )
    copied = [p for p in result.written if p != dest]
    rewritten, deployments = HookIntegrator()._rewrite_hooks_data(
        json.loads(dest.read_text()), tmp_path, "fixture", "claude", hook_file_dir=dest.parent
    )
    assert [p for p, _ in deployments] == copied
    assert copied[0].read_bytes() == source.read_bytes()
    assert parse_hook_source(rewritten).commands[0].command.endswith(suffix)


@pytest.mark.parametrize(
    ("source_command", "expected"),
    [
        (
            'python "$CLAUDE_PROJECT_DIR"/scripts/check.py && echo "$HOME"',
            'python "./scripts/check.py" && echo "$HOME"',
        ),
        ('python "${workspaceFolder}/script space.py" 2> log', 'python "./script space.py" 2> log'),
        (
            r"python $CLAUDE_PROJECT_DIR/script\ space.py; echo ok",
            'python "./script space.py"; echo ok',
        ),
    ],
)
def test_only_project_path_spans_change(tmp_path: Path, source_command: str, expected: str) -> None:
    dest = tmp_path / ".apm/hooks/native.json"
    HooksConverter().convert(
        _finding("claude", _hooks(source_command)), dest, ctx=_context(tmp_path)
    )
    assert parse_hook_source(json.loads(dest.read_text())).commands[0].command == expected


def test_copilot_aliases_keep_both_native_handlers(tmp_path: Path) -> None:
    path = write(
        tmp_path / "hooks.json",
        json.dumps(
            {"hooks": {"Stop": [{"command": "echo one"}], "agentStop": [{"command": "echo two"}]}}
        ),
    )
    dest = tmp_path / ".apm/hooks/copilot-native.json"
    finding = replace(
        _finding("copilot", path=path), kind=HarnessKind.HOOK, format_id="github_hooks"
    )
    result = HooksConverter().convert(finding, dest, ctx=_context(tmp_path))
    commands = parse_hook_source(json.loads(dest.read_text())).commands
    assert result.written == [dest]
    assert [item.event for item in commands] == ["Stop", "Stop"]
    assert [item.command for item in commands] == ["echo one", "echo two"]


def test_kiro_native_trigger_timeout_and_matcher_survive(tmp_path: Path) -> None:
    path = write(
        tmp_path / "hooks.kiro.hook",
        json.dumps(
            {
                "version": "v1",
                "hooks": [
                    {
                        "trigger": "PreTaskExec",
                        "matcher": "build",
                        "action": {"type": "command", "command": "echo task", "timeout": 8},
                    }
                ],
            }
        ),
    )
    dest = tmp_path / ".apm/hooks/kiro-native.json"
    finding = replace(_finding("kiro", path=path), kind=HarnessKind.HOOK, format_id="kiro_hooks")
    HooksConverter().convert(finding, dest, ctx=_context(tmp_path))
    entry = json.loads(dest.read_text())["hooks"]["PreTaskExecution"][0]
    assert entry["matcher"] == "build"
    assert entry["hooks"][0]["timeout"] == 8


@pytest.mark.parametrize(
    "frontmatter", ["tools: [read]", "permission:\n  edit: deny", "color: unsupported"]
)
def test_incompatible_opencode_agents_are_not_silently_repaired(
    tmp_path: Path, frontmatter: str
) -> None:
    source = write(
        tmp_path / "reviewer.md", f"---\ndescription: Review\n{frontmatter}\n---\nReview.\n"
    )
    before = source.read_bytes()
    dest = tmp_path / ".apm/agents/reviewer.agent.md"
    result = AgentsConverter().convert(
        _finding("opencode", path=source), dest, ctx=_context(tmp_path)
    )
    assert result.skipped_reason
    assert not dest.exists()
    assert source.read_bytes() == before


def test_opencode_tool_restrictions_are_reference_only(tmp_path: Path) -> None:
    source = write(
        tmp_path / "reviewer.md",
        "---\ndescription: Review\ntools:\n  read: true\n  write: false\n---\nReview.\n",
    )
    before = source.read_bytes()
    assert validate_opencode_frontmatter(loads_frontmatter(before.decode()).metadata, source) == []
    dest = tmp_path / ".apm/agents/reviewer.agent.md"
    result = AgentsConverter().convert(
        _finding("opencode", path=source), dest, ctx=_context(tmp_path)
    )
    assert result.skipped_reason
    assert result.written == []
    assert not dest.exists()
    assert source.read_bytes() == before


@pytest.mark.parametrize("tool", ["opencode", "claude"])
def test_ordinary_agents_remain_convertible(tmp_path: Path, tool: str) -> None:
    source = write(tmp_path / "reviewer.md", "---\ndescription: Review\n---\nReview.\n")
    dest = tmp_path / ".apm/agents/reviewer.agent.md"
    result = AgentsConverter().convert(_finding(tool, path=source), dest, ctx=_context(tmp_path))
    assert result.skipped_reason is None
    assert result.written == [dest]
    assert loads_frontmatter(dest.read_text()).metadata["description"] == "Review"
