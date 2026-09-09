"""Operation-count and read-count guards for preparation-phase provenance reuse."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from apm_cli.adopt.converters import ConvertContext, ConvertError, ConvertResult
from apm_cli.adopt.converters.base import read_markdown
from apm_cli.adopt.converters.passthrough import CONVERTERS
from apm_cli.adopt.materialize import WriteItem, _staged_entries
from apm_cli.adopt.model import Finding, HarnessKind, Importability, Ownership, Scope
from apm_cli.adopt.provenance import ImportRecord, ImportSources, hash_source, source_identity
from apm_cli.adopt.redact import Redactor
from apm_cli.utils.content_hash import compute_file_hash

from .conftest import FAKE_TOKEN, write

pytestmark = pytest.mark.component


class _CountedEntries(dict[str, ImportRecord]):
    """Count record visits independently of filesystem or machine speed."""

    visits = 0

    def items(self) -> Iterator[tuple[str, ImportRecord]]:
        for item in super().items():
            self.visits += 1
            yield item


class _CountedFindings(tuple[Finding, ...]):
    """Count ambiguity-input visits, including empty-provenance preparation."""

    visits = 0

    def __iter__(self) -> Iterator[Finding]:
        for finding in super().__iter__():
            self.visits += 1
            yield finding


def _finding(index: int = 0) -> Finding:
    return Finding(
        id="same-display-digest",
        tool="copilot",
        scope=Scope.PROJECT,
        kind=HarnessKind.INSTRUCTION,
        display_path=f".github/instructions/rule-{index}.instructions.md",
        importability=Importability.APM_NATIVE,
        ownership=Ownership.HOST_OWNED,
        converter_id="passthrough.instruction",
    )


def test_staged_entries_have_linear_membership_work(tmp_path: Path) -> None:
    """Count exact-path comparisons/probes, not wall time; the old scan grows 98x."""
    counts = []
    for size in (50, 500):
        operations = 0

        class CountedPath(str):
            def __eq__(self, other: object) -> bool:
                nonlocal operations
                operations += 1
                return super().__eq__(other)

            def __hash__(self) -> int:
                nonlocal operations
                operations += 1
                return super().__hash__()

        staging = tmp_path / ".apm"
        items = []
        for i in range(size):
            rel = CountedPath(f"instructions/{i}.instructions.md")
            items.append(
                WriteItem(
                    _finding(i),
                    "passthrough.instruction",
                    rel,
                    "write",
                    None,
                    result=ConvertResult(written=[staging / str(rel)]),
                )
            )
        result = _staged_entries(items, staging)
        counts.append(operations)
        assert result == [f"instructions/{i}.instructions.md" for i in range(size)]
    assert counts[0] > 0, "the probe must observe actual membership work"
    assert counts[1] / counts[0] < 15, counts


def _record(finding: Finding, *, identity: str = "", primary: str = "") -> ImportRecord:
    return ImportRecord(
        source=finding.display_path,
        scope=finding.scope.value,
        converter=finding.converter_id or "",
        source_sha256="source",
        output_sha256="import-v2:output",
        identity=identity,
        primary=primary,
    )


@pytest.mark.parametrize("shape", ["empty", "v2", "legacy", "auxiliary", "ambiguous"])
def test_plan_index_has_linear_record_and_finding_visits(tmp_path: Path, shape: str) -> None:
    """Ten times the inputs must take ten times the visits, not one hundred."""
    counts = []
    for size in (50, 500):
        findings = tuple(_finding(i) for i in range(size))
        counted = _CountedFindings(findings)
        entries = _CountedEntries()
        for i, finding in enumerate(findings):
            primary = f"instructions/{i}.instructions.md"
            if shape == "empty":
                continue
            entries[primary] = _record(
                finding,
                identity=source_identity(finding) if shape in ("v2", "auxiliary") else "",
                primary=primary,
            )
            if shape == "auxiliary":
                entries[f"assets/{i}"] = replace(entries[primary], primary=primary)
            if shape == "ambiguous":
                entries[f"duplicate/{i}"] = replace(entries[primary])
        sources = ImportSources(tmp_path / ".apm/.import-sources.json", entries, tmp_path)
        plan = sources.for_plan(counted)
        built_visits = (entries.visits, counted.visits)
        for i, finding in enumerate(findings):
            primary = f"instructions/{i}.instructions.md"
            assert plan.destination(finding, converter=finding.converter_id or "") == (
                None if shape in ("empty", "ambiguous") else primary
            )
            expected = [primary, f"assets/{i}"] if shape == "auxiliary" else [primary]
            if shape == "ambiguous":
                expected.append(f"duplicate/{i}")
            assert plan.outputs(primary) == ([] if shape == "empty" else expected)
        assert (entries.visits, counted.visits) == built_visits
        assert built_visits == (len(entries), size)
        counts.append(sum(built_visits))
    assert counts[1] == 10 * counts[0]
    assert counts[1] / counts[0] < 15


def test_plan_index_preserves_ambiguity_aliases_and_removed_reservations(tmp_path: Path) -> None:
    """Exact identities win; legacy converter aliases never erase ambiguity."""
    finding = _finding()
    alias = "canonical-converter"
    legacy = _record(finding)
    entries = {
        "legacy": legacy,
        "removed": _record(_finding(1), identity=source_identity(_finding(1))),
    }
    sources = ImportSources(tmp_path / ".apm/.import-sources.json", entries, tmp_path)
    assert sources.for_plan((finding,)).destination(finding) == "legacy"
    assert sources.for_plan((finding,)).destination(finding, converter=alias) == "legacy"
    other = replace(finding, tool="cursor")
    assert sources.for_plan((finding, other)).destination(finding) is None
    entries["legacy-alias"] = replace(legacy, converter=alias)
    assert sources.for_plan((finding,)).destination(finding, converter=alias) is None
    entries["exact"] = replace(legacy, identity=source_identity(finding))
    plan = sources.for_plan((finding, other))
    assert plan.destination(finding, converter=alias) == "exact"
    assert plan.outputs("removed") == ["removed"]
    assert set(sources.entries) == {"legacy", "legacy-alias", "removed", "exact"}
    entries["duplicate-exact"] = replace(entries["exact"])
    assert sources.for_plan((finding,)).destination(finding, converter=alias) is None
    del entries["legacy-alias"]
    # Preserve the existing conservative fallback for ambiguous exact ownership.
    assert sources.for_plan((finding,)).destination(finding) == "legacy"
    # A new planning phase rebuilds indices; no process-wide stale owner cache.
    del entries["legacy"]
    assert sources.for_plan((finding,)).destination(finding) is None


@pytest.mark.parametrize("version", ["import-v2", "sha256"])
def test_output_witness_reuses_full_hash_without_skipping_fresh_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    """One v2 read (two for legacy compatibility) supplies decision and expected."""
    finding = _finding()
    apm_dir = tmp_path / ".apm"
    target = write(apm_dir / "rule.md", "x" * 1_048_576)
    full_hash = hash_source(target, root=tmp_path)
    record = replace(
        _record(finding, identity=source_identity(finding)),
        output_sha256=full_hash if version == "import-v2" else compute_file_hash(target),
    )
    sources = ImportSources(apm_dir / ".import-sources.json", {"rule.md": record}, tmp_path)
    original = Path.open
    reads: list[Path] = []

    def counted_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        mode = args[0] if args else kwargs.get("mode", "r")
        if path == target and "r" in mode:
            reads.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counted_open)
    witness = sources.inspect("rule.md", target, "source", identity=source_identity(finding))
    assert witness.decision == "unchanged"
    assert witness.current_hash == full_hash
    assert len(reads) == (1 if version == "import-v2" else 2)
    target.write_text("local edit", encoding="utf-8")
    fresh = sources.inspect("rule.md", target, "source", identity=source_identity(finding))
    assert fresh.decision == "locally-modified"
    assert fresh.current_hash != witness.current_hash
    assert len(reads) == (2 if version == "import-v2" else 4)


def test_legacy_decision_retains_byte_exact_expected_witness(tmp_path: Path) -> None:
    """Legacy normalized equality cannot turn the new prompt witness into a package hash."""
    finding = _finding()
    target = write(tmp_path / ".apm/rule.md", "line\n")
    record = replace(_record(finding), output_sha256=compute_file_hash(target))
    sources = ImportSources(target.parent / ".import-sources.json", {"rule.md": record}, tmp_path)
    before = sources.inspect("rule.md", target, "changed-source")
    target.write_bytes(b"line\r\n")
    after = sources.inspect("rule.md", target, "changed-source")
    assert before.decision == after.decision == "refresh"
    assert before.current_hash != after.current_hash
    assert after.current_hash == hash_source(target, root=tmp_path)


@pytest.mark.parametrize("size", [50, 500])
@pytest.mark.parametrize("lenient", [False, True])
def test_markdown_passthrough_reads_each_source_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, size: int, lenient: bool
) -> None:
    """Parse already-admitted text using the same strict/lenient markdown grammar."""
    text = (
        "---\ndescription: example: value\n---\nbody\n"
        if lenient
        else '---\napplyTo: "**/*.py"\n---\nbody'
    )
    source = write(tmp_path / "source.instructions.md", text)
    finding = replace(_finding(), abs_path=source)
    expected_metadata, expected_body = read_markdown(source, 1_048_576)
    original = Path.read_text
    reads = 0

    def counted_read(path: Path, *args: Any, **kwargs: Any) -> str:
        nonlocal reads
        if path == source:
            reads += 1
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counted_read)
    ctx = ConvertContext(tmp_path, Scope.PROJECT, Redactor(project_root=tmp_path))
    for i in range(size):
        converter = CONVERTERS[i % 3]
        dest = tmp_path / ".apm" / f"output-{i}.md"
        result = converter.convert(finding, dest, ctx=ctx)
        metadata, body = read_markdown(dest, 1_048_576)
        assert metadata == expected_metadata
        assert body.strip() == expected_body.strip()
        assert result.written == [dest]
        if lenient:
            assert [(change.path, change.action) for change in result.changes] == [
                ("frontmatter", "transformed")
            ]
        else:
            assert dest.read_text(encoding="utf-8") == text + "\n"
    assert reads == size


def test_passthrough_single_read_still_refuses_credentials(tmp_path: Path) -> None:
    """Read reuse must not bypass screening the original frontmatter/body bytes."""
    source = write(tmp_path / "source.md", f"---\ndescription: {FAKE_TOKEN}\n---\nbody\n")
    dest = tmp_path / ".apm/output.md"
    ctx = ConvertContext(tmp_path, Scope.PROJECT, Redactor(project_root=tmp_path))
    with pytest.raises(ConvertError, match="possible"):
        CONVERTERS[0].convert(replace(_finding(), abs_path=source), dest, ctx=ctx)
    assert not dest.exists()
