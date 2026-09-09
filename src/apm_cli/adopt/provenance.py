"""Source identity and complete, bounded local-edit witnesses for explicit import."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from apm_cli.utils.atomic_io import atomic_write_text
from apm_cli.utils.content_hash import compute_file_hash

from .model import Finding
from .safety import approved_path

SIDECAR_NAME = ".import-sources.json"
_FILE_LIMIT = 1_048_576
_TREE_LIMIT = 10 * _FILE_LIMIT
_ENTRY_LIMIT = 2000
_FINGERPRINT = "import-v2:"
Decision = Literal[
    "write", "unchanged", "refresh", "collision", "locally-modified", "source-missing"
]


def source_identity(finding: Finding) -> str:
    """Retain the full finding identity, not its abbreviated display digest."""
    return json.dumps(
        [finding.tool, finding.scope.value, finding.kind.value, finding.display_path],
        ensure_ascii=True,
        separators=(",", ":"),
    )


def admitted_entries(path: Path, root: Path, *, file_limit: int = _FILE_LIMIT) -> list[Path]:
    """Admit the entire tree and its budgets before reading any content."""
    approved_path(path, root, mutable=True)
    pending = [path]
    entries: list[Path] = []
    total = 0
    while pending:
        current = pending.pop()
        approved_path(current, root, mutable=True)
        info = current.stat()
        entries.append(current)
        if len(entries) > _ENTRY_LIMIT:
            raise ValueError("import tree exceeds the entry limit")
        if stat.S_ISDIR(info.st_mode):
            if len(current.relative_to(path).parts) > 64:
                raise ValueError("import tree exceeds the depth limit")
            with os.scandir(current) as children:
                for child in children:
                    if len(entries) + len(pending) >= _ENTRY_LIMIT:
                        raise ValueError("import tree exceeds the entry limit")
                    pending.append(Path(child.path))
        elif stat.S_ISREG(info.st_mode):
            total += info.st_size
            if info.st_size > file_limit or total > _TREE_LIMIT:
                raise ValueError("import content exceeds the size limit")
        else:
            raise ValueError("import contains a non-regular entry")
    return sorted(entries, key=lambda entry: entry.relative_to(path).as_posix())


def hash_source(
    path: Path | None, *, root: Path | None = None, file_limit: int = _FILE_LIMIT
) -> str | None:
    """Fingerprint bytes, paths, types and executable bits, including hidden/empty entries.

    Timestamps and non-executable permission bits are excluded. Windows has no
    portable executable-bit contract, so that field is normalized to zero there.
    This witness is deliberately not the normalized package/lockfile hash.
    """
    if path is None:
        return None
    anchor = root if root is not None else path.parent
    approved_path(path, anchor, mutable=True)
    if not path.exists():
        return None
    entries = admitted_entries(path, anchor, file_limit=file_limit)
    digest = hashlib.sha256()
    for entry in entries:
        info = entry.stat()
        directory = stat.S_ISDIR(info.st_mode)
        frame = json.dumps(
            [
                entry.relative_to(path).as_posix(),
                "directory" if directory else "file",
                (info.st_mode & 0o111) if os.name != "nt" else 0,
                0 if directory else info.st_size,
            ],
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
        if not directory:
            with entry.open("rb") as stream:
                while chunk := stream.read(65536):
                    digest.update(chunk)
    return _FINGERPRINT + digest.hexdigest()


@dataclass
class ImportRecord:
    source: str
    scope: str
    converter: str
    source_sha256: str
    output_sha256: str
    identity: str = ""
    primary: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class ImportSourceIndex:
    """Attribution indices for one plan, rebuilt after provenance/finding changes.

    Construction visits each record and finding once. Destination queries use
    constant-time identity and legacy ambiguity lookups; output queries cost
    only the number of returned outputs. No filesystem evidence is cached here.
    """

    def __init__(self, entries: Mapping[str, ImportRecord], findings: Iterable[Finding]) -> None:
        self._exact: dict[str, list[str]] = {}
        self._legacy: dict[tuple[str, str, str | None], list[str]] = {}
        self._outputs: dict[str, list[str]] = {}
        for dest, record in entries.items():
            if record.identity:
                if not record.primary or record.primary == dest:
                    self._exact.setdefault(record.identity, []).append(dest)
            else:
                key = (record.source, record.scope, record.converter)
                self._legacy.setdefault(key, []).append(dest)
            self._outputs.setdefault(dest, []).append(dest)
            if record.primary != dest:
                self._outputs.setdefault(record.primary, []).append(dest)
        self._candidates = Counter(
            (finding.display_path, finding.scope.value, finding.converter_id)
            for finding in findings
        )

    def destination(self, finding: Finding, *, converter: str = "") -> str | None:
        """Reuse exact ownership; accept legacy attribution only when unambiguous."""
        matches = self._exact.get(source_identity(finding), ())
        if len(matches) == 1:
            return matches[0]
        key = (finding.display_path, finding.scope.value, finding.converter_id)
        if self._candidates[key] != 1:
            return None
        # At most two distinct converter IDs; do not count an alias twice or
        # flatten an arbitrarily large ambiguous bucket for each finding.
        legacy = [
            self._legacy.get((finding.display_path, finding.scope.value, candidate), ())
            for candidate in {finding.converter_id, converter}
        ]
        if sum(len(bucket) for bucket in legacy) != 1:
            return None
        return next(bucket[0] for bucket in legacy if bucket)

    def outputs(self, primary: str) -> list[str]:
        """Return owned outputs, retaining auxiliary and removed-source reservations."""
        return list(self._outputs.get(primary, ()))


@dataclass(frozen=True)
class OutputWitness:
    """One preparation-phase decision and its byte-exact expected output hash.

    ``current_hash`` can be absent on protected/refused outputs. Reuse this
    value only within preparation, never instead of a post-prompt/commit read.
    """

    decision: Decision
    current_hash: str | None = None


@dataclass
class ImportSources:
    """The sole authority for destination reservations and refresh authorization."""

    path: Path
    entries: dict[str, ImportRecord] = field(default_factory=dict)
    root: Path | None = None

    @classmethod
    def load(cls, apm_dir: Path, *, root: Path | None = None) -> ImportSources:
        anchor = root if root is not None else apm_dir.parent
        path = apm_dir / SIDECAR_NAME
        approved_path(path, anchor, mutable=True)
        sources = cls(path=path, root=anchor)
        if not path.exists():
            return sources
        if not path.is_file() or path.stat().st_size > _FILE_LIMIT:
            raise ValueError("import provenance is not a bounded regular file")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") not in (1, 2):
            raise ValueError("unsupported import provenance; preserve and review the sidecar")
        raw_entries = data.get("entries")
        if not isinstance(raw_entries, dict):
            raise ValueError("invalid import provenance entries")
        for dest, record in raw_entries.items():
            if not isinstance(dest, str) or not isinstance(record, dict):
                raise ValueError("invalid import provenance record")
            approved_path(apm_dir / dest, apm_dir, mutable=True)
            required = ("source", "scope", "converter", "source_sha256", "output_sha256")
            if any(not isinstance(record.get(key), str) for key in required):
                raise ValueError("unverifiable import provenance record")
            if any(not isinstance(record.get(key, ""), str) for key in ("identity", "primary")):
                raise ValueError("invalid import source identity")
            sources.entries[dest] = ImportRecord(
                **{key: record[key] for key in required},
                identity=record.get("identity", "") if data["version"] == 2 else "",
                primary=record.get("primary", "") if data["version"] == 2 else "",
            )
        return sources

    def save(self) -> None:
        approved_path(self.path, self.root or self.path.parent.parent, mutable=True)
        payload: dict[str, Any] = {
            "version": 2,
            "entries": {dest: rec.to_dict() for dest, rec in sorted(self.entries.items())},
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.path, json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def destination(
        self, finding: Finding, findings: tuple[Finding, ...], *, converter: str = ""
    ) -> str | None:
        """Single-query compatibility API; planners should reuse ``for_plan``."""
        return self.for_plan(findings).destination(finding, converter=converter)

    def for_plan(self, findings: Iterable[Finding]) -> ImportSourceIndex:
        """Build once before the finding loop; discard when that plan ends."""
        return ImportSourceIndex(self.entries, findings)

    def outputs(self, primary: str) -> list[str]:
        """Single-query compatibility API for an import's complete output set."""
        return self.for_plan(()).outputs(primary)

    def decide(
        self,
        dest_rel: str,
        dest_abs: Path,
        source_hash: str | None,
        *,
        identity: str | None = None,
    ) -> Decision:
        """Return a fresh decision; callers needing its hash should use ``inspect``."""
        return self.inspect(dest_rel, dest_abs, source_hash, identity=identity).decision

    def inspect(
        self,
        dest_rel: str,
        dest_abs: Path,
        source_hash: str | None,
        *,
        identity: str | None = None,
    ) -> OutputWitness:
        """Never authorize replacement using another source's or missing evidence."""
        record = self.entries.get(dest_rel)
        anchor = self.root or self.path.parent.parent
        approved_path(dest_abs, anchor, mutable=True)
        exists = dest_abs.exists()
        if record is None:
            return OutputWitness("collision" if exists else "write")
        if identity is not None and record.identity and identity != record.identity:
            return OutputWitness("collision")
        if source_hash is None:
            return OutputWitness("source-missing")
        if not exists:
            return OutputWitness("locally-modified")
        if not record.output_sha256:
            return OutputWitness("locally-modified")
        try:
            current = hash_source(dest_abs, root=anchor)
            comparable = current
            if not record.output_sha256.startswith(_FINGERPRINT):
                if not dest_abs.is_file() or not record.output_sha256.startswith("sha256:"):
                    return OutputWitness("locally-modified", current)
                comparable = compute_file_hash(dest_abs)
        except (OSError, ValueError):
            return OutputWitness("locally-modified")
        if comparable != record.output_sha256:
            return OutputWitness("locally-modified", current)
        return OutputWitness(
            "unchanged" if source_hash == record.source_sha256 else "refresh", current
        )

    def record(
        self,
        dest_rel: str,
        *,
        source: str,
        scope: str,
        converter: str,
        source_hash: str,
        dest_abs: Path,
        identity: str = "",
        primary: str = "",
    ) -> None:
        self.entries[dest_rel] = ImportRecord(
            source=source,
            scope=scope,
            converter=converter,
            source_sha256=source_hash,
            output_sha256=hash_source(dest_abs, root=self.root) or "",
            identity=identity,
            primary=primary or dest_rel,
        )
