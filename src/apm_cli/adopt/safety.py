"""Importer-local admission policy over the canonical containment authority."""

from __future__ import annotations

from pathlib import Path

from apm_cli.utils.path_security import PathTraversalError, ensure_path_within


def approved_path(path: Path, root: Path, *, mutable: bool = False) -> Path:
    """Admit *path* against the resolved, user-selected scope and return its target.

    Call before enumeration, stat, reads, hashing or mutations, including again
    at conversion/commit time. ``root`` must be the approved project/user anchor,
    never a potentially redirected output directory. A selected-root alias is
    canonicalized by the caller once. Contained ancestor aliases are allowed.

    ``mutable=True`` additionally refuses a symlink leaf (including dangling
    links), for metadata/replacement endpoints and symlink-intolerant sources.
    Missing paths are allowed: admission does not assert existence, type, size,
    content safety or tree membership. Tree callers must admit each descendant
    before inspection and enforce their own budgets. No fingerprints are taken.

    This is resolve-before-use protection on a stable filesystem, not protection
    against concurrent hostile filesystem mutation. Errors deliberately exclude
    resolved paths, which may reveal locations outside the selected scope.
    """
    try:
        resolved = ensure_path_within(path, root)
        symlink_leaf = mutable and path.is_symlink()
    except PathTraversalError:
        raise PathTraversalError("path or symlink escapes approved scope") from None
    except (OSError, RuntimeError, ValueError):
        raise PathTraversalError("cannot verify path within approved scope") from None
    if symlink_leaf:
        raise PathTraversalError("symlink leaf is not allowed for this import path")
    return resolved
