"""Forward migration for per-target MCP deployment ownership."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from apm_cli.utils.path_security import ensure_path_within

logger = logging.getLogger(__name__)


def resolve_mcp_target_servers(
    *,
    recorded_target_servers: dict[str, set[str]],
    ownership_present: bool,
    server_names: set[str],
    stored_configs: dict[str, dict],
    project_root: Path | None,
    user_scope: bool,
    approved_root: Path | None = None,
    admit_file: Callable[[Path], int | None] | None = None,
    max_servers: int | None = None,
    non_interactive: bool = False,
) -> dict[str, set[str]]:
    """Return recorded ownership, adopting exact legacy baselines only when absent."""
    target_servers = {runtime: set(servers) for runtime, servers in recorded_target_servers.items()}
    if target_servers or ownership_present:
        return target_servers
    return adopt_legacy_mcp_target_servers(
        server_names=server_names,
        stored_configs=stored_configs,
        project_root=project_root,
        user_scope=user_scope,
        approved_root=approved_root,
        admit_file=admit_file,
        max_servers=max_servers,
        non_interactive=non_interactive,
    )


def migrate_legacy_project_target_servers(
    target_servers: dict[str, set[str]],
    *,
    active_runtimes: set[str],
    user_scope: bool,
) -> None:
    """Move legacy project VS Code ownership to the Copilot runtime key."""
    if user_scope or "copilot" not in active_runtimes or "vscode" in active_runtimes:
        return
    legacy_servers = target_servers.pop("vscode", set())
    if legacy_servers:
        target_servers.setdefault("copilot", set()).update(legacy_servers)


def adopt_legacy_mcp_target_servers(
    *,
    server_names: set[str],
    stored_configs: dict[str, dict],
    project_root: Path | None,
    user_scope: bool,
    approved_root: Path | None = None,
    admit_file: Callable[[Path], int | None] | None = None,
    max_servers: int | None = None,
    non_interactive: bool = False,
) -> dict[str, set[str]]:
    """Adopt exact native baselines; scoped callers authorize every read first.

    ``approved_root`` is the importer's selected scope, not a config-derived
    parent. Omitting it preserves the installer's existing read policy.
    """
    from apm_cli.core.conflict_detector import MCPConflictDetector
    from apm_cli.factory import ClientFactory
    from apm_cli.integration.mcp_integrator import MCPIntegrator
    from apm_cli.models.dependency.mcp import MCPDependency

    baselines: dict[str, Any] = {}
    for name in sorted(server_names):
        raw = stored_configs.get(name)
        if not isinstance(raw, dict):
            continue
        try:
            dependency = MCPDependency.from_dict(raw)
        except (TypeError, ValueError):
            continue
        if not dependency.is_self_defined:
            continue
        baselines[name] = dependency

    if not baselines:
        return {}

    adopted: dict[str, set[str]] = {}
    for runtime in ClientFactory.supported_clients():
        try:
            client = ClientFactory.create_client(
                runtime,
                project_root=project_root,
                user_scope=user_scope,
            )
            if approved_root is not None:
                ensure_path_within(Path(client.get_config_path()), approved_root)
                existing_configs = [
                    client.get_native_server_configs(
                        approved_root=approved_root,
                        admit_file=admit_file,
                        max_servers=max_servers,
                    )
                ]
            else:
                existing_configs = [MCPConflictDetector(client).get_existing_server_configs()]
            legacy_reader = getattr(client, "get_legacy_current_config", None)
            if callable(legacy_reader):
                try:
                    if approved_root is not None:
                        # An undeclared legacy path is not authorization to read.
                        legacy_path = client.get_legacy_config_path()
                        if legacy_path is None:
                            raise ValueError("No declared legacy config path")
                        ensure_path_within(Path(legacy_path), approved_root)
                        legacy_servers = client.get_native_server_configs(
                            approved_root=approved_root,
                            admit_file=admit_file,
                            max_servers=max_servers,
                            legacy=True,
                        )
                    else:
                        legacy_config = legacy_reader()
                        legacy_servers = legacy_config.get(client.mcp_servers_key)
                    if isinstance(legacy_servers, dict):
                        existing_configs.append(legacy_servers)
                except Exception:
                    # Do not discard an authorized current baseline when only
                    # the obsolete path is unavailable or outside the scope.
                    logger.debug("Could not inspect obsolete MCP target %s", runtime)
        except Exception:
            logger.debug("Could not inspect legacy MCP target %s", runtime)
            continue

        for name, dependency in baselines.items():
            if not any(name in existing for existing in existing_configs):
                continue
            try:
                render_options = {"non_interactive": True} if non_interactive else {}
                expected = client.render_server_config(
                    MCPIntegrator._build_self_defined_info(dependency),
                    **render_options,
                )
            except Exception:
                logger.debug(
                    "Could not render legacy MCP baseline %s for %s",
                    name,
                    runtime,
                    exc_info=True,
                )
                continue
            if any(existing.get(name) == expected for existing in existing_configs):
                adopted.setdefault(runtime, set()).add(name)
    return adopted
