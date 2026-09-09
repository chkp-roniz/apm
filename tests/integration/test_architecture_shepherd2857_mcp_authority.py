"""W3 adoption must consume canonical, scope-authorized MCP ownership."""

from pathlib import Path

import pytest

from scripts.architecture_linter.inventory import build_inventory
from scripts.architecture_linter.registry import load_registry
from scripts.architecture_linter.runner import run_selected_rules

pytestmark = pytest.mark.component
ROOT = Path(__file__).resolve().parents[2]
RULE = "install-deployment-mcp-ownership-migration"
CONSUMER = "src/apm_cli/adopt/ownership.py"
OWNER = "src/apm_cli/install/mcp/ownership.py"


def test_adopt_mcp_ownership_has_registered_consumer_and_guard() -> None:
    registry = load_registry(ROOT / ".apm/architecture/owners", build_inventory(ROOT).files)
    owner = next(v for v in registry.owners if v.id == "legacy-mcp-ownership-key-migration")
    assert CONSUMER in owner.selectors
    assert RULE in owner.guards
    report = run_selected_rules(ROOT, (RULE,))
    assert report.failures == ()
    assert report.violations == ()


@pytest.mark.parametrize(
    "old,new",
    [
        ("mcp_ownership.resolve_mcp_target_servers(", "_incorrect_local_ownership("),
        ("approved_root=root,", "approved_root=None,"),
    ],
)
def test_static_guard_rejects_consumer_bypass(old: str, new: str) -> None:
    source = (ROOT / CONSUMER).read_text()
    mutated = source.replace(old, new)
    assert mutated != source
    report = run_selected_rules(ROOT, (RULE,), source_overrides={CONSUMER: mutated})
    assert report.failures == ()
    assert any(v.rule_id == RULE and v.path == CONSUMER for v in report.violations)


def test_static_guard_rejects_native_read_authorization_removed() -> None:
    source = (ROOT / OWNER).read_text()
    mutated = source.replace("ensure_path_within(", "_removed_guard(")
    assert mutated != source
    report = run_selected_rules(ROOT, (RULE,), source_overrides={OWNER: mutated})
    assert report.failures == ()
    assert any(v.rule_id == RULE and v.path == OWNER for v in report.violations)


@pytest.mark.parametrize(
    "path,old,new",
    [
        (
            "src/apm_cli/adapters/client/base.py",
            "ensure_path_within(config_path, approved_root)",
            "_removed_guard(config_path, approved_root)",
        ),
        (
            "src/apm_cli/adapters/client/base.py",
            "document = self._read_config(config_path)",
            "document = self.get_current_config()",
        ),
        (
            "src/apm_cli/adapters/client/vscode.py",
            'return str(self.project_root / ".vscode" / "mcp.json")',
            'self.project_root.mkdir()\n        return str(self.project_root / ".vscode" / "mcp.json")',
        ),
        (
            "src/apm_cli/adapters/client/vscode.py",
            'return str(self.project_root / ".vscode" / "mcp.json")',
            'self.project_root.exists()\n        return str(self.project_root / ".vscode" / "mcp.json")',
        ),
        (
            "src/apm_cli/adapters/client/copilot.py",
            "self._configure_registry(SimpleRegistryClient, RegistryIntegration, registry_url)",
            "self.registry_client = SimpleRegistryClient(registry_url)",
        ),
    ],
)
def test_static_guard_rejects_mutating_native_read_path(path: str, old: str, new: str) -> None:
    source = (ROOT / path).read_text()
    mutated = source.replace(old, new)
    assert mutated != source
    report = run_selected_rules(ROOT, (RULE,), source_overrides={path: mutated})
    assert report.failures == ()
    assert any(v.rule_id == RULE and v.path == path for v in report.violations)
