---
title: "Brownfield Adoption"
description: "Import supported agent configuration into a managed APM package, review conversion limits, and reconcile deployed files."
sidebar:
  order: 7
---

Use `apm init --discover` to inventory existing agent configuration, then
`--apply` to import supported content into `.apm/` and `apm.yml`. The result is
an [implicit local package](../package-anatomy/) deployed by `apm install`,
not a synchronized mirror of native configuration.

## Discovery and ownership

Discovery uses the target registry for file locations, native readers for hooks
and MCP, and additional root-context and plugin scanners. Knowing a deployment
path does **not** establish a preserving inverse conversion. Preview classifies
findings; apply preparation determines whether their contents can be imported.

Only **host-owned** findings are eligible. Lockfile claims, deployed hashes,
generation markers, hook ownership sidecars, and client/scope-specific MCP
ownership distinguish them from **apm-owned**, **apm-generated**, or **ambiguous**
content. Ambiguous files are not imported, including mixed managed root files.

The inventory labels candidates **apm-native** or **convertible**.
**Reference-only** entries are listed without replacement; **ignored** entries
include unknown files, private overrides, and already-managed content.
Unsafe inputs are refused, not downgraded to reference-only.

Reads and writes must remain within the selected project or user scope.
Unverifiable paths and exceeded admission budgets produce errors. Discovery's
finding cap is not a bound on all filesystem traversal.

## Supported conversions

| Source | Imported form | Limits |
|---|---|---|
| Copilot instructions, prompts, agents | Corresponding `.apm/` primitives | Existing APM-shaped content; validation and credential screening still apply |
| Cursor, Claude, Kiro, Windsurf, Antigravity rules | `.apm/instructions/*.instructions.md` | Native globs/paths become `applyTo`; unsupported trigger distinctions produce warnings |
| Hand-authored root context (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`) | Instructions, scoped for nested context | Generated or ambiguous files excluded; Claude `@path` imports become links or are dropped with reasons |
| Markdown agents; Codex TOML agents | `.apm/agents/*.agent.md` | Portable keys retained, vendor keys reported as dropped; OpenCode agents with native `tools` or `permission` policies, or incompatible frontmatter, are reference-only |
| Markdown commands, Windsurf workflows, Gemini TOML commands | `.apm/prompts/*.prompt.md` | Portable keys retained; vendor fields and argument transformations reported |
| Skill directories | `.apm/skills/<name>/` | Name normalized; symlinks refused; non-content files filtered |
| Merged Claude, Codex, Cursor, Gemini, Windsurf, Antigravity hooks; Copilot/Kiro per-file hooks | `.apm/hooks/<allocated-hook-stem>.json` | Command hooks only; canonical events and timeout units; unknown formats, non-command hooks, and unsupported shell forms are reference-only |
| MCP client entries | Self-defined `dependencies.mcp` entries | OpenCode native `mcp` entries and command arrays supported; unsupported environment references, including Codex `bearer_token_env_var`, `env_http_headers`, and `env_vars`, are reference-only |
| Styles, plugin layouts, canvases | None | Reference-only |

Converters report `preserved`, `transformed`, `defaulted`, `dropped`, and
`redacted` fields with reasons. A hook event passed through unmapped is not a
promise that another harness executes it. Review each target's output.

### Activation differs by harness

Unconditional source rules generally import as `applyTo: "**"`, but target
renderers express that as file matching: Cursor `globs`, Claude `paths`,
Kiro `fileMatchPattern`, or Windsurf `trigger: glob`. Cursor does not regain
`alwaysApply: true` through this conversion.

Without `applyTo`, Cursor uses description-triggered rules, while Claude,
Kiro, and Windsurf render unconditional rules. Manual/model-triggered source
rules can lose those distinctions. Import-and-render does not guarantee
identical activation or behavior across harnesses.

### Hook scripts

Import does not execute hooks or MCP servers. Supported hook commands retain
references to source scripts by default. `--include-hook-scripts` copies admitted
UTF-8 scripts under `.apm/hooks/<allocated-hook-stem>/scripts/`, preserving
ordinary permission bits. APM screens the checked bytes before copying and
rewrites only recognized path spans, preserving surrounding shell syntax.
Command substitutions, here-documents, and unsupported dynamic or machine-local
script paths make the hook reference-only.

### Credential screening

Detected literal credentials in MCP URLs or arguments are **refused**, not
replaced with placeholders. Supported stdio `env` and HTTP `headers` values
can become `${SERVER_KEY}` references; Codex HTTP credential placeholders are
not supported. Export the reported variables before installation.

Screening includes literal portions beside placeholders and outgoing retained
MCP extras. Content converters also refuse recognized credential patterns.
This is bounded screening, not exhaustive secret detection; review imported
files and reports before sharing.

The separate [security model](../../enterprise/security/) has two layers:
**built-in protection** automatically blocks critical findings during `install`,
`compile`, and `unpack`, with zero configuration; **`apm audit`** provides explicit
reporting (SARIF/JSON/markdown), remediation (`--strip`), and standalone scanning
(`--file`).

## Refresh and local edits

`.apm/.import-sources.json` version 2 reserves destinations by full source
identity: tool, scope, primitive kind, and normalized source path. Primary and
auxiliary outputs retain ownership even when sources disappear or colliding
sources are added or reordered. Removing a source does not delete its import.

Refresh requires verified, unchanged destination content. Complete, bounded
fingerprints cover paths, entry types, bytes, additions, removals, hidden files,
empty directories, and POSIX executable bits. Windows normalizes executable
bits to zero; timestamps and other permission bits are excluded. Admission
limits are 1 MiB per file, 10 MiB per tree, 2,000 entries, and depth 64.
These fingerprints are separate from package/lockfile hashes.

Local edits or missing outputs block replacement. Legacy ownership is reused
only when unambiguous; empty or unverifiable output hashes cannot authorize
refresh. Conflicts remain untouched and make apply partial/nonzero. File-source,
destination, and metadata checks run again before commit. Unchanged imports
avoid rewriting output; existing MCP declarations remain authoritative.

## Cut-over

1. Save a version-control checkpoint or backup. Preview with `apm init --discover`.
2. Run `apm init --discover --apply`. Review the staged plan, conversion losses,
   per-server setup requirements, and exclusions before consenting. See the
   [consent and result contract](../../reference/cli/init/#consent-and-results).
3. Inspect `.apm/` and `apm.yml`, supply required environment variables, then
   render a selected target, for example `apm install --target cursor`.
4. Compare deployed files and verify activation. **Apply preserves original
   bytes; installation is a separate operation.** Installing back to the source
   harness can rewrite a same-path rule or skip a colliding hand-authored agent.
   Compilation retains unmarked project-root `CLAUDE.md`, `AGENTS.md`, and
   `GEMINI.md` with a warning.
5. Reconcile only verified duplicates. Keep unsupported content and any original
   still serving the harness; do not blanket-delete native directories or use
   `--force` as a cutover shortcut. Retained originals may overlap with deployed
   context. For a hand-authored `AGENTS.md`, see
   [managed-section compilation](../../reference/cli/compile/).

After verified cutover, edit adopted content in `.apm/` and `apm.yml` and
redeploy. Re-import is explicit, not ongoing synchronization. For user-scope
onboarding, `--global` imports into `~/.apm/`; deploy with `apm install --global`.
