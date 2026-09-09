---
title: apm init
description: Create an APM manifest, or discover and import supported existing agent configuration.
sidebar:
  order: 1
---

## Synopsis

```bash
apm init [PROJECT_NAME] [OPTIONS]
```

## Description

Ordinary `apm init` creates a minimal `apm.yml` in the current directory or in a new
`PROJECT_NAME` subdirectory. Auto-detects name, author, and description
so you can start running `apm install` immediately.

`--discover` instead inventories existing configuration. It is read-only unless
paired with `--apply`, which imports supported content and creates or merges
the manifest rather than overwriting it.

The legacy `--plugin` and `--marketplace` flags (which scaffold a
plugin or marketplace authoring block alongside `apm.yml`) are
deprecated but still accepted; use [`apm plugin init`](../plugin/)
and [`apm marketplace init`](../marketplace/) instead.

## Arguments

| Argument | Description |
|---|---|
| `PROJECT_NAME` | Optional. Name of a new directory to create; enter it afterward with `cd`. Pass `.` to initialize in the current directory (same as omitting). Must be non-blank (not empty or whitespace-only), must not contain `/` or `\`, and must not be `..`. |

## Options

| Flag | Default | Description |
|---|---|---|
| `-y`, `--yes` | off | Ordinary init: use defaults and overwrite an existing `apm.yml` without confirmation. Discovery apply: skip only confirmation, not warnings or safety checks. |
| `--plugin` | off | **Deprecated.** Use [`apm plugin init`](../plugin/) instead. Scaffold a plugin authoring project: also writes `plugin.json` and adds a `devDependencies` block to `apm.yml`. Plugin name must be kebab-case, max 64 chars. |
| `--marketplace` | off | **Deprecated.** Use [`apm marketplace init`](../marketplace/) instead. Append a `marketplace:` authoring block to `apm.yml`. See [Publish to a marketplace](../../../producer/publish-to-a-marketplace/). |
| `--target` | (prompt) | Comma-separated target list. Ordinary init skips the target prompt; discovery apply uses the order for MCP conflicts and adds these targets alongside detected targets. Stable targets include `copilot`, `claude`, `grok-build`, `cursor`, `opencode`, `codex`, `gemini`, `antigravity`, `windsurf`, `kiro`, and `agent-skills`; `all` expands the default stable set. |
| `--discover` | off | Inventory existing agent-harness files (Claude Code, Copilot, Cursor, Codex, Gemini, Windsurf, Kiro, OpenCode, Grok Build) and propose an `apm.yml`. Read-only unless `--apply`. See [Discover existing agent context](#discover-existing-agent-context). |
| `--apply` | off | With `--discover`: import eligible hand-authored content into `.apm/` and create or merge `apm.yml`. Apply preserves originals; later installation has separate collision rules. `--write` is an alias. |
| `--format` | `text` | With `--discover`: `text`, `json`, or `yaml`. Machine formats keep stdout clean. |
| `-g`, `--global` | off | With `--discover`: scan the user scope (`~/.claude`, `~/.cursor`, `~/.codex`, ...) instead of the project, and write into `~/.apm/`. |
| `--include-hook-scripts` | off | With `--discover --apply`: copy supported scripts into `.apm/hooks/<allocated-hook-stem>/scripts/` and rewrite recognized references. By default scripts remain referenced; import never executes them. |
| `-v`, `--verbose` | off | Show detailed output. |

Ordinary-init target precedence: `--target` flag > interactive prompt > auto-detect at
compile time (used with `--yes` or in non-TTY shells).

`init` writes only manifest-safe stable targets. For example, `--target agents`,
`--target vscode`, and the MCP-only `--target intellij` persist the canonical
`copilot` identifier, while `--target all` expands to the default stable set.
Experimental selectors such as `grok-cloud` are accepted by the shared CLI
target parser but are not persisted in `apm.yml`; enable them, then select them
with `apm install --target grok-cloud`.

## Discover existing agent context

Run discovery in the project directory; omit `PROJECT_NAME` or pass `.`.
`--global` selects user scope instead. Registry paths identify candidates,
not guaranteed inverse conversions.

```bash
apm init --discover                   # read-only inventory
apm init --discover --apply           # prepare, review, confirm
apm install --target cursor           # render supported imported content
```

The inventory includes tool, scope, kind, path, importability, ownership, risk,
and proposed destination. `apm-native` and `convertible` are candidates;
preparation may still refuse an item or classify it reference-only.
See the [support matrix](../../../concepts/brownfield-adoption/#supported-conversions)
for agent, hook, and MCP exclusions, credential screening, and activation limits.

### Apply preparation

APM stages eligible host-owned content, validates it with existing primitive
parsers, and plans a comment-preserving manifest merge. Existing MCP
declarations are authoritative; competing definitions are reported rather
than silently replaced. Files, manifest, and provenance participate in commit
and recovery.

Versioned provenance protects local edits and reserves source destinations;
see [refresh rules](../../../concepts/brownfield-adoption/#refresh-and-local-edits).
This is not an automatic sync or force-refresh operation.

Before installing, follow [selective cutover](../../../concepts/brownfield-adoption/#cut-over):
apply preserves originals, but source-target installation can rewrite same-path
rules, skip colliding agents, and retain unmarked root context files.

### Consent and results

Preparation shows file changes, per-server warnings and environment setup,
manifest edits, losses, skips, and refusals before one confirmation.
`--yes` suppresses only that prompt. Actionable non-TTY apply requires `--yes`;
empty or unchanged plans do not prompt.

| Outcome | `write.status` | Exit |
|---|---|---|
| Empty, unchanged, or reference-only-only plan | `complete` | `0` |
| Successful apply | `complete` | `0` |
| Item refusal, conversion error, scan error, or protected conflict; eligible remainder may commit | `partial` | `1` |
| Actionable non-TTY apply without `--yes` | `refused` | `1` |
| Declined or blank confirmation | `cancelled` | `0` |
| Preparation, staged validation, or commit failure | `failed` | `1` |

Preview returns the inventory without `write`; a completed scan exits `0`
even when `errors` lists unevaluated paths. It does not certify importability.

For JSON/YAML discovery execution results, stdout contains one document;
the apply plan and prompt use stderr. Apply adds:

- `write.items`: per-source `id`, `source`, `tool`, `destination`, `decision`,
  `error`, and `changes`, including separate attribution for MCP servers sharing
  `apm.yml#dependencies.mcp`.
- `write.written`, `write.failed`, `write.skipped`, `write.manifest`, and
  `write.changes`: output paths, failures, decisions, manifest notes, and
  field-change records.
- `write.recovery`: `not-needed`, `restored`, or `incomplete`. Commit failure
  attempts restoration; incomplete recovery retains staging material for
  inspection. Do not assume a failed operation restored everything.

`refused` and `cancelled` commit nothing. EOF cancels the prompt in every
format. Ordinary Click argument/usage errors
retain their normal output contract.

### Hidden alias

`apm discover [OPTIONS]` runs the same code as `apm init --discover`.

## Examples

Initialize in the current directory with prompts:

```bash
apm init
```

Non-interactive scaffold of a new directory:

```bash
apm init my-app --yes
cd my-app
```

Plugin authoring project (creates `plugin.json` plus `apm.yml` with
`devDependencies`, version defaults to `0.1.0`):

```bash
apm init my-skill --plugin --yes
```

Pin targets up front, skip the prompt:

```bash
apm init --yes --target copilot,claude,cursor
```

## Ordinary-init behavior

- **Files created:** `apm.yml` always. `plugin.json` when `--plugin` is
  set. The `marketplace:` block is appended to `apm.yml` when
  `--marketplace` is set.
- **Auto-detected fields:**
  - `name` -- from `PROJECT_NAME` or the current directory name. Falls back
    to `my-project` if the derived name is invalid (filesystem roots and
    other edge cases).
  - `author` -- from `git config user.name`, fallback `Developer`.
  - `description` -- generated from project name.
  - `version` -- `1.0.0` (or `0.1.0` with `--plugin --yes`).
- **Brownfield (existing `apm.yml`):** prints `[!] apm.yml already exists`
  and prompts to overwrite. With `--yes`, overwrites without asking.
- **Target seeding on re-init:** when `apm.yml` exists, the prompt
  pre-checks targets read from its existing `target:` field.
- **Codex hint:** if `.codex/` is present, suggests
  `--target agent-skills` to also deploy skills to `.agents/skills/`.
- **Existing plugin sources:** when plugin-native directories such as
  `skills/`, `agents/`, or `commands/` exist at the project root and `.apm/`
  does not, warns that they remain packable. `apm init` does not create
  `.apm/` automatically.
- **agentrc suggestion:** when no agent instruction files are found
  (`.github/copilot-instructions.md`, `AGENTS.md`, `.github/instructions/`),
  the Next Steps panel suggests generating agent instructions:
  - `agentrc` in PATH: prepends `Generate agent instructions: agentrc init`
    as the first next step.
  - `agentrc` not in PATH: prints a tip line with a link to
    `https://github.com/microsoft/agentrc`.
  - Instructions already exist: no mention (suppressed entirely).
- **Exit codes:** `0` on success or user-aborted prompt; `1` on invalid
  project or plugin name, or unhandled error.

## Deprecations

The `--plugin` and `--marketplace` flags are deprecated but remain
functional for compatibility. Each invocation prints a one-line warning
to stderr pointing at the replacement command (`apm plugin init` or
`apm marketplace init`). Migrate to:

- [`apm plugin init`](../plugin/) -- replaces `apm init --plugin`.
- [`apm marketplace init`](../marketplace/) -- replaces
  `apm init --marketplace`.

## Related

- [`apm plugin init`](../plugin/) -- scaffold a publishable plugin
  (replaces `apm init --plugin`).
- [`apm marketplace init`](../marketplace/) -- scaffold a marketplace
  authoring block (replaces `apm init --marketplace`).
- [`apm install`](../install/) -- next step: install dependencies and
  deploy to targets.
- [Quickstart](../../../quickstart/) -- guided first project.
- [Concepts: package anatomy](../../../concepts/package-anatomy/) --
  what goes in `apm.yml`.
