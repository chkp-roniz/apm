---
title: "Existing Projects"
description: "Onboard an existing project with shared packages or import supported agent configuration into APM."
sidebar:
  order: 5
---

Start with shared packages, or [import your current configuration](#import-what-you-already-have)
into a managed APM package. Save a version-control checkpoint or backup before
onboarding: installation can update native files.

## Add APM in three steps

### 1. Initialize

Run `apm init` in your project root:

```bash
apm init
```

This creates `apm.yml` alongside your existing agent files. If a manifest already
exists, ordinary init asks before overwriting it; `--yes` skips that safeguard.

### 2. Install packages

Add the shared packages your team needs:

```bash
apm install microsoft/copilot-best-practices
apm install your-org/team-standards
```

`apm.yml` records dependencies; `apm.lock.yaml` pins exact versions.
Inspect installation warnings and the resulting file changes.

### 3. Commit and share

```bash
git add apm.yml apm.lock.yaml
git commit -m "Add APM manifest"
```

Your teammates run `apm install` to restore the declared packages.

## Import what you already have

For existing rules, agents, skills, hooks, or MCP configuration, use discovery
instead of ordinary init:

```bash
apm init --discover            # read-only inventory
apm init --discover --apply    # review the import plan before confirming
```

Apply preserves original bytes and imports eligible content into `.apm/`,
creating or merging `apm.yml`. Review losses, unsupported entries, and any
per-server environment setup before consenting. Read-only discovery is not
a guarantee that every finding can be imported.

After inspecting the package and supplying required environment variables,
render it for a selected harness:

```bash
apm install --target cursor
```

Follow [selective cutover](../../concepts/brownfield-adoption/#cut-over):
source-target installation can rewrite same-path rules, skip colliding agents,
and retain unmarked root context files. Reconcile verified duplicates only;
keep unsupported originals. Activation differs by harness.

See the [support and screening limits](../../concepts/brownfield-adoption/#supported-conversions)
and [`apm init` outcomes](../../reference/cli/init/#consent-and-results).
After verified cutover, edit `.apm/` and `apm.yml`; imports are not continuously
synchronized.

## Undo onboarding

Commit failures attempt restoration; inspect the
[result and recovery contract](../../reference/cli/init/#consent-and-results)
before retrying. This does not undo a later installation.

To undo a completed onboarding, review and restore the relevant changes from
your checkpoint or backup. Deleting only `apm.yml` and `apm.lock.yaml` does not
restore rewritten native files or remove deployed content. If uninstalling
dependencies, run `apm uninstall <package>` while the manifest and lockfile
still exist; inspect the result before removing project metadata.

## Coming from `npx skills add`

APM is a drop-in replacement. The install gesture is identical, and you also
get a manifest, lockfile, and reproducible installs across machines.

```bash
# Install a whole skill bundle (equivalent to: npx skills add vercel-labs/agent-skills)
apm install vercel-labs/agent-skills

# Install a single skill from a bundle and persist the selection to apm.yml
apm install vercel-labs/agent-skills --skill deploy-to-vercel

# Subsequent bare apm install respects the persisted selection
apm install
```

The `--skill` flag is repeatable. Your selection is written to `apm.yml` and
`apm.lock.yaml` so the exact subset is reproducible on every machine. For
plugin manifest collections, pass either the skill name or the manifest path.

```bash
# Pick two skills, then reset to all
apm install vercel-labs/agent-skills --skill deploy-to-vercel --skill preview
apm install vercel-labs/agent-skills --skill '*'   # back to full bundle
```

Any public repo that works with `npx skills add owner/repo` also works with
`apm install owner/repo`. APM recognizes bare `skills/<name>/SKILL.md`
layouts (the [agentskills.io](https://agentskills.io) convention) as a
first-class package type; `apm.yml` is optional.

See [Package Types](../../reference/package-types/#skill-collection-skillsnameskillmd) for the full
skill collection layout reference.

## Next steps

- [Quickstart](../../quickstart/) -- first-time setup walkthrough
- [Dependencies](../../consumer/manage-dependencies/) -- managing external packages
- [Manifest schema](../../reference/manifest-schema/) -- full `apm.yml` reference
- [CLI commands](../../reference/cli/install/) -- complete command reference

## Deprecated targets

:::note[Deprecated]
`--target agents` is deprecated and maps to `copilot` (`.github/`), not `.agents/`. Use `--target copilot` for GitHub Copilot deployment, or `--target agent-skills` for cross-client `.agents/skills/` deployment. Removal in v1.0.
:::

## Skill routing convergence

:::caution[Behavior change]
Skills for **Copilot, Cursor, OpenCode, Codex, Gemini, and Windsurf** now deploy to `.agents/skills/` by default instead of per-client directories (`.github/skills/`, `.cursor/skills/`, `.gemini/skills/`, etc.). This matches the `.agents/` discovery path documented by those clients and eliminates redundant copies when targeting multiple clients.

**Claude and Kiro are unchanged** - their skills continue to deploy to `.claude/skills/` and `.kiro/skills/`.

To restore the previous per-client layout, pass `--legacy-skill-paths` to any command, or set the `APM_LEGACY_SKILL_PATHS=1` environment variable.
:::

### Auto-migration of legacy lockfile state

When you upgrade APM and run `apm install`, the tool automatically detects legacy per-client skill paths (`.github/skills/`, `.cursor/skills/`, `.opencode/skills/`, `.gemini/skills/`, `.windsurf/skills/`) recorded in your `apm.lock.yaml` and migrates them to `.agents/skills/`.

**What happens:**
- Old per-client skill files are deleted after the new `.agents/skills/` files are written
- The lockfile is updated to reflect the new paths
- The migration is idempotent - running `apm install` again is a no-op
- Foreign / hand-authored skills outside the lockfile are never touched

**What does NOT migrate:**
- `.claude/skills/` and `.kiro/skills/` - Claude and Kiro are not part of the convergence
- `.codex/skills/` - Codex was already on `.agents/skills/` before this change
- Any file not tracked in `apm.lock.yaml`

**If a collision is detected** (e.g., a foreign file already exists at the destination `.agents/skills/` path with different content), the migration aborts entirely with a clear error. Use `--legacy-skill-paths` to skip migration and keep per-client paths.

### CI / automation

The first `apm install` after upgrading to this version will migrate legacy
per-client skill paths to `.agents/skills/` and update `apm.lock.yaml`. In
CI pipelines, this means the working tree will show:

- Deletions under `.github/skills/`, `.cursor/skills/`, `.opencode/skills/`,
  `.gemini/skills/`, and/or `.windsurf/skills/`
- Additions under `.agents/skills/`
- An updated `apm.lock.yaml`

To handle this in CI, either:

- Commit the migrated lockfile and `.agents/skills/` directory, then update
  your CI to expect the new layout, OR
- Set `APM_LEGACY_SKILL_PATHS=1` in your CI environment to defer the
  migration until you are ready to update the lockfile in a controlled
  commit.
