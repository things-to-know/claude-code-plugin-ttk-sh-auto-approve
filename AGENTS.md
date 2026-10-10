# ttk-sh-auto-approve

Claude Code plugin: a `PreToolUse` hook that auto-approves Bash commands it can
prove are read-only, so they don't raise a permission prompt. Distributed
through the things-to-know plugin catalog.

This file is canonical and tool-agnostic. `CLAUDE.md` imports it. If your tool
insists on its own filename, symlink to this file rather than copying it.

## Layout

- `plugin/` is the plugin root and the **only directory that ships** to users.
  Tests, CI, this file, `CLAUDE.md` and `.claude/` stay in the repo.
- `plugin/hooks/hooks.json` runs
  `python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/sh_auto_approve.py` on every
  Bash tool call (exec form, so the path needs no quoting).
- `tests/test_hook_contract.py` runs the hook exactly as `hooks.json` defines it.
- `ci/validate-plugin.sh` wraps `claude plugin validate` (see "No `version`").

## Rules for the hook

- **Threat model:** the hook may run while Claude's context is poisoned. An
  approval for a command that isn't read-only is the failure to avoid.
- **Shell**:
  - The `Bash` tool runs bash or zsh: the user's `$SHELL` when it is one of them, or the one
    `CLAUDE_CODE_SHELL` names. Every rule has to hold under both grammars.
  - When only one shell expands a construct (zsh's `${(e)x}`, `$~x`, glob qualifiers, `=(...)`,
    `echo` escapes without `-e`), refuse it wherever it is spelled.
  - Aliases and functions from the user's shell startup file apply as well, and the hook can't
    see them. The module docstring of `sh_auto_approve.py` has the sources.
- **Fail closed.** Print nothing unless the command is proven read-only. On
  any error, exit 0 with no output. Never exit 2: that blocks the call instead
  of handing it to the user. A crash or timeout also falls back to the normal
  permission prompt, but shows the user a hook error.
- **`gh`**
  - The hook reads `gh api` GETs and the read-only `pr`, `run`, `issue` and `repo` subcommands
    itself (`GH_READ_SPECS`); any other subcommand, or a flag the table doesn't list,
    is left to the operator's rules.
  - A `--jq` that reads the environment is refused, which no rule overturns.
    Operators can drop native `Bash(gh ... view|list *)` allow rules: a native rule still approves
    `--jq '$ENV.GH_TOKEN'`, and only a native deny rule stops that.
- **Stdlib only, isolated interpreter.** `-I` ignores `PYTHONPATH` and user
  site-packages, and keeps the script's own directory off `sys.path`. If the
  hook is split into modules, add its directory explicitly:
  `sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))`.
- **Paths.** Never write under `${CLAUDE_PLUGIN_ROOT}`; it changes with every
  release. Persistent state goes in `${CLAUDE_PLUGIN_DATA}`. Per-project rules
  are found through `${CLAUDE_PROJECT_DIR}`, e.g.
  `$CLAUDE_PROJECT_DIR/.claude/settings.local.json`. Both are exported to the
  hook's environment.
- **Python version.** The hook runs on whatever `python3` is first on the
  user's `PATH`, and stays silent below `MINIMUM_PYTHON` (3.12) or outside
  Linux and macOS. Keep the CI matrix's oldest version at that minimum.

## No `version`

`plugin/.claude-plugin/plugin.json` deliberately has no `version`. The version
users get is derived from the commit sha pinned in the catalog entry, so a
release is a catalog change. A `version` field would override the pin, and a
sha bump without a version bump would then leave users on the old copy.
Consequence: `claude plugin validate --strict` always fails on the missing
version, so CI runs `ci/validate-plugin.sh`, which fails on every other warning.

## Develop

- Run your working copy over the installed one:
  `claude --plugin-dir ./plugin` from the repo root, then `/reload-plugins`
  after edits. A `--plugin-dir` plugin with the same manifest name replaces the
  installed one for that session; `claude plugin list` still shows the
  installed one as enabled.
- Tests: `python3 -m unittest discover -s tests`
- Validate: `bash ci/validate-plugin.sh plugin` (needs `claude` on `PATH`)
- Live debugging: start with `claude --debug`; `~/.claude/debug/<session-id>.txt`
  records which hooks matched and their exit codes.

## Release

1. Merge to `main` with CI green.
2. In the catalog repo, set this plugin's `source.sha` to the merged commit
   (full 40-character lowercase sha):

   ```json
   {
     "name": "ttk-sh-auto-approve",
     "description": "Auto-approves Bash commands it can prove are read-only",
     "source": {
       "source": "git-subdir",
       "url": "things-to-know/claude-code-plugin-ttk-sh-auto-approve",
       "path": "plugin",
       "sha": "<sha>"
     }
   }
   ```

3. Users receive it through marketplace auto-update, if they turned it on, or
   `claude plugin marketplace update <catalog>` followed by
   `claude plugin update ttk-sh-auto-approve@<catalog>`.

## Migrating the real hook

`plugin/scripts/sh_auto_approve.py` is the real hook. Its second tier reads the operator's allow
and deny rules from `.claude/settings.json` and `.claude/settings.local.json` under
`$CLAUDE_PROJECT_DIR`. What remains:

1. This repo is public. Before committing, review the implementation and its
   test fixtures for code you don't own and for infrastructure details
   (hostnames, bucket names, account IDs, internal paths).
2. Add the existing suites under `tests/`. Keep `tests/test_hook_contract.py` passing.
3. In each repo that had the hook configured directly, remove that entry from
   `.claude/settings*.json` once the plugin is enabled there. Hooks aren't
   namespaced, so both copies would run.
