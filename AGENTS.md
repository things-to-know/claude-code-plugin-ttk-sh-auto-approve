# ttk-sh-auto-approve

Claude Code plugin:

- A `PreToolUse` hook that auto-approves Bash commands it can prove are read-only, so they don't
  raise a permission prompt, and `curl` GETs of the documentation sites a project lists
- A `PostToolUse` hook that restores the final newline a `Write` or `Edit` left out

Distributed through the `things-to-know` plugin catalog.

This file is canonical and tool-agnostic. `CLAUDE.md` imports it. If your tool
insists on its own filename, symlink to this file rather than copying it.

## Layout

- `plugin/` is the plugin root and the **only directory that ships** to users.
  Tests, CI, this file, `CLAUDE.md` and `.claude/` stay in the repo.
- `plugin/hooks/hooks.json` runs
  `python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/sh_auto_approve.py` on every Bash tool call,
  and `.../scripts/ensure_final_newline.py` after every `Write` and `Edit` (exec form, so the path
  needs no quoting)
- `tests/test_hook_contract.py` runs both hooks exactly as `hooks.json` defines them
- `ci/validate-plugin.sh` wraps `claude plugin validate` (see "No `version`").
- `tools/explain.py` prints the hook's verdict and reason for each command, for a given
  session (see [Develop](#develop))
- `tools/synthetic_transcript.py` made `tests/fixtures/transcript.jsonl` out of a real
  transcript, every value replaced; its docstring says what it keeps
- `tools/verdict_diff.py` lists the commands the hook's tests ask whose verdict differs between
  an earlier hook and the working copy's, each asked in its test's context
- `pyproject.toml` and `uv.lock` pin the dev tools (`coverage`, `ruff`), which `uv` installs
  into `.venv`; neither ships
- `docs/` holds the guides that would grow `README.md` too long: installing from a clone, and
  releasing

## Rules for the approval hook

- **Threat model:** the hook may run while Claude's context is poisoned. An
  approval for a command that isn't read-only is the failure to avoid.
  - Known gap: a read-only command can still print a secret
    - The hook approves reading a `.env` file inside the project, an `additionalDirectories`
      entry or the session's scratchpad, `grep -r` included
    - README § "Secrets inside your project" tells users what still stops it
  - Known gap: a link a command makes before it reads through it
    - Both layers resolve a path through the links on disk, and through each link an `ln` in
      the same command makes (`_record_planned_links`)
    - Not through one that another program makes, under an operator's rule for it: `tar x`,
      `unzip`, `cp -s`, `git worktree add` or a script
    - A scratchpad whose own path is a link is none: no command reaches it
  - Known gap: git in a repository whose root is out of the read roots, as for a project that
    is a package of a larger repository
    - The hook measures each path git takes, but not what a subcommand reads with none:
      `git log -p` and `git diff` read the whole repository
  - A reader that follows links while it recurses, such as `grep -R`, reads where they lead
    - Both layers walk its directory operands for links (`LINK_FOLLOWERS`), every entry,
      ignore files or not
    - Past `MAX_WALKED_ENTRIES` the command is refused outright, under any rule
    - Behind `xargs`, `find -exec` or `parallel`, no word names what it reads: refused outright
    - An operand below a value the hook didn't read isn't walked: the residual of `grep -r x "$d"`
    - A wildcard operand is matched every way a startup file can make the shell read it
      (`_glob_matches`); one it can't bound, such as `**`, is walked from its literal directory
  - One approval makes a network call: a `curl` GET of one URL on a listed site
    - What leaves the machine is a URL Claude wrote, which a poisoned context can put a secret in
      - So the request goes to an exact listed host, with no userinfo, redirect, proxy or
        `--resolve`
    - What comes in is the page, into Claude's context
      - The README says what to leave out of the list
    - Only the project's settings files widen it, through the list; see `curl` below
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
  - The hook reads `gh api` GETs itself
  - It reads these subcommands itself, flag by flag (`GH_READ_SPECS`): `pr view|list|diff|checks`,
    `run list|view`, `issue view|list`, `repo view` and `search issues|prs`
  - It leaves any other subcommand, and a flag the table doesn't list, to the operator's rules
    - Read-only ones too, such as `gh pr status`, `gh repo list` and `gh search code`
  - A `--jq` that reads the environment, or that the shell rewrites, is refused, which no rule
    overturns
  - Operators can drop native `Bash(gh ... view|list *)` allow rules for the subcommands the hook
    reads
    - A native rule still approves `--jq '$ENV.GH_TOKEN'`, and only a native deny rule stops that
- **`curl`**
  - The list of sites is the project's `WebFetch(domain:HOST)` allow rules (`_curl_sites`)
    - In the files the operator's Bash rules come from: `.claude/settings.json` and
      `.claude/settings.local.json`
    - Only from a file Claude Code applies, as for the Bash allow rules: see "Audit an allow rule"
    - Claude Code protects `.claude/`: a session's `Write` or `Edit` there is never auto-approved
      outside `bypassPermissions`
    - A repository commits `.claude/settings.json`, so a cloned one can list sites, as it can
      allow a Bash command
  - An allow rule lists a host only as written: an exact host, with no whitespace or capital
    letter
  - A `WebFetch` deny or ask rule withholds the hosts it covers
    - From the project's settings, the user's and the managed ones: Claude Code applies all of
      them, and none to a `curl`
  - Nothing is listed while a settings file the hook reads can't be read
    - Nor while managed settings set `allowManagedPermissionRulesOnly`
  - A call the validator doesn't approve is `NoOpinion`, as for `gh`
    - So an operator's `Bash(curl ...)` rule still decides it
    - That includes `-L`, a word spliced in from a variable, a command with a job behind `&`
      (in its substitutions too), a process substitution, and any curlrc unless the command
      starts with `curl -q`
- **Widening**: a change that approves more records where it stops, as
  `TheWideningsHaveAnEdge` does for the loop and splice widenings
  - Each new approval comes with its paired refusals
  - Each refusal sits beside a control approved under the same setup, so a setup that silently
    does nothing fails instead of passing
  - For a path-based widening, the refusals include a recursive read, such as `grep -r`, of the
    directory holding each credential store: Layer B refuses a word that names a store, not one
    that names its parent
  - git's quoted pathspecs, such as `'../*'`, reach no further than a literal `..`
    - Where the repository's root is in the read roots, git stops both there:
      `test_git_refuses_a_pathspec_above_its_repository` pins that stop
    - Where it isn't, the hook measures each path git takes (`_check_git_paths`), with
      `RefusesGitPathsInAnEnclosingRepository`'s refusals
- **Stdlib only, isolated interpreter.** `-I` ignores `PYTHONPATH` and user
  site-packages, and keeps the script's own directory off `sys.path`. If the
  hook is split into modules, add its directory explicitly:
  `sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))`.
- **Paths.** Never write under `${CLAUDE_PLUGIN_ROOT}`; it changes with every
  release. Persistent state goes in `${CLAUDE_PLUGIN_DATA}`. Per-project rules
  are found through `${CLAUDE_PROJECT_DIR}`, e.g.
  `$CLAUDE_PROJECT_DIR/.claude/settings.local.json`. Both are exported to the
  hook's environment.
- **Python version**:
  - The hook runs on whatever `python3` is first on the user's `PATH`, and stays silent below
    `MINIMUM_PYTHON` (3.12) or outside Linux and macOS
  - Keep `MINIMUM_PYTHON` in the CI matrix, and in the Makefile's `TEST_PYTHON_VERSIONS`

## Rules for the newline hook

- **One write**:
  - `ensure_final_newline.py` appends a single line ending, the one the file uses, to the file
    a `Write` or `Edit` named, and only inside the directories its docstring lists
  - It changes nothing else
- **Errors exit 1, never 2**: For a `PostToolUse` hook, exit 2 hands stderr to Claude as feedback;
  exit 1 only shows the user an error
- **The approval hook's last 3 rules hold for it too**:
  - stdlib only and `-I`
  - the paths
  - the Python version (tested to keep its `MINIMUM_PYTHON` and platforms in sync with the
    other hook's)

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
- Verify with `make check`, or with one target such as `make test` or `make lint-py`;
  `make help` lists them.
  - `make check` lints and tests as CI does, but with the linters installed on your machine and
    your `python3`
  - The lint targets read `git ls-files`, so a new file goes unchecked until it is committed:
    pass it, as in `make lint-py PY_FILES='<file>'`
  - For exactly CI's checks: `make check LINTERS_FROM_IMAGES=1`,
    `SH_AUTO_APPROVE_REQUIRE_ZSH=1 make test-all-python-matrix` and `make validate`
  - `make` runs `ruff` and `coverage` through `uv`, which has to be on `PATH`: from `.venv`, at
    the version `uv.lock` pins
    - `pyproject.toml` lists the dev tools; after changing it, `make compile-deps` relocks
  - `make validate` runs `claude plugin validate` through `ci/validate-plugin.sh` and needs
    `claude` on `PATH`; `make check` leaves it out.
  - Python version testing:
    - CI tests every Python version in its matrix
    - `make test` runs your `python3`
    - For a failure CI shows on one version: `make test PYTHON="$(uv python find 3.12)"`, after
      `uv python install 3.12` if that version is missing
  - zsh: `make test` skips `DifferentialAgainstZsh` when `zsh` isn't on `PATH`. CI installs zsh
    and sets `SH_AUTO_APPROVE_REQUIRE_ZSH=1`, which turns that skip into a failure.
  - `make test-coverage` runs the tests under Coverage.py and lists, for each hook, the lines and
    branches no test runs, in the hooks the tests run as separate processes too
    - It sets no minimum, so only a failing test fails it
    - It writes the HTML report to `htmlcov/`; CI runs it on one Python version and uploads that
      report as the `coverage-html` artifact
    - A refusal no test runs is a missing test or a redundant check: the report shows where to
      look, and a reader decides which
- CI runs every check through its `make` target, never the tool directly, so that a local `make`
  checks what CI does
  - A new check gets a target first, and then a CI step that calls it
  - Steps that only set up the runner, such as installing Python, uv or Claude Code, run directly
- The `main` ruleset requires a single check, `ci passed`, which fails unless every other CI job
  succeeded
  - A new job goes in the `needs` of `ci-passed`, or a PR can merge with that job failing
- Live debugging: start with `claude --debug`; `~/.claude/debug/<session-id>.txt`
  records which hooks matched and their exit codes.
- Before saying the hook approves, refuses or has no opinion on a command, run the command
  through `make explain` and quote the verdict it prints: reading the code is not a verdict
  - e.g. `printf '%s\n' 'grep -rf /etc/os-release .' | make explain`
- A hook change ends with `make verdict-diff`, and its pull request lists every verdict that
  changed
  - A refactor changes none
    - It compares only what the tests ask `_classify` in their own process: not how `main`
      builds the context, such as `_project_root`, nor what the `HookProtocol` tests send the
      hook as a separate process
    - A test that fails or errors asks nothing after its failure, and it names each on stderr
  - It compares with the hook where `HEAD` left `origin/main`, which it fetches first;
    `BASE=<revision>` compares with another
  - Past a dozen rows: a summary table, one example per issue or cause with its count, and
    every row below it in a collapsed `<details>`
- Triage a command that prompted by replaying it in its session's context, never a guessed one:
  - Find the session's transcript by its id: `ls ~/.claude/projects/*/<session-id>.jsonl`. It
    moves when the session is resumed elsewhere, and every directory there starts with `-`, so
    pass paths after `--` or prefixed with `./`
  - The transcript records the shell's working directory as `cwd` on each entry. The project
    directory is the one in the session's scratchpad path, or in "Shell cwd was reset to ..."
  - Replay with `make explain` (i.e. `tools/explain.py`):
    - Every Bash call of the session, each from its entry's `cwd`, which each line shows before
      the command: `make -s explain PROJECT=<dir> TRANSCRIPT=<transcript>`
      - Count the calls by reason: append `| cut -f1,2 | sort | uniq -c | sort -rn`
      - `uncertain`: the call came after another in its message, and the transcript doesn't
        record whether Claude Code ran the two together or in turn; the reason gives the verdict
        from each directory
      - A subagent's calls are in a transcript of its own, under `<session-id>/subagents/`
    - Chosen commands: `make explain PROJECT=<dir> CWD=<dir> < commands.txt`
    - Add `SCRATCHPAD_DIR=<dir>`, the session's scratchpad, for a command that reaches it
      - The hook reads it from its payload's `scratchpad_dir`
      - No transcript entry records it, so it goes with `TRANSCRIPT` too
      - Without it, the hook approves no command that reaches a scratchpad
      - A value the hook takes no scratchpad from, such as a relative path, gets a warning
      - It is `<temp>/claude-<uid>/<project>/<session-id>/scratchpad`, with `<temp>` per platform
        as in the "Session scratchpad directory" section of Claude Code's docs
    - Add `HOOK=<path>` to ask the installed copy instead of the working copy
- Audit an allow rule with `make explain`
  - The hook reads allow and deny rules, and `additionalDirectories`, only from the project's
    `.claude/settings.json` and `.claude/settings.local.json`; Claude Code alone applies a rule
    from any other settings file
  - It takes a file's allow rules and `additionalDirectories` only where Claude Code applies the
    file: in a workspace with a trust record in Claude Code's global config, from a setting
    source the session loaded
    - `claude -p` and the SDK run hooks in a workspace never trusted; an interactive session asks
      for trust first
    - The hook reads `--setting-sources` from Claude Code's command line, its parent process's
    - `make explain` reads this machine's trust records; `SETTING_SOURCES=user` explains a
      session started with `--setting-sources user`
  - `NO_RULES=1` and `SETTINGS=<file>` replace those 2 files, `additionalDirectories` included
  - `NO_RULES=1`: whether the hook approves the rule's command without the rule
    - If it does, the rule is redundant wherever the hook runs. It stays silent below
      `MINIMUM_PYTHON`, outside Linux and macOS, and on any error, and there the rule decides
    - For a command that reads an `additionalDirectories` entry, use `SETTINGS` instead, with a
      file that holds only the entries
  - `SETTINGS=<file>`: what else the rule approves
    - First a command the rule matches and `NO_RULES=1` doesn't approve. It has to come back
      `allow`: a file that doesn't exist reads as no rules, without a word
    - Then the writing forms of the same program, such as `make lint-fix` for `Bash(make lint-*)`
    - The hook approves a pipeline, or a list joined by `;`, `&&` or `||`, whose segments each
      only read or match an allow rule, so a wildcard rule reaches every command its pattern
      matches, wherever it stands

## Linting

When a linter flags content that is correct, fix the linter's configuration, not the content.
For example:

- The hanging indent of a docstring or a Markdown list item: `editorconfig-checker` reads it as
  a wrong indent, so the `Makefile` passes `-disable-indent-size`.
- A CommonMark list continuation: keep it, and adjust the markdownlint rule that flags it.
- A line that can't be wrapped, such as a long URL or command: exempt it in the
  configuration rather than breaking it.

`make lint-fix` applies the fixes the linters can make on their own. Review its diff like any
other change: where a fix rewrote content that was correct, revert it and adjust the rule instead.

## Commits

- Conventional commits
- The subject line comes first and stands alone: `type(scope): Summary`, as in `git log`.
- Add a body only when the subject isn't enough, but not too verbose.
- A commit stands for one distinct change: a fix a review asks for goes into the commit it
  fixes, not into a commit per finding
  - A fix to a gap older than the branch is a distinct change, with a commit of its own
  - Rebasing a PR, fold a commit that only fixes a review of an earlier one, or say in the PR
    why it stays

## Release

[docs/release.md](docs/release.md) has the steps: merge, point the catalog's `source.sha` at the
merge commit, update the installed copy, and check it took.

## Public repository

This repo is public. Before committing, review the change, its test fixtures included, for code
you don't own and for infrastructure details: hostnames, bucket names, account IDs, internal paths.
