# ttk-sh-auto-approve

A [Claude Code](https://code.claude.com/docs) plugin with 2 hooks:

- A `PreToolUse` hook that auto-approves Bash commands it can prove are read-only. Everything
  else, including errors, timeouts and unexpected input, goes through Claude Code's normal
  permission prompt.
- A `PostToolUse` hook that restores the final newline a `Write` or `Edit` left out. A `Write`
  approved at a permission prompt saves the file without one.

> **Status:** not released yet. Requires Python 3.12 or later on Linux or macOS;
> anywhere else both hooks do nothing, and every command prompts.

## The Bash tool may run zsh

> [!WARNING]
> Despite its name, Claude Code's Bash tool runs each command in your login shell when that is
> bash or zsh (zsh is the macOS default), or in the shell `CLAUDE_CODE_SHELL` names.
> The aliases and functions from your shell startup file apply too.
>
> So the hook checks every command against both grammars, and refuses anything only one of them
> would expand. What it can't see is your aliases: if one turns a read-only program such as `ls`
> or `grep` into something that writes, the hook still approves it.

## Secrets inside your project

> [!WARNING]
> The hook approves reads anywhere inside the project, its `additionalDirectories` and the
> session's scratchpad, and a secret kept there is a file like any other: `cat .env` and
> `grep -r PASSWORD .` are approved.
>
> The hook refuses a command that names a credential store under your home directory, such as
> `~/.aws` or `~/.ssh`, but refusing only leaves the call to Claude Code. Claude Code runs a
> built-in set of read-only commands, `cat` and `grep` among them, without a permission prompt in
> every mode, except as `permissions.blockReadsOutsideWorkingDirectories` changes for paths
> outside your working directories. So it runs `cat .env` unprompted with or without the hook.
>
> What stops these reads is Claude Code's own settings
> ([permissions](https://code.claude.com/docs/en/permissions)):
>
> - A `Read()` deny rule, such as `Read(//**/.env)` in `~/.claude/settings.json`. Claude Code
>   applies it even when a hook approves: to its own file tools, to the targets of redirections,
>   and to the file commands it recognizes in Bash, such as `cat`, `head` and `tail`. It doesn't
>   apply to a command that reads a file without naming it, such as `grep -r PASSWORD .`
> - `Read(//**/.env)` matches only files named `.env`: `.env.local` and the like need a rule of
>   their own, such as `Read(//**/.env.*)`
> - `permissions.blockReadsOutsideWorkingDirectories`, for paths outside your working directories
>
> The hook reads `additionalDirectories` only from the project's `.claude/settings.json` and
> `.claude/settings.local.json`. It drops an entry that is or contains your home directory, or
> that is, contains or sits inside a credential store; each entry it keeps widens what it may
> read.

## Install

Through the things-to-know plugin catalog (not published yet).

To try it for one session from a clone of this repo:

```bash
claude --plugin-dir ./plugin
```

If you registered either hook yourself, in a `settings.json` or `settings.local.json`, remove
that entry once the plugin is enabled: hooks aren't namespaced, so both copies would run.

## What runs on your machine

A plugin runs with your user privileges. This one registers 2 hooks. Both use only the Python
standard library and make no network calls.

- Before each Bash tool call, `python3 -I plugin/scripts/sh_auto_approve.py`. It writes nothing.
- After each `Write` and `Edit`, `python3 -I plugin/scripts/ensure_final_newline.py`. It appends
  a single newline to the file just written, when that is a non-empty text file without one,
  inside the project, a git repository or `~/.claude`.

## Development

See [AGENTS.md](AGENTS.md) for the layout, the rules the hook follows, how to
test it and how releases work.
