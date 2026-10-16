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

## Install

Through the things-to-know plugin catalog (not published yet).

To try it for one session from a clone of this repo:

```bash
claude --plugin-dir ./plugin
```

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
