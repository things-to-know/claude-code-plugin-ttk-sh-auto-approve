# ttk-sh-auto-approve

A [Claude Code](https://code.claude.com/docs) plugin with a `PreToolUse` hook
that auto-approves Bash commands it can prove are read-only. Everything else,
including errors, timeouts and unexpected input, goes through Claude Code's
normal permission prompt.

> **Status:** not released yet. Requires Python 3.12 or later on Linux or macOS;
> anywhere else the hook stays silent and every command prompts.

## Install

Through the things-to-know plugin catalog (not published yet).

To try it for one session from a clone of this repo:

```bash
claude --plugin-dir ./plugin
```

## What runs on your machine

A plugin runs with your user privileges. This one registers a single hook on
the Bash tool that runs `python3 -I plugin/scripts/sh_auto_approve.py`.
It uses only the Python standard library and makes no network calls.

## Development

See [CLAUDE.md](CLAUDE.md) for the layout, the rules the hook follows, how to
test it and how releases work.
