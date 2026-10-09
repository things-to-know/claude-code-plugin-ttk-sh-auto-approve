# ttk-sh-auto-approve

A [Claude Code](https://code.claude.com/docs) plugin with a `PreToolUse` hook
that auto-approves Bash commands it can prove are read-only. Everything else,
including errors, timeouts and unexpected input, goes through Claude Code's
normal permission prompt.

> **Status:** placeholder. The current hook never approves anything.

## Install

Through the things-to-know plugin catalog (not published yet).

To try it for one session from a clone of this repo:

```bash
claude --plugin-dir ./plugin
```

## What runs on your machine

A plugin runs with your user privileges. This one registers a single hook on
the Bash tool that runs `python3 -I plugin/scripts/bash_readonly_allow.py`.
It uses only the Python standard library and makes no network calls.

## Development

See [CLAUDE.md](CLAUDE.md) for the layout, the rules the hook follows, how to
test it and how releases work.
