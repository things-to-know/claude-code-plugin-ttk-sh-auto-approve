"""PreToolUse hook: auto-approve Bash commands that are provably read-only.

PLACEHOLDER IMPLEMENTATION. `is_provably_read_only` always returns False, so
this hook currently never approves anything and every command goes through
Claude Code's normal permission flow. Replace this file with the real
implementation (see CLAUDE.md, "Migrating the real hook").

Contract with Claude Code (https://code.claude.com/docs/en/hooks):
- Input: one JSON object on stdin, with `tool_name` and `tool_input.command`.
- To approve: print a JSON object whose hookSpecificOutput.permissionDecision
  is "allow", and exit 0.
- No decision: print nothing and exit 0. Staying silent never approves.
- Do NOT exit 2: that blocks the call instead of deferring to the user.

Fail closed: any doubt, error or unexpected input means "print nothing".
Stdlib only, and run with `python3 -I` (see hooks/hooks.json), so the hook
never imports code from PYTHONPATH, user site-packages or its own directory.
"""

from __future__ import annotations

import json
import sys


def is_provably_read_only(command: str) -> bool:
    """Return True only when `command` is proven to have no side effects."""
    return False


def decide(payload: object) -> dict | None:
    """Return the hook output to print, or None for "no decision"."""
    if not isinstance(payload, dict) or payload.get("tool_name") != "Bash":
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    if not is_provably_read_only(command):
        return None
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": "ttm-sh-auto-approve: read-only command",
        }
    }


def main() -> int:
    try:
        decision = decide(json.load(sys.stdin))
    except Exception:  # fail closed: never let an error turn into an approval
        return 0
    if decision is not None:
        json.dump(decision, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
