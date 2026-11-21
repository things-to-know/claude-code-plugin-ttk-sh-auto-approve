#!/usr/bin/env python3
r"""Count the Bash calls of Claude Code transcripts whose command matches a regular expression.

For development only: this file is outside ``plugin/``, so it never ships. A retrospective
looks for an earlier occurrence of what a session met, such as a command that prompted, in every
transcript on the machine::

    python3 -I tools/transcript_calls.py '^make( -s)? -C ' [<transcript or directory> ...]

With no path it reads every transcript under ``~/.claude/projects``, a subagent's included. It
prints one line per session that has a match, with the count of its matching calls by who
allowed each, and a last line with the number of sessions and the totals:

- ``user_temporary``: Claude Code prompted, and the operator allowed the call once
- ``hook``: a ``PreToolUse`` hook allowed it; ``config``: Claude Code did, by a rule or its mode
- ``unrecorded``: the transcript holds no ``permissionDecision`` for it, as before Claude Code
  2.1.293

The regular expression is searched in each command, as Python's ``re.search`` does. Only the
commands are read: nothing a call printed is.
"""

import argparse
import collections
import json
import re
from collections.abc import Iterator
from pathlib import Path

UNRECORDED = "unrecorded"


def transcripts(paths: list[Path]) -> list[Path]:
    """The transcripts in ``paths``: each file, and every ``.jsonl`` below each directory."""
    found: list[Path] = []
    for path in paths:
        found.extend(sorted(path.rglob("*.jsonl")) if path.is_dir() else [path])
    return found


def session_of(path: Path) -> str:
    """The first 8 characters of the session id; a subagent's is its session's."""
    if path.parent.name == "subagents":
        return path.parent.parent.name[:8]
    return path.stem[:8]


def bash_calls(path: Path) -> Iterator[tuple[str, str]]:
    """Each Bash call in the transcript at ``path``: its command, and who allowed it."""
    sources: dict[str, str] = {}
    calls: list[tuple[str, str]] = []
    with path.open(encoding="utf-8", errors="replace") as lines:
        for line in lines:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            message = entry.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            if not isinstance(content, list) or not content:
                continue
            decision = entry.get("permissionDecision")
            if isinstance(decision, dict) and isinstance(content[0], dict):
                sources[str(content[0].get("tool_use_id"))] = str(decision.get("source"))
            if entry.get("type") != "assistant":
                continue
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "tool_use" or block.get("name") != "Bash":
                    continue
                arguments = block.get("input")
                command = arguments.get("command") if isinstance(arguments, dict) else None
                if isinstance(command, str):
                    calls.append((str(block.get("id")), command))
    for call_id, command in calls:
        yield command, sources.get(call_id, UNRECORDED)


def count(pattern: re.Pattern[str], paths: list[Path]) -> dict[str, collections.Counter[str]]:
    """For each session with a match, its matching calls counted by who allowed each."""
    sessions: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for path in transcripts(paths):
        for command, source in bash_calls(path):
            if pattern.search(command):
                sessions[session_of(path)][source] += 1
    return dict(sessions)


def counts_text(counts: collections.Counter[str]) -> str:
    """``source=count`` pairs, by source."""
    return " ".join(f"{source}={n}" for source, n in sorted(counts.items()))


def main(argv: list[str] | None = None) -> int:
    """Print the counts per session, then the totals."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("pattern", help="a regular expression searched in each command")
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="transcripts or directories of them; by default ~/.claude/projects",
    )
    args = parser.parse_args(argv)
    paths = args.paths or [Path.home() / ".claude" / "projects"]
    sessions = count(re.compile(args.pattern), paths)
    total: collections.Counter[str] = collections.Counter()
    for session, counts in sorted(sessions.items()):
        total.update(counts)
        print(session, counts_text(counts))
    print(f"sessions {len(sessions)} {counts_text(total)}".rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
