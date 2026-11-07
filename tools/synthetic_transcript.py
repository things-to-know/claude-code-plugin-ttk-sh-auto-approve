#!/usr/bin/env python3
r"""Make a synthetic transcript out of a real one: its structure kept, every value replaced.

For development only: this file is outside ``plugin/``, so it never ships. It made
``tests/fixtures/transcript.jsonl``, which ``tests/test_explain.py`` replays, so that
``explain.py --transcript`` meets the entries Claude Code writes, not the ones a test imagined::

    python3 -I tools/synthetic_transcript.py --project <dir> <session>.jsonl \
        > tests/fixtures/transcript.jsonl

Taken from the real transcript, in its order:

- the first entry of each shape: its ``type``, and the set of block types in its
  ``message.content``, with the tool's name for a call
- assistant entries that call Bash, up to ``BASH_CALLS``, and ``PER_KIND`` of each kind: where
  the call ran (the project, a directory inside it, elsewhere) and whether its command spans
  lines

Kept in each entry: its keys, booleans and nulls, and the values Claude Code itself defines,
when they have the shape of one: a ``type``, ``role`` and the like that read as one lowercase
word, a tool's name in CamelCase, and Claude Code's version. Nesting is kept only where a
parser of Bash calls reads: the entry, its ``message``, the message's ``content`` blocks, and a
Bash call's ``input``. Any other object or list is left empty, since it can hold anything,
down to the input schema of every tool the session had.

Replaced, so that nothing the session typed, ran, read or printed is left:

- a Bash call's command: a made-up one whose verdict the tests know, wherever the same text
  appears again
- a ``cwd``: ``__PROJECT__``, ``__PROJECT__/tests`` or ``__ELSEWHERE__``, by where it is
  relative to ``--project``
- an id or a timestamp, as a value or as a key: a made-up one, the same for each real one, so
  the links between entries hold
- another tool's name, such as an MCP server's: ``mcp__example__tool``
- any other string: ``redacted``; a number: ``0``; a key that is not a plain identifier:
  ``redacted_key_<n>``

It fails closed: before printing, it checks every string it is about to write against the
shapes it may write, and the whole output for the home directory, the user name and each real
working directory, and exits 1 at the first it finds. On stderr it lists the Bash calls it
kept, as the tests expect them.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

BASH_CALLS = 10
PER_KIND = 2

REDACTED = "redacted"
PROJECT = "__PROJECT__"
INSIDE = "__PROJECT__/tests"
ELSEWHERE = "__ELSEWHERE__"
OTHER_TOOL = "mcp__example__tool"

# Commands whose verdicts tell what the parser got right: `cat AGENTS.md` is approved only from
# inside the project, which is why every call from elsewhere gets it, and `ls` alone is approved
# where `ls` followed by `git push` on the next line is refused.
MULTI_LINE = "ls\ngit push"
SINGLE_LINE = ("cat AGENTS.md", "git push", "wc -l AGENTS.md", "ls")

ENUM_KEYS = frozenset({"type", "role", "subtype", "stop_reason", "userType", "entrypoint"})
ENUM = re.compile(r"[a-z][a-z_-]{0,40}")
TOOL_NAME = re.compile(r"[A-Z][A-Za-z]{1,40}")
VERSION = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,6}")
KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,40}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
PREFIXED_ID = re.compile(r"(toolu|srvtoolu|msg|req)_[A-Za-z0-9]{8,}")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
MADE_UUID = re.compile(r"00000000-0000-4000-8000-\d{12}")
MADE_PREFIXED_ID = re.compile(r"(toolu|srvtoolu|msg|req)_\d{8}")
MADE_TIMESTAMP = re.compile(r"2026-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z")

# Where a parser of Bash calls reads, as paths of keys, `*` standing for a list's items. A Bash
# call's `input` is opened too, in `Redactor.opens`.
OPENED = frozenset({(), ("message",), ("message", "content"), ("message", "content", "*")})


def bash_calls(entry: object) -> list[dict]:
    """The Bash calls of an assistant entry, each a ``tool_use`` block with a command."""
    if not isinstance(entry, dict) or entry.get("type") != "assistant":
        return []
    message = entry.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, list):
        return []
    return [
        block
        for block in content
        if isinstance(block, dict)
        and block.get("type") == "tool_use"
        and block.get("name") == "Bash"
        and isinstance(block.get("input"), dict)
        and isinstance(block["input"].get("command"), str)
    ]


def shape(entry: dict) -> tuple[str, ...]:
    """The entry's type, and its content blocks' types, with the tool's name for a call.

    The types are a set: an ``api-request-blob`` holds a whole conversation's blocks, and their
    order would make nearly every blob a shape of its own.
    """
    message = entry.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    blocks = content if isinstance(content, list) else [content]
    kinds = []
    for block in blocks:
        if not isinstance(block, dict):
            kinds.append(type(block).__name__)
        elif block.get("type") == "tool_use":
            kinds.append(f"tool_use:{block.get('name')}")
        else:
            kinds.append(str(block.get("type")))
    return str(entry.get("type")), *sorted(set(kinds))


def where(cwd: object, project: str) -> str:
    """The placeholder for a working directory, by where it is relative to the project."""
    if cwd == project:
        return PROJECT
    if isinstance(cwd, str) and cwd.startswith(project.rstrip("/") + "/"):
        return INSIDE
    return ELSEWHERE


def select(path: Path, project: str) -> tuple[list[dict], dict[str, str], list[str]]:
    """The entries to keep, the made-up command for each real one, and the real directories."""
    kept: list[dict] = []
    commands: dict[str, str] = {}
    shapes: set[tuple[str, ...]] = set()
    kinds: Counter[tuple[str, bool]] = Counter()
    directories: set[str] = set()
    single_lines = 0
    with path.open(encoding="utf-8") as lines:
        for line in lines:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry, dict):
                continue
            if isinstance(entry.get("cwd"), str):
                directories.add(entry["cwd"])
            calls = bash_calls(entry)
            if calls:
                command = calls[0]["input"]["command"]
                kind = (where(entry.get("cwd"), project), "\n" in command)
                if sum(kinds.values()) >= BASH_CALLS or kinds[kind] >= PER_KIND:
                    continue
                kinds[kind] += 1
                for call in calls:
                    real = call["input"]["command"]
                    if "\n" in real:
                        commands.setdefault(real, MULTI_LINE)
                    elif kind[0] == ELSEWHERE:
                        commands.setdefault(real, "cat AGENTS.md")
                    elif real not in commands:
                        commands[real] = SINGLE_LINE[single_lines % len(SINGLE_LINE)]
                        single_lines += 1
                kept.append(entry)
            elif shape(entry) not in shapes:
                shapes.add(shape(entry))
                kept.append(entry)
    return kept, commands, sorted(directories)


class Redactor:
    """Replaces every value of the entries it is given, keeping what Claude Code defines."""

    def __init__(self, project: str, commands: dict[str, str]) -> None:
        """Map ``cwd`` values by ``project``, and each real command in ``commands``."""
        self.project = project
        self.commands = commands
        self.made: dict[str, str] = {}
        self.times: dict[str, str] = {}
        self.keys: dict[str, str] = {}

    def value(self, value: object, path: tuple[str, ...] = (), parent: object = None) -> object:
        """The value at ``path`` in an entry, replaced; ``parent`` is the object holding it."""
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int | float):
            return 0
        if isinstance(value, str):
            return self.string(value, path[-1] if path else None, parent)
        if not self.opens(path, parent):
            return [] if isinstance(value, list) else {}
        if isinstance(value, list):
            return [self.value(item, (*path, "*"), parent) for item in value]
        if isinstance(value, dict):
            return {
                self.key(name): self.value(item, (*path, name), value)
                for name, item in value.items()
            }
        return REDACTED

    @staticmethod
    def opens(path: tuple[str, ...], parent: object) -> bool:
        """Whether the object or list at ``path`` keeps its contents."""
        if path in OPENED:
            return True
        return (
            path == ("message", "content", "*", "input")
            and isinstance(parent, dict)
            and parent.get("type") == "tool_use"
            and parent.get("name") == "Bash"
        )

    def key(self, key: str) -> str:
        """A key that names a field, as it is; an id, made up as a value is; any other, too."""
        if UUID.fullmatch(key) or PREFIXED_ID.fullmatch(key):
            return self.made_id(key)
        if KEY.fullmatch(key) and "__" not in key:
            return key
        return self.keys.setdefault(key, f"redacted_key_{len(self.keys)}")

    def made_id(self, value: str) -> str:
        """The made-up id for a real one, the same each time it appears."""
        if match := PREFIXED_ID.fullmatch(value):
            return self.made.setdefault(value, f"{match.group(1)}_{len(self.made):08d}")
        return self.made.setdefault(value, f"00000000-0000-4000-8000-{len(self.made):012d}")

    def string(self, value: str, key: str | None, parent: object) -> str:
        """The string to write in place of ``value``, found under ``key`` in ``parent``."""
        if key == "cwd":
            return where(value, self.project)
        if value in self.commands:
            return self.commands[value]
        if key in ENUM_KEYS and ENUM.fullmatch(value):
            return value
        if key == "name" and isinstance(parent, dict) and parent.get("type") == "tool_use":
            return value if TOOL_NAME.fullmatch(value) else OTHER_TOOL
        if key == "version" and VERSION.fullmatch(value):
            return value
        if UUID.fullmatch(value) or PREFIXED_ID.fullmatch(value):
            return self.made_id(value)
        if TIMESTAMP.fullmatch(value):
            moment = EPOCH + timedelta(seconds=len(self.times))
            return self.times.setdefault(value, moment.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
        return REDACTED


def written_by_us(value: object, commands: set[str]) -> str | None:
    """The first string or key in ``value`` that has none of the shapes this tool writes."""
    if isinstance(value, list):
        return next((bad for item in value if (bad := written_by_us(item, commands))), None)
    if isinstance(value, dict):
        for name, item in value.items():
            made = (MADE_UUID, MADE_PREFIXED_ID)
            if not (
                (KEY.fullmatch(name) and "__" not in name)
                or name.startswith("redacted_key_")
                or any(pattern.fullmatch(name) for pattern in made)
            ):
                return name
            if bad := written_by_us(item, commands):
                return bad
        return None
    if not isinstance(value, str):
        return None
    fixed = {REDACTED, PROJECT, INSIDE, ELSEWHERE, OTHER_TOOL, *commands}
    shapes = (ENUM, TOOL_NAME, VERSION, MADE_UUID, MADE_PREFIXED_ID, MADE_TIMESTAMP)
    if value in fixed or any(pattern.fullmatch(value) for pattern in shapes):
        return None
    return value


def main(argv: list[str] | None = None) -> int:
    """Print the synthetic transcript, or exit 1 when anything real is left in it."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("transcript", type=Path, help="the real transcript, a .jsonl file")
    parser.add_argument("--project", required=True, help="the session's CLAUDE_PROJECT_DIR")
    args = parser.parse_args(argv)

    entries, commands, directories = select(args.transcript, args.project)
    redactor = Redactor(args.project, commands)
    output = []
    for entry in entries:
        redacted = redactor.value(entry)
        if (bad := written_by_us(redacted, set(commands.values()))) is not None:
            print(f"not a value this tool writes: {bad[:80]!r}", file=sys.stderr)
            return 1
        output.append(json.dumps(redacted, separators=(",", ":")))
        for call in bash_calls(redacted):
            command = call["input"]["command"].replace("\n", "\\n")
            print(f"{redacted.get('cwd')}\t{command}", file=sys.stderr)
    text = "\n".join(output) + "\n"
    home = str(Path.home())
    for real in (home, Path(home).name, args.project, *directories):
        if real in text:
            print(f"a real value is left: {real!r}", file=sys.stderr)
            return 1
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
