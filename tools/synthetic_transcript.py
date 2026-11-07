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
  relative to ``--project``, as ``explain.py --transcript`` shows it
- an id or a timestamp, as a value or as a key: a made-up one, the same for each real one, so
  the links between entries hold
- another tool's name, such as an MCP server's: ``mcp__example__tool``
- any other string: ``redacted``; a number: ``0``; a key that is not a plain identifier:
  ``redacted_key_<n>``

It fails closed: before printing, it checks every string and key it is about to write against
the shapes it may write, each of Claude Code's under its own key, and every one of them for the
home directory, the project and each real working directory, and for the user name as a word of
its own anywhere but in a ``role`` or ``type``, and exits 1 at the first it finds. On stderr it
lists the Bash calls it kept, as the tests expect them.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

# `-I` keeps this script's own directory off `sys.path`, and `explain.py`, next to it, defines a
# Bash call and where it ran for both tools
sys.path.insert(0, str(Path(__file__).resolve().parent))
from explain import bash_commands, shown_directory

BASH_CALLS = 10
PER_KIND = 2

REDACTED = "redacted"
PROJECT = "__PROJECT__"
INSIDE = "__PROJECT__/tests"
ELSEWHERE = "__ELSEWHERE__"
OTHER_TOOL = "mcp__example__tool"

# Commands whose verdicts tell what the parser got right: `cat AGENTS.md` is approved only from
# inside the project, which is why every single-line call from elsewhere gets it, and `ls` alone
# is approved where `ls` followed by `git push` on the next line is refused.
FROM_ELSEWHERE = "cat AGENTS.md"
MULTI_LINE = "ls\ngit push"
SINGLE_LINE = (FROM_ELSEWHERE, "git push", "wc -l AGENTS.md", "ls")

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

# The keys whose values only Claude Code writes, in every entry: the user's name spelled as one
# of them, as `user` is, is not the user's name there
OWN_WORD_KEYS = frozenset({"role", "type"})


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


def where(cwd: object, root: str) -> str:
    """The placeholder for a working directory, by where ``explain.py`` shows it.

    ``root`` is the project with its symbolic links resolved, as ``explain.py`` resolves it.
    """
    if not isinstance(cwd, str) or "\0" in cwd or not Path(cwd).is_absolute():
        return ELSEWHERE
    shown = shown_directory(cwd, root)
    if shown == ".":
        return PROJECT
    return ELSEWHERE if Path(shown).is_absolute() else INSIDE


def select(path: Path, root: str) -> tuple[list[dict], dict[str, str], list[str]]:
    """The entries to keep, the made-up command for each real one, and the real directories.

    ``root`` is the project, resolved as ``explain.py`` resolves it.
    """
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
            calls = bash_commands(entry)
            if calls:
                kind = (where(entry.get("cwd"), root), "\n" in calls[0])
                # A command already made up as another one keeps it, which from elsewhere would
                # be a verdict that does not depend on where the call ran
                if kind == (ELSEWHERE, False) and any(
                    commands.get(real, FROM_ELSEWHERE) != FROM_ELSEWHERE for real in calls
                ):
                    continue
                if sum(kinds.values()) >= BASH_CALLS or kinds[kind] >= PER_KIND:
                    continue
                kinds[kind] += 1
                for real in calls:
                    if "\n" in real:
                        commands.setdefault(real, MULTI_LINE)
                    elif kind[0] == ELSEWHERE:
                        commands.setdefault(real, FROM_ELSEWHERE)
                    elif real not in commands:
                        commands[real] = SINGLE_LINE[single_lines % len(SINGLE_LINE)]
                        single_lines += 1
                kept.append(entry)
            elif shape(entry) not in shapes:
                shapes.add(shape(entry))
                kept.append(entry)
    return kept, commands, sorted(directories)


def defined_by_claude_code(value: str, key: str | None, parent: object) -> bool:
    """Whether ``value``, under ``key`` in ``parent``, is one Claude Code itself defines there.

    A ``type``, ``role`` and the like that reads as one lowercase word, a tool's name in
    CamelCase, and Claude Code's version: each shape only under its own key, so that a word a
    session wrote anywhere else is not taken for one.
    """
    if key in ENUM_KEYS:
        return ENUM.fullmatch(value) is not None
    if key == "name" and isinstance(parent, dict) and parent.get("type") == "tool_use":
        return TOOL_NAME.fullmatch(value) is not None
    return key == "version" and VERSION.fullmatch(value) is not None


class Redactor:
    """Replaces every value of the entries it is given, keeping what Claude Code defines."""

    def __init__(self, root: str, commands: dict[str, str]) -> None:
        """Map ``cwd`` values by ``root``, the resolved project, and each real command."""
        self.root = root
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
            return where(value, self.root)
        if value in self.commands:
            return self.commands[value]
        if defined_by_claude_code(value, key, parent):
            return value
        if key == "name" and isinstance(parent, dict) and parent.get("type") == "tool_use":
            return OTHER_TOOL
        if UUID.fullmatch(value) or PREFIXED_ID.fullmatch(value):
            return self.made_id(value)
        if TIMESTAMP.fullmatch(value):
            moment = EPOCH + timedelta(seconds=len(self.times))
            return self.times.setdefault(value, moment.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
        return REDACTED


def written_by_us(
    value: object, commands: set[str], key: str | None = None, parent: object = None
) -> str | None:
    """The first string or key in ``value`` that has none of the shapes this tool writes.

    ``key`` and ``parent`` say where ``value`` sits, as for ``Redactor.value``: what Claude Code
    defines passes only under the key it is defined for.
    """
    if isinstance(value, list):
        return next(
            (bad for item in value if (bad := written_by_us(item, commands, "*", parent))), None
        )
    if isinstance(value, dict):
        for name, item in value.items():
            made = (MADE_UUID, MADE_PREFIXED_ID)
            if not (
                (KEY.fullmatch(name) and "__" not in name)
                or name.startswith("redacted_key_")
                or any(pattern.fullmatch(name) for pattern in made)
            ):
                return name
            if bad := written_by_us(item, commands, name, value):
                return bad
        return None
    if not isinstance(value, str):
        return None
    fixed = {REDACTED, PROJECT, INSIDE, ELSEWHERE, OTHER_TOOL, *commands}
    made = (MADE_UUID, MADE_PREFIXED_ID, MADE_TIMESTAMP)
    if (
        value in fixed
        or any(pattern.fullmatch(value) for pattern in made)
        or defined_by_claude_code(value, key, parent)
    ):
        return None
    return value


def real_value_left(
    entries: list[object], paths: list[str], user: str, fixed: set[str]
) -> str | None:
    """The first real value left in ``entries``, read as values rather than as JSON text.

    - Each of ``paths`` that is absolute anywhere in a string or a key, except ``/``, which
      every path holds: a relative one, such as ``.``, is in nearly every string
    - ``user``, the user's name, as a word of its own: in any key, and in any string but one
      this tool wrote (``fixed``) or a ``role`` or ``type``, the keys whose values only Claude
      Code writes, so that a name such as ``user`` is not taken for itself
    """
    paths = [path for path in paths if path != os.sep and Path(path).is_absolute()]
    word = re.compile(rf"(?<!\w){re.escape(user)}(?!\w)", re.IGNORECASE) if user else None

    def found_in(text: str, key: str | None) -> str | None:
        if found := next((path for path in paths if path in text), None):
            return found
        if word is None or text in fixed or key in OWN_WORD_KEYS:
            return None
        return user if word.search(text) else None

    def walk(value: object, key: str | None) -> str | None:
        if isinstance(value, dict):
            for name, item in value.items():
                if found := found_in(name, None) or walk(item, name):
                    return found
        elif isinstance(value, list):
            for item in value:
                if found := walk(item, key):
                    return found
        elif isinstance(value, str):
            return found_in(value, key)
        return None

    return next((found for entry in entries if (found := walk(entry, None))), None)


def main(argv: list[str] | None = None) -> int:
    """Print the synthetic transcript, or exit 1 when anything real is left in it."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("transcript", type=Path, help="the real transcript, a .jsonl file")
    parser.add_argument("--project", required=True, help="the session's CLAUDE_PROJECT_DIR")
    args = parser.parse_args(argv)

    root = os.path.realpath(args.project)
    entries, commands, directories = select(args.transcript, root)
    made_up = set(commands.values())
    redactor = Redactor(root, commands)
    output = []
    for entry in entries:
        redacted = redactor.value(entry)
        if (bad := written_by_us(redacted, made_up)) is not None:
            print(f"not a value this tool writes: {bad[:80]!r}", file=sys.stderr)
            return 1
        output.append(redacted)
        for command in bash_commands(redacted):
            print(f"{redacted.get('cwd')}\t{command.replace('\n', '\\n')}", file=sys.stderr)
    home = str(Path.home())
    paths = [home, args.project, root, *directories]
    fixed = {REDACTED, PROJECT, INSIDE, ELSEWHERE, OTHER_TOOL, *made_up}
    if (real := real_value_left(output, paths, Path(home).name, fixed)) is not None:
        print(f"a real value is left: {real!r}", file=sys.stderr)
        return 1
    sys.stdout.write("".join(json.dumps(entry, separators=(",", ":")) + "\n" for entry in output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
