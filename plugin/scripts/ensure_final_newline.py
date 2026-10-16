#!/usr/bin/env python3
"""Restore the final newline that a ``Write`` or ``Edit`` left out.

A Claude Code ``PostToolUse`` hook, which the plugin's ``hooks/hooks.json`` runs after every
``Write`` and ``Edit``. It is the plugin's one hook that writes, and what it writes is a single
newline, at the end of a file Claude has just written.

A ``Write`` approved at a permission prompt, PyCharm's diff view, saves the file without its final
newline, whether or not the operator changed the content there. A ``Write`` that needs no prompt
keeps it, and so does an ``Edit`` in the middle of a file. Neither tool can put it back: ``Write``
loses it again, and an ``Edit`` whose ``old_string`` reaches the end of the file fails with
"String not found". The hook covers ``Edit`` as well, in case one ever drops it.

The hook acts on a file inside any of:

- ``CLAUDE_PROJECT_DIR``
- a git worktree: the nearest directory above the file that holds a ``.git`` entry, a directory
  for a repository or a file for a linked worktree
- Claude's configuration directory, ``CLAUDE_CONFIG_DIR`` or else ``~/.claude``: the user's
  ``CLAUDE.md``, skills and memories

The home directory and ``/`` never count as one of these, so a file outside every repository,
such as a token file meant to end without a newline, is left alone.

The hook reads the tool call on stdin and appends a single line ending to the file it names:
the one its first line ends with, ``\\r\\n`` or ``\\n``, and ``\\n`` when no line has ended yet.
A file that ends in a bare ``\\r`` with ``\\r\\n`` endings gets the ``\\n`` that completes it.
It changes nothing else, and leaves the file alone when it is:

- named by a tool other than ``Write`` or ``Edit``, or by a relative path
- outside the directories above, once symlinks are resolved
- not a regular file, or empty
- already ending in ``\\n``
- binary, judged by a NUL byte in its first 8 KiB

A text file meant to end without a newline, such as a test fixture, gets one too: write it from
the shell instead.

Requires Python ``MINIMUM_PYTHON`` or later on Linux or macOS, as ``sh_auto_approve.py`` does.
Anywhere else it does nothing. An error exits 1, which Claude Code reports without blocking
anything: by the time a ``PostToolUse`` hook runs, the tool call is over.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# The same as `sh_auto_approve.py`'s, which says why; a test keeps the two equal.
MINIMUM_PYTHON = (3, 12)
SUPPORTED_PLATFORMS = ("linux", "darwin")

TOOLS = frozenset({"Edit", "Write"})
SNIFF_BYTES = 8192


def too_wide(directory: Path) -> bool:
    """Whether ``directory`` is ``/`` or the home directory, too wide to stand for a project."""
    return directory.parent == directory or directory == Path.home().resolve()


def roots() -> list[Path]:
    """``CLAUDE_PROJECT_DIR`` and Claude's configuration directory, resolved."""
    candidates = (
        os.environ.get("CLAUDE_PROJECT_DIR"),
        os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude",
    )
    resolved = [Path(candidate).resolve() for candidate in candidates if candidate]
    return [root for root in resolved if not too_wide(root)]


def in_git_worktree(path: Path) -> bool:
    """Whether the nearest directory above ``path`` with a ``.git`` entry is a narrow one."""
    for directory in path.parents:
        if os.path.lexists(directory / ".git"):
            return not too_wide(directory)
    return False


def target(event: object) -> Path | None:
    """The file a ``Write`` or ``Edit`` touched, if the hook may act on it, or ``None``."""
    if not isinstance(event, dict) or event.get("tool_name") not in TOOLS:
        return None
    tool_input = event.get("tool_input")
    file_path = tool_input.get("file_path") if isinstance(tool_input, dict) else None
    if not isinstance(file_path, str) or not os.path.isabs(file_path):
        return None
    path = Path(file_path).resolve()
    if any(path.is_relative_to(root) for root in roots()) or in_git_worktree(path):
        return path
    return None


def missing_ending(path: Path) -> bytes | None:
    """What a non-empty text file needs to end its last line, or ``None`` if it needs nothing."""
    if not path.is_file():
        return None
    with path.open("rb") as file:
        head = file.read(SNIFF_BYTES)
        if not head or b"\0" in head:
            return None
        file.seek(-1, os.SEEK_END)
        last = file.read(1)
    if last == b"\n":
        return None
    first = head.find(b"\n")
    if first < 1 or head[first - 1 : first] != b"\r":
        return b"\n"
    return b"\n" if last == b"\r" else b"\r\n"


def main() -> int:
    """Claude Code PostToolUse hook entry point."""
    if sys.version_info < MINIMUM_PYTHON or sys.platform not in SUPPORTED_PLATFORMS:
        return 0
    path = target(json.load(sys.stdin))
    ending = None if path is None else missing_ending(path)
    if ending is not None:
        with path.open("ab") as file:
            file.write(ending)
    return 0


if __name__ == "__main__":
    sys.exit(main())
