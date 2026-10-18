#!/usr/bin/env python3
"""Print the hook's verdict on each command, with its reason, as a given session would get it.

For development only: this file is outside ``plugin/``, so it never ships.

Each command gets one tab-separated line:

    allow       <reason>  <command>
    no-opinion  <reason>  <command>
    refused     <reason>  <command>

``no-opinion`` is a ``NoOpinion``: the hook stays silent and the host's own rules decide, so an
allow rule can still grant it. ``refused`` is any other ``NotReadOnly``: the hook stays silent
and no allow rule makes it approve. Neither means the host prompted: a native rule can still
let the command through.

A verdict depends on where the session stands, so the context is passed in, never guessed:

- ``--project``: ``CLAUDE_PROJECT_DIR``, the directory the session started in. To triage a
  command that prompted, take it from the session's scratchpad path, or from "Shell cwd was
  reset to ..." in its transcript
- ``--cwd``: the shell's working directory when the command ran, recorded as ``cwd`` on each
  transcript entry. It defaults to ``--project``
- ``--settings``: the settings files to read the allow and deny rules and
  ``additionalDirectories`` from, instead of the project's own; ``--no-rules`` reads none
- ``--hook``: the hook to ask, e.g. the installed copy under ``~/.claude/plugins/cache/``,
  whose decisions are the ones the operator saw. It defaults to this repository's working copy

Commands are read one per line from stdin when none is given as an argument. A command that
spans lines, such as one with a here-document, goes as an argument.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

WORKING_COPY = Path(__file__).resolve().parents[1] / "plugin" / "scripts" / "sh_auto_approve.py"


def load_hook(path: Path) -> ModuleType:
    """Import the hook from ``path`` under a name of its own, without running ``main``.

    No bytecode is written next to it: ``path`` may be the installed copy, or ``plugin/``, which
    a local marketplace install copies along with the scripts. ``-I`` ignores
    ``PYTHONDONTWRITEBYTECODE``, so the script sees to it itself.
    """
    spec = importlib.util.spec_from_file_location("sh_auto_approve", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load the hook from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    return module


def verdict(hook: ModuleType, command: str) -> tuple[str, str]:
    """The decision and its reason, from the hook's own classifier."""
    try:
        hook._classify(command)
    except hook.NoOpinion as reason:
        return "no-opinion", str(reason)
    except hook.NotReadOnly as reason:
        return "refused", str(reason)
    except RecursionError:
        return "refused", "nested too deeply to read"
    return "allow", "every command only reads, or matches an allow rule"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("commands", nargs="*", help="commands to explain; stdin when none")
    parser.add_argument("--project", required=True, help="the session's CLAUDE_PROJECT_DIR")
    parser.add_argument("--cwd", help="the shell's working directory; default: --project")
    parser.add_argument("--hook", type=Path, default=WORKING_COPY, help="the hook to ask")
    rules = parser.add_mutually_exclusive_group()
    rules.add_argument("--settings", help=f"settings files, separated by {os.pathsep!r}")
    rules.add_argument("--no-rules", action="store_true", help="read no settings file")
    args = parser.parse_args(argv)

    hook = load_hook(args.hook)
    os.environ[hook.PROJECT_DIR_ENV] = args.project
    if args.no_rules:
        os.environ[hook.SETTINGS_ENV] = ""
    elif args.settings is not None:
        os.environ[hook.SETTINGS_ENV] = args.settings
    else:
        os.environ.pop(hook.SETTINGS_ENV, None)

    # What `main` in the hook does with the payload's `cwd`, minus the version and platform
    # checks: explaining a verdict is useful on any machine.
    cwd = os.path.realpath(args.cwd or args.project)
    root = hook._project_root(cwd)
    if root is None:
        parser.error(f"no project root for {args.project}: the hook stays silent on everything")
    hook._SESSION_CWD = cwd
    hook.REPO_ROOT = root

    commands = args.commands or [line.rstrip("\n") for line in sys.stdin if line.strip()]
    for command in commands:
        print(*verdict(hook, command), command, sep="\t")
    return 0


if __name__ == "__main__":
    sys.exit(main())
