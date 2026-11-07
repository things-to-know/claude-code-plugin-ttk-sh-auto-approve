#!/usr/bin/env python3
r"""Print the hook's verdict on each command, with its reason, as a given session would get it.

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

``--transcript`` takes the commands from a session's transcript instead: every Bash call
Claude made, in order, each from the ``cwd`` its entry records, which is why it takes no
``--cwd``. A subagent's calls are in a transcript of their own. Each line gets a field before
the command, the directory the call ran in: ``.`` for the project, a path relative to it inside
it, and anywhere else the path as the transcript has it:

    allow       <reason>  <directory>  <command>

The fields print escaped, so that each line is one call: ``\\`` for a backslash, ``\n``,
``\t`` and ``\r``, and ``\xNN`` for any other control character, which also keeps an escape
sequence away from the terminal. A transcript that cannot be read, or a call without a
``cwd``, is an error, and nothing is printed: a partial list would read as the whole session.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType

WORKING_COPY = Path(__file__).resolve().parents[1] / "plugin" / "scripts" / "sh_auto_approve.py"

# How `--transcript` prints a command and a reason: a backslash doubled, the characters that
# would end a line or a field by name, and any other control character by its code
ESCAPES = {
    **{code: f"\\x{code:02x}" for code in (*range(0x20), 0x7F, *range(0x80, 0xA0))},
    ord("\\"): "\\\\",
    ord("\n"): "\\n",
    ord("\t"): "\\t",
    ord("\r"): "\\r",
}


class TranscriptError(Exception):
    """A transcript this module cannot replay; the message says which, and why."""


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


def assistant_entry(line: str) -> dict | None:
    """The line's entry, when it is a JSON object of type ``assistant``."""
    try:
        entry = json.loads(line)
    except ValueError:
        return None
    return entry if isinstance(entry, dict) and entry.get("type") == "assistant" else None


def bash_commands(entry: dict) -> list[str]:
    """The command of each Bash call in an assistant entry's content."""
    message = entry.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    commands = []
    for block in content if isinstance(content, list) else []:
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            continue
        tool_input = block.get("input")
        command = tool_input.get("command") if isinstance(tool_input, dict) else None
        if block.get("name") == "Bash" and isinstance(command, str):
            commands.append(command)
    return commands


def transcript_calls(path: Path) -> list[tuple[str, str]]:
    """Each Bash call in the transcript at ``path``, in order, with the ``cwd`` it ran in.

    A call is a ``tool_use`` block for the Bash tool, with a string ``command``, in the content
    of an ``assistant`` entry. Other entries can hold copies of earlier calls, an
    ``api-request-blob`` among them, and are skipped, as is a line that is not a JSON object:
    the last line of a session still running may not be whole yet.
    """
    calls = []
    try:
        with path.open(encoding="utf-8") as lines:
            for number, line in enumerate(lines, start=1):
                entry = assistant_entry(line)
                commands = bash_commands(entry) if entry is not None else []
                cwd = entry.get("cwd") if entry is not None else None
                if commands and not (isinstance(cwd, str) and cwd):
                    raise TranscriptError(f"{path}, line {number}: a Bash call without a cwd")
                calls.extend((cwd, command) for command in commands)
    except (OSError, UnicodeDecodeError) as error:
        raise TranscriptError(f"cannot read the transcript {path}: {error}") from error
    return calls


def shown_directory(cwd: str, project: str) -> str:
    """The directory a call ran in, as ``--transcript`` prints it.

    ``.`` for the project, a path relative to it inside it, and anywhere else the path as the
    transcript has it, so that a call made away from the project stands out.
    """
    project = os.path.normpath(project)
    if cwd == project:
        return "."
    if cwd.startswith(project.rstrip(os.sep) + os.sep):
        return cwd[len(project.rstrip(os.sep)) + 1 :]
    return cwd


def main(argv: list[str] | None = None) -> int:
    """Print the verdict and reason for each command, from the arguments, stdin or a transcript."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("commands", nargs="*", help="commands to explain; stdin when none")
    parser.add_argument("--project", required=True, help="the session's CLAUDE_PROJECT_DIR")
    parser.add_argument("--cwd", help="the shell's working directory; default: --project")
    parser.add_argument("--hook", type=Path, default=WORKING_COPY, help="the hook to ask")
    parser.add_argument(
        "--transcript", type=Path, help="a session's transcript, to explain its every Bash call"
    )
    rules = parser.add_mutually_exclusive_group()
    rules.add_argument("--settings", help=f"settings files, separated by {os.pathsep!r}")
    rules.add_argument("--no-rules", action="store_true", help="read no settings file")
    args = parser.parse_args(argv)
    if args.transcript is not None and args.commands:
        parser.error("--transcript takes no commands: they come from the transcript")
    if args.transcript is not None and args.cwd is not None:
        parser.error("--cwd goes unused with --transcript: each call runs in its entry's cwd")

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

    if args.transcript is not None:
        try:
            calls = transcript_calls(args.transcript)
        except TranscriptError as error:
            parser.error(str(error))
        for call_cwd, command in calls:
            hook._SESSION_CWD = os.path.realpath(call_cwd)
            decision, reason = verdict(hook, command)
            directory = shown_directory(call_cwd, args.project)
            fields = (reason, directory, command)
            print(decision, *(field.translate(ESCAPES) for field in fields), sep="\t")
        return 0

    commands = args.commands or [line.rstrip("\n") for line in sys.stdin if line.strip()]
    for command in commands:
        print(*verdict(hook, command), command, sep="\t")
    return 0


if __name__ == "__main__":
    sys.exit(main())
