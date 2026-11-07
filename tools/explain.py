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
- ``--scratchpad-dir``: the session's scratchpad directory, the ``scratchpad_dir`` of the hook's
  payload. No transcript entry records it, so it goes with ``--transcript`` too. Without it, the
  session has no scratchpad, and the hook approves no command that reaches one. A value the hook
  takes no scratchpad from, as it takes none from a payload's of that shape, gets the same
  verdicts, and a warning on stderr
- ``--settings``: the settings files to read the allow and deny rules,
  ``additionalDirectories`` and the ``WebFetch`` rules that list the sites for ``curl`` from,
  instead of the project's own; ``--no-rules`` reads none. The ``WebFetch`` deny and ask rules of
  the user's and the managed settings, which take sites off that list, are read either way
- ``--setting-sources``: the setting sources the session loaded, as Claude Code's flag of that
  name lists them; by default every one, as in a session started without it. The hook takes
  the allow rules and ``additionalDirectories`` of the project's own files only from the
  sources the session loaded, and only in a workspace Claude Code has a trust record for,
  which it reads from this machine's Claude Code config
- ``--hook``: the hook to ask, e.g. the installed copy under ``~/.claude/plugins/cache/``,
  whose decisions are the ones the operator saw. It defaults to this repository's working copy

Commands are read one per line from stdin when none is given as an argument. A command that
spans lines, such as one with a here-document, goes as an argument.

``--transcript`` takes the commands from a session's transcript instead: every Bash call
Claude made, in order, each from the ``cwd`` its entry records, which is why it takes no
``--cwd``. A subagent's calls are in a transcript of their own. Each line gets a field before
the command, the directory the call ran in: ``.`` for the project, a path relative to it inside
it, both as the hook resolves symbolic links, and anywhere else the path as the transcript has
it:

    allow       <reason>  <directory>  <command>

The ``cwd`` on a call's entry is where the shell stood when Claude sent the message. A call
after another one in the same message started there if Claude Code ran the two together, and
from where the earlier call left the shell if it ran them in turn, which the transcript does
not record. So such a call is also replayed from the ``cwd`` that each earlier call's result
records, when that result came before its own, and where that changes the verdict, the line
says so, with each verdict and the directory it comes from:

    uncertain   <decision> from <directory>: <reason>; ...  <directory>  <command>

The fields print escaped, so that each line is one call and reads as the text it is: ``\\``
for a backslash, ``\n``, ``\t`` and ``\r``, ``\xNN`` for any other control character, which
also keeps an escape sequence away from the terminal, and ``\uNNNN`` or ``\UNNNNNNNN`` for a
format character such as a bidirectional override, a line or paragraph separator, and a lone
surrogate. A transcript that cannot be read, or a call without an absolute ``cwd``, is an
error, and nothing is printed: a partial list would read as the whole session.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import unicodedata
from pathlib import Path
from types import ModuleType
from typing import NamedTuple

WORKING_COPY = Path(__file__).resolve().parents[1] / "plugin" / "scripts" / "sh_auto_approve.py"

# How `--transcript` prints a field: a backslash doubled, and the characters that would end a
# line or a field by name
NAMED_ESCAPES = {"\\": "\\\\", "\n": "\\n", "\t": "\\t", "\r": "\\r"}

# ... and by its code, any other character of these categories: a control character, which a
# terminal acts on; a format character, such as a bidirectional override, which changes how the
# text around it reads; a line or paragraph separator; and a lone surrogate, which no encoding
# can write
CODED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})


class TranscriptError(Exception):
    """A transcript this module cannot replay; the message says which, and why."""


class Call(NamedTuple):
    """A Bash call from a transcript."""

    # Where the shell stood when Claude sent the call's message, as its entry records it
    cwd: str
    command: str
    # Where an earlier call in the same message left the shell, as that call's result records
    # it, when the result came before this call's own: the call ran from there instead if
    # Claude Code ran the two in turn
    alternatives: tuple[str, ...] = ()


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


# The verdict on a command the hook's classifier returns from
ALLOWED = ("allow", "every command only reads, or matches an allow rule")


def verdict(hook: ModuleType, command: str) -> tuple[str, str]:
    """The decision and its reason, from the hook's own classifier."""
    try:
        hook._classify(command)
    except Exception as error:  # noqa: BLE001 - as the hook's `main`, whatever the error
        return refusal(hook, error)
    return ALLOWED


def refusal(hook: ModuleType, error: Exception) -> tuple[str, str]:
    """The decision and its reason, for an exception the hook's classifier raised.

    An exception other than a ``NotReadOnly`` is a ``refused``, with the exception as its
    reason: the hook's ``main`` stays silent on one, and no allow rule gets a say.
    """
    if isinstance(error, hook.NoOpinion):
        return "no-opinion", str(error)
    if isinstance(error, hook.NotReadOnly):
        return "refused", str(error)
    if isinstance(error, RecursionError):
        return "refused", "nested too deeply to read"
    return "refused", f"the hook raised {type(error).__name__}: {error}"


def replay(hook: ModuleType, cwd: str, command: str) -> tuple[str, str]:
    """The verdict on ``command`` with the shell in ``cwd``, which the hook's ``main`` resolves."""
    hook._SESSION_CWD = os.path.realpath(cwd)
    return verdict(hook, command)


def tool_uses(entry: object) -> list[dict]:
    """The ``tool_use`` blocks in the content of ``entry``, when it is an ``assistant`` entry."""
    if not isinstance(entry, dict) or entry.get("type") != "assistant":
        return []
    message = entry.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    blocks = content if isinstance(content, list) else []
    return [
        block for block in blocks if isinstance(block, dict) and block.get("type") == "tool_use"
    ]


def bash_command(block: dict) -> str | None:
    """The command of a ``tool_use`` block, when it calls Bash with one."""
    tool_input = block.get("input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    return command if block.get("name") == "Bash" and isinstance(command, str) else None


def bash_commands(entry: object) -> list[str]:
    """The command of each Bash call in ``entry``, when it is an ``assistant`` entry."""
    return [command for block in tool_uses(entry) if (command := bash_command(block)) is not None]


def answered(entry: dict) -> list[str]:
    """The id of each call whose result a ``user`` entry holds."""
    message = entry.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    return [
        block["tool_use_id"]
        for block in (content if isinstance(content, list) else [])
        if isinstance(block, dict)
        and block.get("type") == "tool_result"
        and isinstance(block.get("tool_use_id"), str)
    ]


def replayable(cwd: object) -> bool:
    """Whether a ``cwd`` is one a call can be replayed from: an absolute path, without a NUL."""
    return isinstance(cwd, str) and "\0" not in cwd and Path(cwd).is_absolute()


def transcript_calls(path: Path) -> list[Call]:
    """Each Bash call in the transcript at ``path``, in order.

    A call is a ``tool_use`` block for the Bash tool, with a string ``command``, in the content
    of an ``assistant`` entry, and its result a ``tool_result`` block in a ``user`` entry. Other
    entries can hold copies of both, an ``api-request-blob`` among them, and are skipped, as is
    a line that is not a JSON object: the last line of a session still running may not be whole
    yet.
    """
    found: list[tuple[str, str, str | None, str | None]] = []  # cwd, command, call id, message id
    siblings: dict[str, list[str]] = {}  # message id: the id of each call it holds, in order
    results: dict[str, tuple[int, str]] = {}  # call id: the line and cwd of its result
    try:
        with path.open(encoding="utf-8") as lines:
            for number, line in enumerate(lines, start=1):
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(entry, dict):
                    continue
                cwd = entry.get("cwd")
                if entry.get("type") == "user" and replayable(cwd):
                    for call_id in answered(entry):
                        results.setdefault(call_id, (number, cwd))
                message = entry.get("message")
                message_id = message.get("id") if isinstance(message, dict) else None
                message_id = message_id if isinstance(message_id, str) else None
                for block in tool_uses(entry):
                    call_id = block.get("id") if isinstance(block.get("id"), str) else None
                    if call_id is not None and message_id is not None:
                        siblings.setdefault(message_id, []).append(call_id)
                    if (command := bash_command(block)) is None:
                        continue
                    if not replayable(cwd):
                        problem = f"{path}, line {number}: a Bash call without an absolute cwd"
                        raise TranscriptError(problem)
                    found.append((cwd, command, call_id, message_id))
    except (OSError, UnicodeDecodeError) as error:
        raise TranscriptError(f"cannot read the transcript {path}: {error}") from error

    calls = []
    for cwd, command, call_id, message_id in found:
        in_message = siblings.get(message_id, []) if message_id is not None else []
        earlier = in_message[: in_message.index(call_id)] if call_id in in_message else []
        own = results[call_id][0] if call_id in results else None
        alternatives: list[str] = []
        for sibling in earlier:
            if sibling not in results:
                continue
            line, left_in = results[sibling]
            # A result after this call's own is a call that finished after this one did, so this
            # one did not start once it had
            if own is not None and line > own:
                continue
            if left_in != cwd and left_in not in alternatives:
                alternatives.append(left_in)
        calls.append(Call(cwd, command, tuple(alternatives)))
    return calls


def shown_directory(cwd: str, root: str) -> str:
    """The directory a call ran in, as ``--transcript`` prints it.

    ``root`` is the project as the hook resolves it. ``.`` for the project and a path relative
    to it inside it, once ``cwd`` is resolved the same way, and anywhere else the path as the
    transcript has it, so that a call made away from the project stands out.
    """
    resolved = os.path.realpath(cwd)
    if resolved == root:
        return "."
    if resolved.startswith(root + os.sep):
        return resolved[len(root) + 1 :]
    return cwd


def escaped(field: str) -> str:
    """``field`` as ``--transcript`` prints it, on one line and as the text it is."""
    return "".join(_escaped(char) for char in field)


def _escaped(char: str) -> str:
    """One character of a field: by name, by its code, or as it is."""
    if char in NAMED_ESCAPES:
        return NAMED_ESCAPES[char]
    if unicodedata.category(char) not in CODED_CATEGORIES:
        return char
    code = ord(char)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def transcript_lines(hook: ModuleType, calls: list[Call], root: str) -> list[str]:
    """The line ``--transcript`` prints for each call, ending in a newline."""
    lines = []
    for call in calls:
        directories = (call.cwd, *call.alternatives)
        verdicts = [replay(hook, directory, call.command) for directory in directories]
        decision, reason = verdicts[0]
        if len(set(verdicts)) > 1:
            decision = "uncertain"
            reason = "; ".join(
                f"{each} from {shown_directory(directory, root)}: {why}"
                for directory, (each, why) in zip(directories, verdicts, strict=True)
            )
        fields = (reason, shown_directory(call.cwd, root), call.command)
        lines.append("\t".join((decision, *map(escaped, fields))) + "\n")
    return lines


def main(argv: list[str] | None = None) -> int:
    """Print the verdict and reason for each command, from the arguments, stdin or a transcript."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("commands", nargs="*", help="commands to explain; stdin when none")
    parser.add_argument("--project", required=True, help="the session's CLAUDE_PROJECT_DIR")
    parser.add_argument("--cwd", help="the shell's working directory; default: --project")
    parser.add_argument(
        "--scratchpad-dir", help="the session's scratchpad directory; default: none"
    )
    parser.add_argument("--hook", type=Path, default=WORKING_COPY, help="the hook to ask")
    parser.add_argument(
        "--transcript", type=Path, help="a session's transcript, to explain its every Bash call"
    )
    rules = parser.add_mutually_exclusive_group()
    rules.add_argument("--settings", help=f"settings files, separated by {os.pathsep!r}")
    rules.add_argument("--no-rules", action="store_true", help="read no settings file")
    parser.add_argument(
        "--setting-sources", help="the setting sources the session loaded; default: all"
    )
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

    # What `main` in the hook does with the payload's `cwd` and `scratchpad_dir`, minus the
    # version and platform checks: explaining a verdict is useful on any machine.
    cwd = os.path.realpath(args.cwd or args.project)
    root = hook._project_root(cwd)
    if root is None:
        parser.error(f"no project root for {args.project}: the hook stays silent on everything")
    hook._SESSION_CWD = cwd
    hook._SCRATCHPAD_DIR = args.scratchpad_dir
    hook.REPO_ROOT = root
    if args.setting_sources is not None:
        # Asked of the hook itself, which may be a copy that reads no setting sources
        if not hasattr(hook, "_SETTING_SOURCES"):
            parser.error(f"--setting-sources: {args.hook} reads no setting sources")
        # Claude Code refuses a name it doesn't know, rather than load no source by it
        unknown = {name.strip() for name in args.setting_sources.split(",")} - {""}
        unknown -= hook.SETTING_SOURCES
        if unknown:
            parser.error(f"--setting-sources: not a setting source: {', '.join(sorted(unknown))}")
        hook._SETTING_SOURCES = hook._setting_sources(
            [hook.SETTING_SOURCES_FLAG, args.setting_sources]
        )

    # Otherwise a typo in the option reads as the hook's own refusal. Asked of the hook itself,
    # which may be a copy that takes no `scratchpad_dir` at all.
    scratch_directory = getattr(hook, "_scratch_directory", None)
    if args.scratchpad_dir is not None and scratch_directory and scratch_directory() is None:
        print(
            f"{parser.prog}: warning: the hook takes no scratchpad from --scratchpad-dir "
            f"{args.scratchpad_dir!r}, only from an absolute, normalized path the shell reads "
            "as it is: the verdicts are a session's without one",
            file=sys.stderr,
        )

    if args.transcript is not None:
        try:
            calls = transcript_calls(args.transcript)
        except TranscriptError as error:
            parser.error(str(error))
        # Every line first, then all of them in one write: an error leaves nothing printed
        sys.stdout.write("".join(transcript_lines(hook, calls, str(root))))
        return 0

    commands = args.commands or [line.rstrip("\n") for line in sys.stdin if line.strip()]
    for command in commands:
        print(*verdict(hook, command), command, sep="\t")
    return 0


if __name__ == "__main__":
    sys.exit(main())
