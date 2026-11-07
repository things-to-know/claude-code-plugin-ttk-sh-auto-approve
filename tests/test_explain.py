"""`tools/explain.py` prints the hook's verdict with its reason, for the session it is given."""

import itertools
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPLAIN = ROOT / "tools" / "explain.py"
FIXTURE = ROOT / "tests" / "fixtures" / "transcript.jsonl"

# Each made-up call gets an id of its own, as each real one has
CALL_NUMBERS = itertools.count()


def explain(*args: str, stdin: str = "") -> list[list[str]]:
    """Each output line, split into decision, reason and command."""
    result = subprocess.run(
        [sys.executable, "-I", str(EXPLAIN), "--project", str(ROOT), "--no-rules", *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return [line.split("\t") for line in result.stdout.splitlines()]


def explain_fails(*args: str) -> subprocess.CompletedProcess[str]:
    """The run itself, for a call that is meant to fail."""
    return subprocess.run(
        [sys.executable, "-I", str(EXPLAIN), "--project", str(ROOT), "--no-rules", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def error_line(result: subprocess.CompletedProcess[str]) -> str:
    """The last line on stderr, where argparse puts its error, after the usage line.

    The usage line names every option, so it would match any error.
    """
    lines = result.stderr.strip().splitlines()
    return lines[-1] if lines else ""


def assistant(*blocks: object, cwd: str | None = str(ROOT), message_id: str | None = None) -> dict:
    """An assistant entry holding ``blocks`` as its message's content, as a transcript records it.

    ``cwd=None`` leaves the entry without the shell's working directory.
    """
    entry: dict = {
        "type": "assistant",
        "message": {
            "id": message_id or f"msg_{next(CALL_NUMBERS):08d}",
            "role": "assistant",
            "content": list(blocks),
        },
    }
    if cwd is not None:
        entry["cwd"] = cwd
    return entry


def bash_block(command: object) -> dict:
    """A call to the Bash tool, as a content block."""
    return {
        "type": "tool_use",
        "id": f"toolu_{next(CALL_NUMBERS):08d}",
        "name": "Bash",
        "input": {"command": command, "description": "A made-up call"},
    }


def bash_call(command: str, cwd: str | None = str(ROOT), message_id: str | None = None) -> dict:
    """An assistant entry calling the Bash tool once, as a transcript records each call.

    Calls Claude made together, in one message, are entries of their own that share the
    message's id: none of 3,337 Bash calls in 58 real transcripts shared an entry.
    """
    return assistant(bash_block(command), cwd=cwd, message_id=message_id)


def write_transcript(directory: str, *entries: dict | str) -> str:
    """A transcript in ``directory``, one line per entry: a dict as JSON, a str as it is."""
    path = Path(directory) / "session.jsonl"
    lines = (entry if isinstance(entry, str) else json.dumps(entry) for entry in entries)
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return str(path)


class Explains(unittest.TestCase):
    def test_an_approval_and_a_refusal_with_their_reasons(self):
        (allowed, refused) = explain("wc -l AGENTS.md", "git -C /tmp log")
        self.assertEqual(allowed[0], "allow")
        self.assertEqual(refused[0], "no-opinion")
        self.assertIn("git -C points at", refused[1])
        self.assertEqual(refused[2], "git -C /tmp log")

    def test_commands_from_stdin(self):
        lines = explain(stdin="git push\n\nls\n")
        self.assertEqual([line[0] for line in lines], ["refused", "allow"])

    def test_the_working_directory_changes_the_verdict(self):
        """The case that made the tool: a relative read is in scope from the project and out
        of it from a directory the session moved to."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_cwd_") as elsewhere:
            (inside,) = explain("cat AGENTS.md")
            (outside,) = explain("--cwd", elsewhere, "cat AGENTS.md")
        self.assertEqual(inside[0], "allow")
        self.assertEqual(outside[0], "no-opinion")
        self.assertIn("outside the working directories", outside[1])

    def test_writes_no_bytecode_next_to_the_hook(self):
        """The hook it asks may be the installed copy, or the working copy, which a local
        marketplace install copies along with its `__pycache__`."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_copy_") as directory:
            hook = Path(directory) / "sh_auto_approve.py"
            shutil.copyfile(ROOT / "plugin" / "scripts" / "sh_auto_approve.py", hook)
            (allowed,) = explain("--hook", str(hook), "ls")
            self.assertEqual(allowed[0], "allow", "the copy was loaded and asked")
            self.assertEqual(list(Path(directory).iterdir()), [hook])


class ExplainsATranscript(unittest.TestCase):
    """`--transcript` replays a session's Bash calls, each where the session stood.

    Each error case has a control that succeeds under the same setup: without one, the option's
    absence fails the same way, with argparse's exit status 2.
    """

    def test_every_bash_call_in_order(self):
        """The last 2 are calls Claude made together: entries of their own, one message id."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            path = write_transcript(
                directory,
                bash_call("wc -l AGENTS.md"),
                bash_call("git push", message_id="msg_together"),
                bash_call("ls", message_id="msg_together"),
            )
            lines = explain("--transcript", path)
        self.assertEqual([line[0] for line in lines], ["allow", "refused", "allow"])
        self.assertEqual([line[3] for line in lines], ["wc -l AGENTS.md", "git push", "ls"])

    def test_each_call_from_its_own_working_directory(self):
        """The reason for the option: one `--cwd` for a whole session gets every call after a
        `cd` wrong. Back inside after outside, so a directory kept from a previous call
        fails too. Each line shows the directory before the command: `.` for the project,
        relative inside it, and as the transcript has it anywhere else."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as elsewhere:
            path = write_transcript(
                elsewhere,
                bash_call("cat AGENTS.md"),
                bash_call("cat AGENTS.md", cwd=elsewhere),
                bash_call("cat AGENTS.md"),
                bash_call("cat AGENTS.md", cwd=str(ROOT / "tests")),
            )
            lines = explain("--transcript", path)
        self.assertEqual([line[0] for line in lines], ["allow", "no-opinion", "allow", "allow"])
        self.assertIn("outside the working directories", lines[1][1])
        self.assertEqual([line[2] for line in lines], [".", elsewhere, ".", "tests"])

    def test_a_command_that_spans_lines_is_judged_whole(self):
        """Not by its first line, which alone would be approved."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            path = write_transcript(directory, bash_call("ls\ngit push"), bash_call("ls"))
            (whole, first_line) = explain("--transcript", path)
        self.assertEqual(whole[0], "refused")
        self.assertIn("push", whole[1])
        self.assertEqual(first_line[0], "allow")

    def test_each_command_prints_escaped_on_one_line(self):
        r"""A backslash prints as `\\`, a newline as `\n`, a tab as `\t`, a carriage return as
        `\r`, and any other control character as `\xNN`, in the directory as in the command. So
        each output line is one call with 4 fields, which `cut -f1,2 | sort | uniq -c` counts by
        reason; a `\n` in the output is a newline in the command, never one the command
        spelled; and an escape sequence in a command does not reach the terminal."""
        commands = (
            "printf 'a\\nb'",
            "printf 'a\tb'",
            "printf 'a\rb'",
            "printf '\x1b[31m'",
            "ls\ngit push",
        )
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            path = write_transcript(
                directory,
                *map(bash_call, commands),
                bash_call("ls", cwd=str(ROOT / "a\tb")),
            )
            lines = explain("--transcript", path)
        self.assertEqual(
            [line[2:] for line in lines],
            [
                [".", r"printf 'a\\nb'"],
                [".", r"printf 'a\tb'"],
                [".", r"printf 'a\rb'"],
                [".", r"printf '\x1b[31m'"],
                [".", r"ls\ngit push"],
                [r"a\tb", "ls"],
            ],
        )

    def test_stdin_is_not_read(self):
        """Commands come from the transcript alone. Were stdin read as well, `make explain
        TRANSCRIPT=...` run at a terminal would wait for input that never comes."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            path = write_transcript(directory, bash_call("ls"))
            lines = explain("--transcript", path, stdin="git push\n")
        self.assertEqual([line[3] for line in lines], ["ls"])

    def test_only_bash_calls_are_explained(self):
        """A transcript also holds prompts, summaries, text, other tools' calls, tool results,
        copies of earlier calls outside assistant entries, and, while the session runs, a last
        line that is not whole yet. The other lines are shapes no real transcript has, each of
        which a parser that trusts the format would crash on. Each line mentions a command that
        would be refused, where it can, so one taken for a call shows."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            path = write_transcript(
                directory,
                {"type": "user", "cwd": str(ROOT), "message": {"content": "run git push"}},
                {"type": "summary", "summary": "git push"},
                assistant(
                    {"type": "text", "text": "git push"},
                    {"type": "tool_use", "id": "toolu_read", "name": "Read", "input": {}},
                ),
                bash_call("wc -l AGENTS.md"),
                {
                    "type": "user",
                    "cwd": str(ROOT),
                    "message": {
                        "content": [
                            {"type": "tool_result", "tool_use_id": "toolu_0", "content": "git push"}
                        ]
                    },
                },
                {"type": "api-request-blob", "message": {"content": [bash_block("git push")]}},
                "42",
                "[]",
                '"git push"',
                "null",
                {"type": "assistant", "cwd": str(ROOT)},
                {"type": "assistant", "cwd": str(ROOT), "message": None},
                {"type": "assistant", "cwd": str(ROOT), "message": {"content": None}},
                {"type": "assistant", "cwd": str(ROOT), "message": {"content": "git push"}},
                assistant({"type": "tool_use", "id": "toolu_no_input", "name": "Bash"}),
                assistant({"type": "tool_use", "id": "toolu_text", "name": "Bash", "input": "ls"}),
                assistant(bash_block(["git push"])),
                "",
                '{"type": "assistant", "message": {"content": [{"type": "tool_use", '
                '"name": "Bash", "input": {"command": "git push"',
            )
            lines = explain("--transcript", path)
        self.assertEqual([line[3] for line in lines], ["wc -l AGENTS.md"])

    def test_a_transcript_as_claude_code_writes_it(self):
        """`tests/fixtures/transcript.jsonl` is a real session's transcript with every value
        replaced, by `tools/synthetic_transcript.py`: the first entry of each shape the session
        wrote, and 10 of its Bash calls, from the project, a directory inside it and elsewhere.
        Its `api-request-blob` entries repeat earlier calls, which must not be counted again."""
        text = FIXTURE.read_text(encoding="utf-8")
        copies = [
            block
            for entry in map(json.loads, text.splitlines())
            if entry["type"] != "assistant"
            for block in entry.get("message", {}).get("content", [])
            if isinstance(block, dict) and block.get("name") == "Bash"
        ]
        self.assertTrue(copies, "the fixture still holds calls outside assistant entries")
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as elsewhere:
            for placeholder, real in (("__ELSEWHERE__", elsewhere), ("__PROJECT__", str(ROOT))):
                text = text.replace(placeholder, json.dumps(real)[1:-1])
            path = Path(elsewhere) / "session.jsonl"
            path.write_text(text, encoding="utf-8")
            lines = explain("--transcript", str(path))
        self.assertEqual(
            [(line[0], line[2], line[3]) for line in lines],
            [
                ("allow", ".", "cat AGENTS.md"),
                ("refused", "tests", "git push"),
                ("allow", "tests", "wc -l AGENTS.md"),
                ("allow", ".", "ls"),
                *[("refused", "tests", "ls\\ngit push")] * 2,
                *[("refused", ".", "ls\\ngit push")] * 2,
                *[("no-opinion", elsewhere, "cat AGENTS.md")] * 2,
            ],
        )

    def test_a_call_without_a_working_directory_is_an_error(self):
        """None of 3,337 Bash calls in 58 real transcripts lacked a `cwd`, so one that does is a
        format this tool does not know, and any verdict for it would be a guess. Nothing is
        printed: a partial list would read as the whole session."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            (control,) = explain("--transcript", write_transcript(directory, bash_call("ls")))
            path = write_transcript(directory, bash_call("ls"), bash_call("ls", cwd=None))
            result = explain_fails("--transcript", path)
        self.assertEqual(control[3], "ls")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("line 2", error_line(result))

    def test_cwd_and_a_transcript_together_are_an_error(self):
        """Each call's directory comes from its entry, so a `--cwd` would go unused."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            path = write_transcript(directory, bash_call("ls"))
            (control,) = explain("--transcript", path)
            result = explain_fails("--transcript", path, "--cwd", directory)
        self.assertEqual(control[3], "ls")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("--cwd", error_line(result))

    def test_commands_and_a_transcript_together_are_an_error(self):
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            path = write_transcript(directory, bash_call("ls"))
            (control,) = explain("--transcript", path)
            result = explain_fails("--transcript", path, "wc -l AGENTS.md")
        self.assertEqual(control[3], "ls")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("--transcript", error_line(result))

    def test_a_transcript_that_cannot_be_read_is_an_error(self):
        """Missing, a directory, or not UTF-8: the error names it, and nothing is printed."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            (control,) = explain("--transcript", write_transcript(directory, bash_call("ls")))
            not_utf8 = Path(directory) / "latin1.jsonl"
            not_utf8.write_bytes(b'{"type": "summary", "summary": "caf\xe9"}\n')
            unreadable = {
                "missing": Path(directory) / "missing.jsonl",
                "a directory": Path(directory),
                "not UTF-8": not_utf8,
            }
            for case, path in unreadable.items():
                with self.subTest(case):
                    result = explain_fails("--transcript", str(path))
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(path.name, error_line(result))
        self.assertEqual(control[3], "ls")


if __name__ == "__main__":
    unittest.main()
