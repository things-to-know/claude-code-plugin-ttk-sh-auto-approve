"""`tools/explain.py` prints the hook's verdict with its reason, for the session it is given."""

import itertools
import json
import os
import re
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

# A session's scratchpad, and another session's
SCRATCH = "/tmp/claude-1000/-home-user-project/00000000-0000-4000-8000-000000000000/scratchpad"
OTHER_SCRATCH = SCRATCH.replace("-000000000000/", "-000000000001/")


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


def run_explain(*args: str) -> subprocess.CompletedProcess[str]:
    """The run itself, for its exit status and stderr."""
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


def bash_block(command: object, call_id: str | None = None) -> dict:
    """A call to the Bash tool, as a content block."""
    return {
        "type": "tool_use",
        "id": call_id or f"toolu_{next(CALL_NUMBERS):08d}",
        "name": "Bash",
        "input": {"command": command, "description": "A made-up call"},
    }


def bash_call(
    command: str,
    cwd: str | None = str(ROOT),
    message_id: str | None = None,
    call_id: str | None = None,
) -> dict:
    """An assistant entry calling the Bash tool once, as a transcript records each call.

    Calls Claude made together, in one message, are entries of their own that share the
    message's id: none of 3,337 Bash calls in 58 real transcripts shared an entry.
    """
    return assistant(bash_block(command, call_id), cwd=cwd, message_id=message_id)


def result(call_id: str, cwd: str) -> dict:
    """The user entry holding a call's result, with where the call left the shell."""
    return {
        "type": "user",
        "cwd": cwd,
        "message": {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": call_id, "content": "output"}],
        },
    }


# A hook that raises on the command `boom`, approves any other, and has what `explain.py` uses of
# the real one
RAISING_HOOK = """
import os
from pathlib import Path

PROJECT_DIR_ENV = "CLAUDE_PROJECT_DIR"
SETTINGS_ENV = "SH_AUTO_APPROVE_SETTINGS"
REPO_ROOT = None
_SESSION_CWD = None
_SCRATCHPAD_DIR = None


class NotReadOnly(Exception):
    pass


class NoOpinion(NotReadOnly):
    pass


def _project_root(cwd):
    return Path(os.path.realpath(os.environ[PROJECT_DIR_ENV]))


def _classify(command):
    if command == "boom":
        raise ValueError("a bug")
"""


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

    def test_the_scratchpad_changes_the_verdict(self):
        """A write into a scratchpad is approved when it is the session's, as
        `--scratchpad-dir` names it, and refused when it is another session's, or when the
        session has none."""
        command = f"wc -l AGENTS.md > {SCRATCH}/out.txt"
        (own,) = explain("--scratchpad-dir", SCRATCH, command)
        (other,) = explain("--scratchpad-dir", OTHER_SCRATCH, command)
        (none,) = explain(command)
        self.assertEqual(own[0], "allow")
        for line in (other, none):
            self.assertEqual(line[:2], ["refused", "disallowed punctuation or redirection: >"])

    def test_a_scratchpad_dir_the_hook_takes_none_from_is_warned_about(self):
        """The hook takes no scratchpad from a `scratchpad_dir` that is relative, not normalized,
        or spelled in a character the shell reads otherwise, so a typo in `--scratchpad-dir`
        would read as the hook's own refusal. Each gets the verdict of a session without a
        scratchpad, as a payload of that shape does, exit status 0, and a warning naming it.
        The control, the session's own, gets no warning."""
        control = run_explain("--scratchpad-dir", SCRATCH, f"wc -l AGENTS.md > {SCRATCH}/out.txt")
        self.assertEqual((control.returncode, control.stderr), (0, ""))
        self.assertTrue(control.stdout.startswith("allow\t"), control.stdout)
        for directory in (
            "scratchpad",
            SCRATCH.replace("/scratchpad", "/x/../scratchpad"),
            "/tmp/a b/scratchpad",
        ):
            with self.subTest(directory=directory):
                result = run_explain(
                    "--scratchpad-dir", directory, f"wc -l AGENTS.md > {directory}/out.txt"
                )
                self.assertEqual(result.returncode, 0)
                self.assertTrue(result.stdout.startswith("refused\t"), result.stdout)
                self.assertIn("warning: the hook takes no scratchpad from", result.stderr)
                self.assertIn(repr(directory), result.stderr)

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

    def test_the_scratchpad_of_a_transcript(self):
        """No entry records the session's scratchpad, so `--scratchpad-dir` goes with
        `--transcript` too: a write into it is approved with the option, and refused without."""
        command = f"wc -l AGENTS.md > {SCRATCH}/out.txt"
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            path = write_transcript(directory, bash_call(command))
            (own,) = explain("--transcript", path, "--scratchpad-dir", SCRATCH)
            (none,) = explain("--transcript", path)
        self.assertEqual(own[0], "allow")
        self.assertEqual(none[0], "refused")

    def test_the_directory_as_the_hook_resolves_it(self):
        """The directory shows where the hook judged the call: a symbolic link to the project,
        or the project with a trailing slash, is the project. Anywhere else shows as the
        transcript has it, which a call from the directory holding the link is."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            link = Path(directory) / "link"
            link.symlink_to(ROOT, target_is_directory=True)
            path = write_transcript(
                directory,
                bash_call("cat AGENTS.md", cwd=str(link)),
                bash_call("cat AGENTS.md", cwd=str(link / "tests")),
                bash_call("cat AGENTS.md", cwd=f"{ROOT}/"),
                bash_call("cat AGENTS.md", cwd=f"{ROOT}/tests/"),
                bash_call("cat AGENTS.md", cwd=directory),
            )
            lines = explain("--transcript", path)
        self.assertEqual(
            [(line[0], line[2]) for line in lines],
            [
                ("allow", "."),
                ("allow", "tests"),
                ("allow", "."),
                ("allow", "tests"),
                ("no-opinion", directory),
            ],
        )

    def test_a_call_after_another_in_its_message(self):
        """Claude Code runs the calls of one message together, each from where the message
        started, or in turn, each from where the one before left the shell, and the
        transcript records neither: a session's own transcript holds both, with the same
        entries. Where the two directories give different verdicts, the line says
        `uncertain`, with each. Where the call's result came before the earlier one's, they
        ran together, and where the two verdicts agree, the directory does not matter."""

        def calls(left_in: str, *, in_turn: bool) -> list[dict]:
            results = [result("toolu_cd", left_in), result("toolu_cat", left_in)]
            return [
                bash_call("cd elsewhere", call_id="toolu_cd", message_id="msg_both"),
                bash_call("cat AGENTS.md", call_id="toolu_cat", message_id="msg_both"),
                *(results if in_turn else reversed(results)),
            ]

        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as elsewhere:
            cases = {
                "in turn, from elsewhere": calls(elsewhere, in_turn=True),
                "together": calls(elsewhere, in_turn=False),
                "in turn, from inside": calls(str(ROOT / "tests"), in_turn=True),
            }
            lines = {}
            for case, entries in cases.items():
                with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
                    path = write_transcript(directory, *entries)
                    (_, lines[case]) = explain("--transcript", path)
        self.assertEqual(lines["in turn, from elsewhere"][0], "uncertain")
        self.assertRegex(
            lines["in turn, from elsewhere"][1],
            rf"^allow from \.: .+; no-opinion from {re.escape(elsewhere)}: "
            r".*outside the working directories",
        )
        self.assertEqual(lines["in turn, from elsewhere"][2:], [".", "cat AGENTS.md"])
        self.assertEqual(lines["together"][0], "allow")
        self.assertEqual(lines["in turn, from inside"][0], "allow")

    def test_an_error_in_the_hook_is_a_refusal(self):
        """The hook's `main` stays silent on any exception, so a call the hook raises on is
        refused, with the exception as its reason, and the calls around it still print."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            hook = Path(directory) / "raising_hook.py"
            hook.write_text(RAISING_HOOK, encoding="utf-8")
            path = write_transcript(directory, bash_call("ls"), bash_call("boom"), bash_call("ls"))
            lines = explain("--hook", str(hook), "--transcript", path)
        self.assertEqual(
            [line[:2] for line in lines],
            [
                ["allow", "every command only reads, or matches an allow rule"],
                ["refused", "the hook raised ValueError: a bug"],
                ["allow", "every command only reads, or matches an allow rule"],
            ],
        )

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
        `\r`, any other control character as `\xNN`, and a format character, a line separator
        or a lone surrogate as `\uNNNN` or `\UNNNNNNNN`, in the directory as in the command. So
        each output line is one call with 4 fields, which `cut -f1,2 | sort | uniq -c` counts by
        reason; a `\n` in the output is a newline in the command, never one the command
        spelled; an escape sequence in a command does not reach the terminal; a bidirectional
        override does not make the command read as another; and a lone surrogate, which no
        encoding can write, does not end the output early. Any other character prints as it
        is."""
        commands = (
            "printf 'a\\nb'",
            "printf 'a\tb'",
            "printf 'a\rb'",
            "printf '\x1b[31m'",
            "ls\ngit push",
            "printf '\x85'",
            "ls # \u202egnp.txt",
            "ls\u2028git push",
            "printf '\U000e0001'",
            "printf '\ud83d'",
            "printf 'caf\u00e9 \u4e2d'",
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
                [".", r"printf '\x85'"],
                [".", r"ls # \u202egnp.txt"],
                [".", r"ls\u2028git push"],
                [".", r"printf '\U000e0001'"],
                [".", r"printf '\ud83d'"],
                [".", "printf 'caf\u00e9 \u4e2d'"],
                [r"a\tb", "ls"],
            ],
        )

    def test_stdin_is_not_read(self):
        """Commands come from the transcript alone. Were stdin read as well, `tools/explain.py
        --transcript ...` run at a terminal would wait for input that never comes."""
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
        """None of 3,337 Bash calls in 58 real transcripts lacked a `cwd`, so one that does, or
        whose `cwd` is not an absolute path, is a format this tool does not know, and any
        verdict for it would be a guess. Nothing is printed: a partial list would read as the
        whole session."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            (control,) = explain("--transcript", write_transcript(directory, bash_call("ls")))
            for case, cwd in {
                "missing": None,
                "empty": "",
                "relative": "tests",
                "with a NUL": f"{ROOT}\0",
            }.items():
                with self.subTest(case):
                    path = write_transcript(directory, bash_call("ls"), bash_call("ls", cwd=cwd))
                    failed = run_explain("--transcript", path)
                    self.assertEqual(failed.returncode, 2)
                    self.assertEqual(failed.stdout, "")
                    self.assertIn("line 2", error_line(failed))
        self.assertEqual(control[3], "ls")

    def test_cwd_and_a_transcript_together_are_an_error(self):
        """Each call's directory comes from its entry, so a `--cwd` would go unused."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            path = write_transcript(directory, bash_call("ls"))
            (control,) = explain("--transcript", path)
            result = run_explain("--transcript", path, "--cwd", directory)
        self.assertEqual(control[3], "ls")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("--cwd", error_line(result))

    def test_commands_and_a_transcript_together_are_an_error(self):
        with tempfile.TemporaryDirectory(prefix="readonly_hook_transcript_") as directory:
            path = write_transcript(directory, bash_call("ls"))
            (control,) = explain("--transcript", path)
            result = run_explain("--transcript", path, "wc -l AGENTS.md")
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
                    result = run_explain("--transcript", str(path))
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(path.name, error_line(result))
        self.assertEqual(control[3], "ls")


class ExplainsTheProjectFilesTheSessionApplies(unittest.TestCase):
    """The project's own files, read as the hook reads them in the session: from the setting
    sources it loaded, in a workspace Claude Code's config, in the scratch `HOME`, trusts."""

    def test_the_setting_sources_the_session_loaded(self):
        with tempfile.TemporaryDirectory(prefix="explain_sources_") as tmp:
            home, project = Path(tmp, "home"), Path(os.path.realpath(tmp), "project")
            (project / ".git").mkdir(parents=True)
            (project / ".claude").mkdir()
            home.mkdir()
            rules = {"permissions": {"allow": ["Bash(gh release list *)"]}}
            (project / ".claude" / "settings.local.json").write_text(json.dumps(rules))
            records = {"projects": {str(project): {"hasTrustDialogAccepted": True}}}
            (home / ".claude.json").write_text(json.dumps(records))

            def decision(*args: str) -> str:
                result = subprocess.run(
                    [sys.executable, "-I", str(EXPLAIN), "--project", str(project), *args],
                    input="gh release list --repo x\n",
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                    env={"PATH": os.environ["PATH"], "HOME": str(home)},
                )
                return result.stdout.split("\t")[0] or error_line(result)

            self.assertEqual("allow", decision(), "every source, as without the flag")
            self.assertEqual("allow", decision("--setting-sources", "user,local"))
            self.assertEqual("no-opinion", decision("--setting-sources", "user"))
            self.assertIn("not a setting source: lcoal", decision("--setting-sources", "lcoal"))


if __name__ == "__main__":
    unittest.main()
