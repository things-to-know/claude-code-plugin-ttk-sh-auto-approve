"""`tools/synthetic_transcript.py` keeps a transcript's structure and leaves no real value in it."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "tools" / "synthetic_transcript.py"

SESSION = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"


def load_generator() -> ModuleType:
    """The generator as a module, for the checks that a whole run cannot reach.

    It puts `tools/` on `sys.path` to import `explain.py`, which is undone here.
    """
    saved = list(sys.path)
    try:
        spec = importlib.util.spec_from_file_location("synthetic_transcript", GENERATOR)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved
    return module


def generate(
    directory: str, project: str, home: str, *entries: dict
) -> subprocess.CompletedProcess[str]:
    """A run on a transcript of ``entries``, as the user whose home is ``home``."""
    transcript = Path(directory) / "real.jsonl"
    text = "".join(f"{json.dumps(entry)}\n" for entry in entries)
    transcript.write_text(text, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-I", str(GENERATOR), "--project", project, str(transcript)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={**os.environ, "HOME": home},
    )


def strings(value: object) -> list[str]:
    """Every string and key in ``value``, decoded, which JSON text may write escaped."""
    if isinstance(value, dict):
        return [text for name, item in value.items() for text in (name, *strings(item))]
    if isinstance(value, list):
        return [text for item in value for text in strings(item)]
    return [value] if isinstance(value, str) else []


def bash_call(number: int, command: str, cwd: str, **fields: object) -> dict:
    """An assistant entry calling Bash once, with the ids and timestamp a real one has."""
    return {
        "type": "assistant",
        "cwd": cwd,
        "sessionId": SESSION,
        "timestamp": f"2026-11-07T21:39:{number:02d}.292Z",
        "uuid": f"00c0ffee-0000-4000-8000-{number:012d}",
        **fields,
        "message": {
            "id": f"msg_01RealMessage{number:04d}",
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": f"toolu_01RealCall{number:04d}",
                    "name": "Bash",
                    "input": {"command": command, "description": "A real description"},
                }
            ],
        },
    }


def listed(result: subprocess.CompletedProcess[str]) -> list[str]:
    """The calls the run kept, as it lists them on stderr."""
    return [line for line in result.stderr.splitlines() if line.startswith("__")]


class LeavesNoRealValue(unittest.TestCase):
    def test_a_session_with_real_values_everywhere(self):
        """Commands, directories, a branch, an email, a tool's output, an MCP server and a
        directory that JSON writes escaped: none is left, and the calls are kept by where they
        ran and whether they span lines."""
        with tempfile.TemporaryDirectory(prefix="synthetic_transcript_") as directory:
            home = str(Path(directory) / "home" / "glarrain")
            project = f"{home}/ws/acme-app"
            elsewhere = str(Path(directory) / "elsewhere" / "josé")
            for path in (f"{project}/sub", elsewhere):
                Path(path).mkdir(parents=True)
            result = generate(
                directory,
                project,
                home,
                {
                    "type": "user",
                    "cwd": project,
                    "sessionId": SESSION,
                    "gitBranch": "glarrain/feature",
                    "message": {"role": "user", "content": "mail glarrain@example.com the s3cr3t"},
                },
                bash_call(1, "grep -r token /srv/acme-internal", project),
                {
                    "type": "user",
                    "cwd": f"{project}/sub",
                    "message": {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "toolu_01RealCall0001",
                                "content": "token=s3cr3t",
                            }
                        ],
                    },
                },
                bash_call(2, "cat ~/notes.txt", f"{project}/sub"),
                bash_call(3, "ls -la", elsewhere),
                bash_call(4, "cd sub\nmake deploy", project),
                {
                    "type": "assistant",
                    "cwd": project,
                    "message": {
                        "id": "msg_01RealMessage0005",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "toolu_01RealCall0005",
                                "name": "mcp__acme__deploy",
                                "input": {"target": "prod"},
                            }
                        ],
                    },
                },
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = [json.loads(line) for line in result.stdout.splitlines()]
        everything = [result.stdout, *(text for entry in output for text in strings(entry))]
        for real in ("glarrain", "acme", "s3cr3t", "token", "josé", "notes", "deploy", "prod"):
            with self.subTest(real):
                self.assertFalse([text for text in everything if real in text])
        self.assertEqual(
            listed(result),
            [
                "__PROJECT__\tcat AGENTS.md",
                "__PROJECT__/tests\tgit push",
                "__ELSEWHERE__\tcat AGENTS.md",
                "__PROJECT__\tls\\ngit push",
            ],
        )

    def test_the_user_name_left_as_a_word(self):
        """A value Claude Code's shape for its key lets through is still checked for the user's
        name. Beside it, the same entry with a value of Claude Code's own."""
        with tempfile.TemporaryDirectory(prefix="synthetic_transcript_") as directory:
            home = str(Path(directory) / "home" / "glarrain")
            project = f"{home}/ws/app"
            Path(project).mkdir(parents=True)
            left = generate(
                directory, project, home, bash_call(1, "ls", project, entrypoint="glarrain")
            )
            control = generate(
                directory, project, home, bash_call(1, "ls", project, entrypoint="cli")
            )
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertEqual(left.returncode, 1)
        self.assertEqual(left.stdout, "")
        self.assertIn("a real value is left: 'glarrain'", left.stderr)

    def test_a_word_claude_code_writes_is_not_the_user_name(self):
        """A user named `user` sees it as every user entry's `type` and `role`, and one named
        `ed` inside every `redacted`. Beside each, the same user's name in a key whose values
        Claude Code does not alone write, which is still checked."""
        with tempfile.TemporaryDirectory(prefix="synthetic_transcript_") as directory:
            for name in ("user", "ed"):
                with self.subTest(name):
                    home = str(Path(directory) / "home" / name)
                    project = f"{home}/ws/app"
                    Path(project).mkdir(parents=True)
                    prompt = {
                        "type": "user",
                        "cwd": project,
                        "message": {"role": "user", "content": "a prompt, redacted"},
                    }
                    run = generate(directory, project, home, prompt, bash_call(1, "ls", project))
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertIn('"type":"user"', run.stdout)
                    self.assertIn('"redacted"', run.stdout)
                    named = bash_call(1, "ls", project, entrypoint=name)
                    control = generate(directory, project, home, prompt, named)
                    self.assertEqual(control.returncode, 1)
                    self.assertIn(f"a real value is left: {name!r}", control.stderr)


class KeepsCallsByWhereTheyRan(unittest.TestCase):
    def test_the_project_with_a_trailing_slash(self):
        """`--project` with a trailing slash names the same project, as `explain.py` reads it."""
        with tempfile.TemporaryDirectory(prefix="synthetic_transcript_") as directory:
            home = str(Path(directory) / "home" / "someone")
            project = f"{home}/ws/app"
            Path(project).mkdir(parents=True)
            runs = [
                generate(directory, given, home, bash_call(1, "ls", project))
                for given in (project, f"{project}/")
            ]
        for run in runs:
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(listed(run), ["__PROJECT__\tcat AGENTS.md"])

    def test_every_single_line_call_from_elsewhere_is_cat(self):
        """`cat AGENTS.md` is approved inside the project and not elsewhere, so a call from
        elsewhere tests where it ran. A command first made up as another, inside the project,
        is not kept from elsewhere; another one, made up for the first time, is."""
        with tempfile.TemporaryDirectory(prefix="synthetic_transcript_") as directory:
            home = str(Path(directory) / "home" / "someone")
            project = f"{home}/ws/app"
            elsewhere = str(Path(directory) / "elsewhere")
            for path in (project, elsewhere):
                Path(path).mkdir(parents=True)
            run = generate(
                directory,
                project,
                home,
                bash_call(1, "pwd", project),
                bash_call(2, "ls -la", project),
                bash_call(3, "ls -la", elsewhere),
                bash_call(4, "du -sh", elsewhere),
            )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(
            listed(run),
            ["__PROJECT__\tcat AGENTS.md", "__PROJECT__\tgit push", "__ELSEWHERE__\tcat AGENTS.md"],
        )


class Checks(unittest.TestCase):
    """The checks that run before anything is printed, given values no `Redactor` writes."""

    @classmethod
    def setUpClass(cls):
        cls.generator = load_generator()

    def test_a_shape_of_claude_codes_passes_only_under_its_own_key(self):
        """A lowercase word is a `type`, `role` and the like, not a branch."""
        written_by_us = self.generator.written_by_us
        self.assertIsNone(written_by_us({"type": "assistant", "entrypoint": "cli"}, set()))
        self.assertEqual(written_by_us({"type": "assistant", "gitBranch": "acme"}, set()), "acme")

    def test_a_real_path_is_found_where_json_would_escape_it(self):
        """Read as values: as JSON text, a directory outside ASCII is written escaped."""
        real_value_left = self.generator.real_value_left
        entry = {"cwd": "/home/josé/app"}
        self.assertNotIn("/home/josé", json.dumps(entry))
        self.assertEqual(real_value_left([entry], ["/home/josé"], "", set()), "/home/josé")
        self.assertIsNone(real_value_left([{"cwd": "__PROJECT__"}], ["/home/josé"], "", set()))


if __name__ == "__main__":
    unittest.main()
