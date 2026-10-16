"""Tests for the `PostToolUse` hook that restores the final newline after `Write` and `Edit`.

The hook under test is `plugin/scripts/ensure_final_newline.py`, run as a subprocess the way
Claude Code runs it: the tool call as JSON on stdin, with `CLAUDE_PROJECT_DIR` and `HOME` naming
directories in a temporary one. `test_hook_contract.py` checks that `hooks.json` runs it. The hook
writes files, so every case asserts the exact bytes left behind, and the cases that leave a file
alone matter as much as the ones that fix it.
"""

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "plugin" / "scripts"
HOOK_PATH = SCRIPTS / "ensure_final_newline.py"


def load(name: str):
    """Import one of the plugin's scripts by path, without running its ``main``."""
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EnsureFinalNewline(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        if any((directory / ".git").exists() for directory in self.root.parents):
            self.skipTest(f"{self.root} is inside a git worktree, which the hook acts on")
        self.project = self.root / "project"
        self.home = self.root / "home"
        self.project.mkdir()
        self.home.mkdir()
        self.env = {
            **{name: value for name, value in os.environ.items() if name != "CLAUDE_CONFIG_DIR"},
            "CLAUDE_PROJECT_DIR": str(self.project),
            "HOME": str(self.home),
        }

    def run_hook(
        self,
        file_path: Path | str,
        tool_name: str = "Write",
        **env: str | None,
    ) -> subprocess.CompletedProcess[str]:
        """Run the hook, with ``env`` changing the environment: ``None`` removes a variable."""
        event = {
            "hook_event_name": "PostToolUse",
            "tool_name": tool_name,
            "tool_input": {"file_path": str(file_path)},
        }
        environment = {**self.env, **env}
        result = subprocess.run(
            [sys.executable, "-I", str(HOOK_PATH)],
            input=json.dumps(event),
            capture_output=True,
            text=True,
            cwd=self.project,
            env={name: value for name, value in environment.items() if value is not None},
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def write(self, path: Path, content: bytes = b"last line") -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_appends_the_newline_a_write_left_out(self) -> None:
        path = self.write(self.project / "doc.md", b"# Title\n\nlast line")
        self.run_hook(path)
        self.assertEqual(path.read_bytes(), b"# Title\n\nlast line\n")

    def test_appends_the_newline_an_edit_left_out(self) -> None:
        path = self.write(self.project / "doc.md")
        self.run_hook(path, tool_name="Edit")
        self.assertEqual(path.read_bytes(), b"last line\n")

    def test_appends_the_line_ending_the_file_uses(self) -> None:
        """The first line's ending decides, so a file in `\\r\\n` does not end in a bare `\\n`."""
        cases = {
            "crlf": (b"a\r\nlast line", b"a\r\nlast line\r\n"),
            "crlf, cut after the cr": (b"a\r\nlast line\r", b"a\r\nlast line\r\n"),
            "lf": (b"a\nlast line", b"a\nlast line\n"),
            "lf first, then crlf": (b"a\nb\r\nlast line", b"a\nb\r\nlast line\n"),
            "a blank first line": (b"\nlast line", b"\nlast line\n"),
            "one line": (b"last line", b"last line\n"),
        }
        for label, (content, expected) in cases.items():
            with self.subTest(label):
                path = self.write(self.project / "doc.md", content)
                self.run_hook(path)
                self.run_hook(path, tool_name="Edit")
                self.assertEqual(path.read_bytes(), expected, "once, however often it runs")

    def test_appends_a_single_newline_however_often_it_runs(self) -> None:
        path = self.write(self.project / "doc.md")
        self.run_hook(path)
        self.run_hook(path, tool_name="Edit")
        self.assertEqual(path.read_bytes(), b"last line\n")

    def test_follows_a_symlink_that_stays_inside_the_project(self) -> None:
        real = self.write(self.project / "real.md")
        link = self.project / "link.md"
        link.symlink_to(real)
        self.run_hook(link)
        self.assertEqual(real.read_bytes(), b"last line\n")

    def test_appends_in_a_repository_outside_the_project(self) -> None:
        (self.root / "repo" / ".git").mkdir(parents=True)
        path = self.write(self.root / "repo" / "docs" / "doc.md")
        self.run_hook(path)
        self.assertEqual(path.read_bytes(), b"last line\n")

    def test_appends_in_a_linked_worktree_outside_the_project(self) -> None:
        self.write(self.root / "worktree" / ".git", b"gitdir: /elsewhere/.git/worktrees/x\n")
        path = self.write(self.root / "worktree" / "doc.md")
        self.run_hook(path)
        self.assertEqual(path.read_bytes(), b"last line\n")

    def test_appends_in_the_configuration_directory(self) -> None:
        path = self.write(self.home / ".claude" / "CLAUDE.md")
        self.run_hook(path)
        self.assertEqual(path.read_bytes(), b"last line\n")

    def test_the_configuration_directory_follows_its_variable(self) -> None:
        configured = self.write(self.root / "config" / "CLAUDE.md")
        default = self.write(self.home / ".claude" / "CLAUDE.md")
        self.run_hook(configured, CLAUDE_CONFIG_DIR=str(self.root / "config"))
        self.run_hook(default, CLAUDE_CONFIG_DIR=str(self.root / "config"))
        self.assertEqual(configured.read_bytes(), b"last line\n")
        self.assertEqual(default.read_bytes(), b"last line")

    def test_works_without_a_project_directory(self) -> None:
        (self.root / "repo" / ".git").mkdir(parents=True)
        in_repo = self.write(self.root / "repo" / "doc.md")
        in_project = self.write(self.project / "doc.md")
        self.run_hook(in_repo, CLAUDE_PROJECT_DIR=None)
        self.run_hook(in_project, CLAUDE_PROJECT_DIR=None)
        self.assertEqual(in_repo.read_bytes(), b"last line\n")
        self.assertEqual(in_project.read_bytes(), b"last line")

    def test_leaves_alone_a_file_that_needs_nothing(self) -> None:
        cases = {
            "ends in a newline": b"last line\n",
            "ends in a blank line": b"last line\n\n",
            "is empty": b"",
            "is binary": b"\x89PNG\r\n\x1a\n\x00\x00",
        }
        for label, content in cases.items():
            with self.subTest(label):
                path = self.write(self.project / "file", content)
                self.run_hook(path)
                self.assertEqual(path.read_bytes(), content)

    def test_leaves_alone_a_file_outside_every_directory_it_acts_on(self) -> None:
        cases = {
            "beside the project": self.root / "outside.md",
            "in the home directory": self.home / "notes.md",
            "in a sibling of the configuration directory": self.home / ".config" / "token",
        }
        for label, path in cases.items():
            with self.subTest(label):
                self.write(path)
                self.run_hook(path)
                self.assertEqual(path.read_bytes(), b"last line")

    def test_leaves_alone_a_symlink_out_of_the_project(self) -> None:
        outside = self.write(self.root / "outside.md")
        link = self.project / "link.md"
        link.symlink_to(outside)
        self.run_hook(link)
        self.assertEqual(outside.read_bytes(), b"last line")

    def test_leaves_alone_a_project_that_only_shares_a_prefix(self) -> None:
        path = self.write(self.root / "project-other" / "doc.md")
        self.run_hook(path)
        self.assertEqual(path.read_bytes(), b"last line")

    def test_leaves_alone_the_home_directory_as_a_project(self) -> None:
        path = self.write(self.home / "notes.md")
        self.run_hook(path, CLAUDE_PROJECT_DIR=str(self.home))
        self.run_hook(path, CLAUDE_PROJECT_DIR="/")
        self.assertEqual(path.read_bytes(), b"last line")

    def test_leaves_alone_the_home_directory_as_a_repository(self) -> None:
        (self.home / ".git").mkdir()
        (self.home / "repo" / ".git").mkdir(parents=True)
        at_home = self.write(self.home / "notes.md")
        in_repo = self.write(self.home / "repo" / "doc.md")
        self.run_hook(at_home)
        self.run_hook(in_repo)
        self.assertEqual(at_home.read_bytes(), b"last line")
        self.assertEqual(in_repo.read_bytes(), b"last line\n")

    def test_leaves_alone_a_file_named_by_another_tool(self) -> None:
        path = self.write(self.project / "notes.md")
        for tool_name in ("NotebookEdit", "Read", "MultiEdit"):
            with self.subTest(tool_name):
                self.run_hook(path, tool_name=tool_name)
                self.assertEqual(path.read_bytes(), b"last line")

    def test_leaves_alone_a_relative_path(self) -> None:
        path = self.write(self.project / "doc.md")
        self.run_hook("doc.md")
        self.assertEqual(path.read_bytes(), b"last line")

    def test_ignores_a_file_that_is_gone(self) -> None:
        path = self.project / "deleted.md"
        self.run_hook(path)
        self.assertFalse(path.exists())

    def test_does_nothing_where_the_plugin_is_not_supported(self) -> None:
        """Run in-process, since the platform and the version are the interpreter's own."""
        newline = load("ensure_final_newline")
        path = self.write(self.project / "doc.md")
        event = json.dumps({"tool_name": "Write", "tool_input": {"file_path": str(path)}})
        unsupported = (
            unittest.mock.patch.object(sys, "platform", "win32"),
            unittest.mock.patch.object(sys, "version_info", (3, 11)),
        )
        with unittest.mock.patch.dict(os.environ, self.env, clear=True):
            for patch in unsupported:
                with self.subTest(patch=patch.attribute), patch:
                    with unittest.mock.patch.object(sys, "stdin", io.StringIO(event)):
                        self.assertEqual(newline.main(), 0)
                    self.assertEqual(path.read_bytes(), b"last line")
            with unittest.mock.patch.object(sys, "stdin", io.StringIO(event)):
                self.assertEqual(newline.main(), 0)
            self.assertEqual(path.read_bytes(), b"last line\n", "the control: supported here")

    def test_supports_what_the_approval_hook_supports(self) -> None:
        newline, approval = load("ensure_final_newline"), load("sh_auto_approve")
        self.assertEqual(newline.MINIMUM_PYTHON, approval.MINIMUM_PYTHON)
        self.assertEqual(newline.SUPPORTED_PLATFORMS, approval.SUPPORTED_PLATFORMS)


if __name__ == "__main__":
    unittest.main()
