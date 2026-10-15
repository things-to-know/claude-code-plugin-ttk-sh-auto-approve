"""`tools/explain.py` prints the hook's verdict with its reason, for the session it is given."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPLAIN = ROOT / "tools" / "explain.py"


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


if __name__ == "__main__":
    unittest.main()
