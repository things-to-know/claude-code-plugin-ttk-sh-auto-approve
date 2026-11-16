"""`tools/verdict_diff.py` lists the commands whose verdict differs between two hooks."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "verdict_diff.py"
HOOK = ROOT / "plugin" / "scripts" / "sh_auto_approve.py"
# The tests the tool runs here: committed, so that `--base` reads them at a revision too
CASES = ROOT / "tests" / "fixtures" / "verdict_diff_cases.py"

# A hook with no opinion on anything, with only the names `tools/verdict_diff.py` uses
SILENT_HOOK = """
class NotReadOnly(Exception):
    pass


class NoOpinion(NotReadOnly):
    pass


def _classify(command, depth=0):
    raise NoOpinion("silent")
"""

# A hook that approves everything, with the names `CASES` uses as well
APPROVING_HOOK = """
SETTINGS_ENV = "SH_AUTO_APPROVE_SETTINGS"
_SCRATCHPAD_DIR = None


class NotReadOnly(Exception):
    pass


class NoOpinion(NotReadOnly):
    pass


def _classify(command, depth=0):
    return None


def is_read_only(command):
    try:
        _classify(command)
    except NotReadOnly:
        return False
    return True
"""

# A hook with no opinion on anything, whose reason names the command's last word
NAMING_HOOK = """
class NotReadOnly(Exception):
    pass


class NoOpinion(NotReadOnly):
    pass


def _classify(command, depth=0):
    raise NoOpinion("reads " + command.split()[-1])


def is_read_only(command):
    try:
        _classify(command)
    except NotReadOnly:
        return False
    return True
"""

# Tests that ask about a path in 2 temporary directories, one past a directory's name, one in
# the checkout, and one that names no directory. `CHECKOUT` becomes the checkout's path
PATH_CASES = """
import importlib.util
import os
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("hook", os.environ["SH_AUTO_APPROVE_HOOK"])
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


class Cases(unittest.TestCase):
    def test_paths(self):
        with tempfile.TemporaryDirectory(prefix="readonly_hook_home_") as directory:
            hook.is_read_only(f"cat {directory}/x")
            hook.is_read_only(f"cat {directory}x")
        with tempfile.TemporaryDirectory() as directory:
            hook.is_read_only(f"cat {directory}/x")
        hook.is_read_only("cat CHECKOUT/x")
        hook.is_read_only("cat AGENTS.md")
"""

SCRATCH = "/tmp/claude-1000/-home-dir1-dir2/00000000-0000-4000-8000-000000000000/scratchpad"
FIRST = "sed -i 's/a/b/' AGENTS.md"
SECOND = "sed -n '1e touch PWNED' AGENTS.md"


def run_tool(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def run(before: Path, tests: Path) -> list[str]:
    result = run_tool("--before", str(before), "--tests", str(tests))
    result.check_returncode()
    return result.stdout.splitlines()


def listed(result: subprocess.CompletedProcess[str]) -> list[str]:
    """The commands a run lists, its count left out."""
    return [line.split("\t")[-1] for line in result.stdout.splitlines()[:-1]]


class ListsChangedVerdicts(unittest.TestCase):
    def setUp(self):
        self.scratch = Path(tempfile.mkdtemp(prefix="verdict_diff_"))
        self.addCleanup(shutil.rmtree, self.scratch)

    def test_an_identical_hook_changes_nothing(self):
        """Each command is asked of it in the test's context: `ls <scratchpad>` is no opinion
        without the scratchpad, and `touch PWNED` without the rule file."""
        copy = self.scratch / "sh_auto_approve.py"
        shutil.copy(HOOK, copy)
        self.assertEqual(run(copy, CASES), ["0 of 8 verdicts changed"])

    def test_each_changed_decision_is_listed_once(self):
        silent = self.scratch / "silent.py"
        silent.write_text(SILENT_HOOK)
        *changed, count = run(silent, CASES)
        self.assertEqual(count, "8 of 8 verdicts changed")
        self.assertEqual(
            [line.split("\t")[:2] + line.split("\t")[3:] for line in changed],
            [
                ["no-opinion", "allow", "wc -c AGENTS.md"],
                ["no-opinion", "allow", r"wc -l AGENTS.md\nwc -w AGENTS.md"],
                ["no-opinion", "allow", f"ls {SCRATCH}"],
                ["no-opinion", "allow", "touch PWNED"],
                ["no-opinion", "refused", FIRST],
                ["no-opinion", "refused", SECOND],
                ["no-opinion", "allow", "wc -l AGENTS.md"],
                ["no-opinion", "refused", "cat /dev/tcp/example.com/80"],
            ],
        )

    def test_it_writes_no_bytecode_next_to_the_earlier_hook(self):
        silent = self.scratch / "silent.py"
        silent.write_text(SILENT_HOOK)
        run(silent, CASES)
        self.assertEqual([path.name for path in self.scratch.iterdir()], ["silent.py"])

    def test_the_tests_at_the_base_get_its_verdicts(self):
        """`test_refused_in_a_row` asserts 2 refusals. Against a hook that approves both, it stops
        at the first, and says so on stderr. The same test at `--base` gets the earlier hook's
        refusals, passes, and asks both."""
        approving = self.scratch / "approving.py"
        approving.write_text(APPROVING_HOOK)
        copy = self.scratch / "sh_auto_approve.py"
        shutil.copy(HOOK, copy)
        alone = run_tool("--before", str(copy), "--after", str(approving), "--tests", str(CASES))
        self.assertEqual(alone.returncode, 0, alone.stderr)
        self.assertIn(FIRST, listed(alone))
        self.assertNotIn(SECOND, listed(alone), "the test stopped at the first")
        self.assertIn("Cases.test_refused_in_a_row", alone.stderr)
        based = run_tool("--base=HEAD", "--after", str(approving), "--tests", str(CASES))
        self.assertEqual(based.returncode, 0, based.stderr)
        self.assertIn(FIRST, listed(based))
        self.assertIn(SECOND, listed(based))
        self.assertEqual(
            based.stderr.count("Cases.test_refused_in_a_row"), 1, "it failed only at the later"
        )

    def test_a_base_that_looks_like_an_option_is_a_revision(self):
        """Without `--end-of-options`, `git show` reads it as `--output` and writes the file."""
        target = self.scratch / "out:plugin" / "scripts"
        target.mkdir(parents=True)
        refused = run_tool(f"--base=--output={self.scratch / 'out'}", "--tests", str(CASES))
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertEqual(list(target.iterdir()), [])
        self.assertIn("fatal: ", refused.stderr, "git's own reason")
        self.assertNotIn("Traceback", refused.stderr)
        control = run_tool("--base=HEAD", "--tests", str(CASES))
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertRegex(control.stdout, r"\b[0-9]+ of 8 verdicts changed\n\Z")


class PrintsNoPathOfTheRun(unittest.TestCase):
    """#85: a temporary directory the run made prints as `<tmp>`, and the checkout as
    `<project>`, so that 2 runs print the same lines, which a public pull request can carry."""

    def setUp(self):
        self.scratch = Path(tempfile.mkdtemp(prefix="verdict_diff_"))
        self.addCleanup(shutil.rmtree, self.scratch)
        (self.scratch / "approving.py").write_text(APPROVING_HOOK)
        (self.scratch / "naming.py").write_text(NAMING_HOOK)
        (self.scratch / "path_cases.py").write_text(PATH_CASES.replace("CHECKOUT", str(ROOT)))

    def run_paths(self) -> list[str]:
        result = run_tool(
            "--before",
            str(self.scratch / "approving.py"),
            "--after",
            str(self.scratch / "naming.py"),
            "--tests",
            str(self.scratch / "path_cases.py"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def test_each_path_prints_as_its_placeholder(self):
        """The 2 temporary directories read the same, so their commands are one line. A name
        that runs on past a directory's is another file, and keeps its path."""
        tmp, past, checkout, plain, count = self.run_paths()
        self.assertEqual(tmp, "allow\tno-opinion\treads <tmp>/x\tcat <tmp>/x")
        self.assertRegex(past, r"\Aallow\tno-opinion\treads /\S+x\tcat /\S+x\Z")
        self.assertNotIn("<tmp>", past)
        self.assertEqual(checkout, "allow\tno-opinion\treads <project>/x\tcat <project>/x")
        self.assertEqual(plain, "allow\tno-opinion\treads AGENTS.md\tcat AGENTS.md")
        self.assertEqual(count, "4 of 4 verdicts changed")

    def test_two_runs_print_the_same_lines(self):
        """But for the one past a directory's name, whose path is the run's own."""
        first, second = self.run_paths(), self.run_paths()
        self.assertNotEqual(first[1], second[1], "the control: each run names its own")
        self.assertEqual(first[:1] + first[2:], second[:1] + second[2:])


if __name__ == "__main__":
    unittest.main()
