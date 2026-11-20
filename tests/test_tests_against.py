"""`tools/tests_against.py` runs chosen tests against the working copy's hook and another."""

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "tests_against.py"
HOOK = ROOT / "plugin" / "scripts" / "sh_auto_approve.py"
SCRIPTS = HOOK.parent
# Fast tests that ask the hook for approvals and refusals both
SELECTED = "TheWideningsHaveAnEdge"
# The line a mutant's `_classify` starts after, to give no opinion on anything
CLASSIFY = "def _classify(command: str, depth: int = 0) -> None:\n"

spec = importlib.util.spec_from_file_location("tests_against", TOOL)
assert spec is not None and spec.loader is not None
tests_against = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tests_against)


def run_tool(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-B", str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def listing() -> list[str]:
    return sorted(path.name for path in SCRIPTS.iterdir())


class RunsTestsAgainstTwoHooks(unittest.TestCase):
    def setUp(self):
        stray = tests_against.untracked(SCRIPTS)
        if stray:
            self.skipTest(f"the tool refuses while plugin/scripts holds untracked files: {stray}")
        self.scratch = Path(tempfile.mkdtemp(prefix="tests_against_"))
        self.addCleanup(shutil.rmtree, self.scratch)
        self.before = listing()

    def test_a_mutant_fails_where_the_working_copy_passes(self):
        """The mutant sits outside `plugin/scripts/`, and the tool runs it from beside the hook,
        then removes it."""
        text = HOOK.read_text()
        self.assertEqual(text.count(CLASSIFY), 1, "the line the mutant changes")
        mutant = self.scratch / "mutant.py"
        mutant.write_text(text.replace(CLASSIFY, CLASSIFY + '    raise NoOpinion("mutant")\n'))
        ran = run_tool("--verbose", "--before", str(mutant), SELECTED)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        name, working, other = ran.stdout.rstrip("\n").split("\t")
        self.assertEqual((name, working), (SELECTED, "ok"))
        self.assertRegex(other, r"^failed \(failures=[1-9][0-9]*, errors=0\)$")
        self.assertIn(f"{SELECTED}\tother\tFAIL: ", ran.stderr)
        self.assertNotIn(f"{SELECTED}\tworking copy\t", ran.stderr)
        self.assertEqual(listing(), self.before, "no copy left beside the hook")

    def test_the_hook_at_the_base_passes_too(self):
        ran = run_tool("--base=HEAD", SELECTED)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertEqual(ran.stdout, f"{SELECTED}\tok\tok\n")
        self.assertEqual(listing(), self.before)

    def test_the_other_hook_runs_from_beside_the_working_copys(self):
        """A copy elsewhere fails these 2 by its location alone."""
        copy = self.scratch / "sh_auto_approve.py"
        shutil.copy(HOOK, copy)
        names = (
            "test_the_scratch_directory_is_the_payloads_scratchpad_dir",
            "test_the_keys_claude_code_sends_alongside_the_command",
        )
        ran = run_tool("--before", str(copy), *names)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertEqual(ran.stdout, "".join(f"{name}\tok\tok\n" for name in names))

    def test_a_name_that_selects_no_test(self):
        copy = self.scratch / "sh_auto_approve.py"
        shutil.copy(HOOK, copy)
        ran = run_tool("--before", str(copy), "no_test_has_this_name", SELECTED)
        self.assertEqual(ran.returncode, 1, ran.stderr)
        self.assertEqual(
            ran.stdout, f"no_test_has_this_name\tno test\tno test\n{SELECTED}\tok\tok\n"
        )

    def test_a_base_that_looks_like_an_option_is_a_revision(self):
        """Without `--end-of-options`, `git show` reads it as `--output` and writes the file."""
        target = self.scratch / "out:plugin" / "scripts"
        target.mkdir(parents=True)
        refused = run_tool(f"--base=--output={self.scratch / 'out'}", SELECTED)
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertEqual(list(target.iterdir()), [])
        self.assertIn("fatal: ", refused.stderr, "git's own reason")
        self.assertNotIn("Traceback", refused.stderr)
        self.assertEqual(listing(), self.before)


class RefusesAnUntrackedFileBesideTheHook(unittest.TestCase):
    def test_it_runs_nothing_while_one_is_there(self):
        """A local marketplace install would ship it, as it would a copy a killed run left."""
        stray = SCRIPTS / f"{tests_against.PREFIX}stray.py"
        self.assertFalse(stray.exists())
        stray.write_text("")
        self.addCleanup(stray.unlink, missing_ok=True)
        refused = run_tool("--base=HEAD", SELECTED)
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertIn(stray.name, refused.stderr)
        self.assertEqual(refused.stdout, "")
        self.assertEqual(sorted(SCRIPTS.glob(f"{tests_against.PREFIX}*")), [stray])


class ReadsAUnittestRun(unittest.TestCase):
    def test_each_ending(self):
        for stderr, returncode, expected in (
            ("...\nRan 3 tests in 0.1s\n\nOK\n", 0, "ok"),
            ("Ran 1 test in 0.1s\n\nOK (skipped=1)\n", 0, "ok"),
            ("Ran 3 tests in 0.1s\n\nFAILED (failures=2)\n", 1, "failed (failures=2, errors=0)"),
            ("Ran 3 tests\n\nFAILED (errors=1, skipped=2)\n", 1, "failed (failures=0, errors=1)"),
            ("Ran 0 tests in 0.0s\n\nNO TESTS RAN\n", 5, "no test"),
            ("Traceback (most recent call last):\nImportError: x\n", 1, "unknown: ImportError: x"),
            ("", 1, "unknown: exit 1"),
        ):
            with self.subTest(stderr=stderr):
                self.assertEqual(tests_against.result(stderr, returncode), expected)


if __name__ == "__main__":
    unittest.main()
