#!/usr/bin/env python3
"""List the commands whose verdict differs between an earlier hook and the working copy's.

For development only: this file is outside ``plugin/``, so it never ships.

The commands are the ones the hook's tests ask it, as the tests build them. The tests run against
the later hook, and each command a test asks it goes to the earlier hook too, at that moment, so
under whatever the test set up: its rule file, scratchpad, project, working directory and git
config. The earlier hook takes from the later one the names the later's ``main`` sets for each
call, and shares the environment. A command is compared whole, as the test asks it, not the
parts the hook reads it in.

With ``--base``, the tests at that revision run too, read at the path ``--tests`` has in its
repository, so that a case the change deletes or rewrites is still asked. They get the earlier
hook's verdicts, the ones they were written for, so they pass as they did there, and ask every
command, even after one whose verdict the change moves. A test that fails or errors asks nothing
after its failure, and stderr names it.

Only the calls to ``_classify`` made in this process are compared. How ``main`` derives the
context it classifies in, such as ``_project_root``, is not, and neither is what the tests that
run the hook as a separate process send it.

Each command whose decision changed gets one tab-separated line for each change, the fields
escaped as ``tools/explain.py --transcript`` prints them:

    <decision before>  <decision after>  <reason after>  <command>

A last line counts the commands. For a refactor, the count must be 0; for any other hook change,
the lines are the change's effect, to list in its pull request.

The earlier hook is ``--base``, a git revision whose ``plugin/scripts/sh_auto_approve.py`` is
read, or ``--before``, a file.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
HOOK_PATH = "plugin/scripts/sh_auto_approve.py"
TESTS_PATH = "tests/test_sh_auto_approve.py"
# The variable the hook's tests load the hook from
HOOK_ENV = "SH_AUTO_APPROVE_HOOK"

# `-I` keeps this script's directory off `sys.path`
sys.path.insert(0, str(TOOLS))
import explain  # noqa: E402


def session_globals(hook: ModuleType) -> set[str]:
    """The names the hook's ``main`` sets for each call, such as the shell's working directory.

    Read from ``main`` itself, so that a name added there is shared too.
    """
    tree = ast.parse(Path(hook.__file__).read_text())
    return {
        name
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
        for inner in ast.walk(node)
        if isinstance(inner, ast.Global)
        for name in inner.names
    }


class Asked:
    """Each command the tests ask, and each change of decision on one."""

    def __init__(self, earlier: ModuleType) -> None:
        """Ask ``earlier`` too, each command the hooks this watches are asked."""
        self.earlier = earlier
        self.commands: dict[str, None] = {}
        # (decision before, decision after, command): the reason after
        self.changes: dict[tuple[str, str, str], str] = {}

    def watch(self, later: ModuleType, *, answer_before: bool) -> None:
        """Ask the earlier hook each command ``later`` is asked whole, in the same context.

        With ``answer_before``, the caller gets the earlier hook's verdict, not the later's.
        """
        classify = later._classify
        shared = session_globals(later) | session_globals(self.earlier)

        def asking_both(command: str, depth: int = 0) -> None:
            if depth:  # a part of a command the hook is already reading
                classify(command, depth)
                return
            for name in shared & set(vars(later)):
                setattr(self.earlier, name, getattr(later, name))
            before = explain.verdict(self.earlier, command)
            try:
                classify(command)
            except Exception as error:
                self.record(command, before, explain.refusal(later, error))
                if not answer_before:
                    raise
            else:
                self.record(command, before, explain.ALLOWED)
            if answer_before:
                answer(later, before)

        later._classify = asking_both

    def record(self, command: str, before: tuple[str, str], after: tuple[str, str]) -> None:
        """Count ``command``, and keep its change of decision, if any."""
        self.commands.setdefault(command)
        if before[0] != after[0]:
            self.changes.setdefault((before[0], after[0], command), after[1])


def answer(hook: ModuleType, verdict: tuple[str, str]) -> None:
    """Return, or raise what ``hook`` raises for ``verdict``, with its reason."""
    decision, reason = verdict
    if decision == "no-opinion":
        raise hook.NoOpinion(reason)
    if decision != explain.ALLOWED[0]:
        raise hook.NotReadOnly(reason)


def run_tests(path: Path, name: str, asked: Asked, *, answer_before: bool) -> list[str]:
    """Run the tests at ``path``, as the module ``name``, with ``asked`` watching their hook.

    Returns the tests that failed or errored, each of which asked nothing after its failure.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        sys.exit(f"cannot load the tests from {path}")
    module = importlib.util.module_from_spec(spec)
    # `unittest` finds a test's module fixtures through `sys.modules`
    sys.modules[name] = module
    spec.loader.exec_module(module)
    asked.watch(module.hook, answer_before=answer_before)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    # stdout is the list's
    with contextlib.redirect_stdout(io.StringIO()):
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    failed = (test.id().removeprefix(f"{name}.") for test, _ in (*result.failures, *result.errors))
    return list(dict.fromkeys(failed))


def in_repository(path: Path) -> str:
    """``path`` relative to the git repository that holds it, as ``git show`` reads it."""
    resolved = path.resolve()
    for directory in resolved.parents:
        if (directory / ".git").exists():
            return resolved.relative_to(directory).as_posix()
    sys.exit(f"{path} is in no git repository, so it has no path to read at --base")


def show(revision: str, path: str, target: Path) -> Path:
    """Write ``path`` at ``revision`` to ``target``."""
    # `--end-of-options`: git reads `--base=--output=<file>` as a revision, and refuses it,
    # instead of writing that file. git comes from `PATH`, as for the Makefile, and its error
    # goes to stderr
    shown = subprocess.run(  # noqa: S603 - the revision follows `--end-of-options`
        ["git", "show", "--end-of-options", f"{revision}:{path}"],  # noqa: S607
        cwd=ROOT,
        stdout=subprocess.PIPE,
        check=False,
    )
    if shown.returncode != 0:
        sys.exit(f"cannot read {path} at {revision!r}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(shown.stdout)
    return target


def main(argv: list[str] | None = None) -> int:
    """Print each command whose decision differs, then how many there are."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    before = parser.add_mutually_exclusive_group(required=True)
    before.add_argument("--base", help="the git revision of the earlier hook, e.g. origin/main")
    before.add_argument("--before", type=Path, help="the earlier hook, as a file")
    parser.add_argument("--after", type=Path, default=explain.WORKING_COPY, help="the later hook")
    parser.add_argument(
        "--tests", type=Path, default=ROOT / TESTS_PATH, help="the tests that ask the hooks"
    )
    args = parser.parse_args(argv)

    # The tests load the later hook from there
    os.environ[HOOK_ENV] = str(args.after.resolve())
    with tempfile.TemporaryDirectory() as scratch:
        # (the tests, what they are called on stderr, whether they get the earlier verdicts)
        suites = [(args.tests, str(args.tests), False)]
        if args.base is not None:
            earlier = show(args.base, HOOK_PATH, Path(scratch, "sh_auto_approve.py"))
            tests = in_repository(args.tests)
            at_base = show(args.base, tests, Path(scratch, tests))
            suites.append((at_base, f"{tests} at {args.base}", True))
        else:
            earlier = args.before
        asked = Asked(explain.load_hook(earlier))
        for number, (path, called, answer_before) in enumerate(suites):
            failed = run_tests(
                path, f"verdict_diff_tests_{number}", asked, answer_before=answer_before
            )
            if failed:
                print(
                    f"{len(failed)} of the tests in {called} failed or errored:",
                    *failed,
                    sep="\n  ",
                    file=sys.stderr,
                )

    for (old_decision, new_decision, command), new_reason in asked.changes.items():
        print(old_decision, new_decision, *map(explain.escaped, (new_reason, command)), sep="\t")
    changed = len({command for _, _, command in asked.changes})
    print(f"{changed} of {len(asked.commands)} verdicts changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
