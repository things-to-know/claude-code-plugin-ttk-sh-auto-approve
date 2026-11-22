#!/usr/bin/env python3
"""Run chosen tests against the working copy's hook and against another, and print each result.

For development only: this file is outside ``plugin/``, so it never ships.

Each name goes to ``unittest``'s ``-k``, as ``make test TEST_ARGS='-k <name>'`` passes it, and the
tests it selects run twice: against the working copy's hook, then against the other one, which
the tests load from ``SH_AUTO_APPROVE_HOOK``. So a review finding's test can be shown to fail on
the hook the review read, and a mutant shown to fail a test.

The other hook is ``--base``, a git revision whose ``plugin/scripts/sh_auto_approve.py`` is
read, or ``--before``, a file. It runs from beside the working copy's, in ``plugin/scripts/``: a
copy anywhere else fails ``HookProtocol.test_the_scratch_directory_is_the_payloads_scratchpad_dir``
and ``HookProcessRobustness.test_the_keys_claude_code_sends_alongside_the_command`` by its location
alone. It is written there under a name no file has, and removed once the tests have run.

- A local marketplace install copies ``plugin/`` as it is, untracked files included, so this
  refuses to run while ``plugin/scripts/`` holds an untracked file, such as a copy a killed run
  left behind
- ``GIT_DIR`` and ``GIT_WORK_TREE`` are unset for the tests, as a session's shell has them: an
  exec step of ``git rebase -x`` sets ``GIT_DIR``, and the hook then refuses what the tests expect

One tab-separated line per name:

    <name>  <result against the working copy's hook>  <result against the other>

A result is ``ok``, ``failed (failures=<n>, errors=<n>)``, or ``no test``, when the name selects
none. With ``--verbose``, each run's failing tests and their assertion messages go to stderr.

Exit status: 1 when a name selects no test, else 0.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
SCRIPTS = ROOT / "plugin" / "scripts"
# The variable the hook's tests load the hook from
HOOK_ENV = "SH_AUTO_APPROVE_HOOK"
# The other hook's name in `SCRIPTS`, before `tempfile`'s random part
PREFIX = "_tests_against_"

# `-I` keeps this script's directory off `sys.path`
sys.path.insert(0, str(TOOLS))
import verdict_diff  # noqa: E402


def untracked(directory: Path) -> list[str]:
    """The files git doesn't track in ``directory``, ignored ones left out."""
    listed = subprocess.run(  # noqa: S603 - fixed arguments, the directory after `--`
        ["git", "status", "--porcelain", "--untracked-files=all", "--", directory],  # noqa: S607
        cwd=ROOT,
        env=tests_environment(None),
        capture_output=True,
        text=True,
        check=False,
    )
    if listed.returncode != 0:
        sys.exit(f"cannot list the untracked files in {directory}: {listed.stderr.strip()}")
    return [line[3:] for line in listed.stdout.splitlines() if line.startswith("?? ")]


def tests_environment(hook: Path | None) -> dict[str, str]:
    """The environment the tests run in, ``hook`` the one they load, if not the working copy's."""
    environment = {
        name: value
        for name, value in os.environ.items()
        if name not in {"GIT_DIR", "GIT_WORK_TREE", HOOK_ENV}
    }
    if hook is not None:
        environment[HOOK_ENV] = str(hook)
    return environment


def result(stderr: str, returncode: int) -> str:
    """What a ``unittest`` run's stderr says of it, in one word or a few."""
    ran = re.search(r"^Ran ([0-9]+) tests?\b", stderr, re.MULTILINE)
    if ran is not None and ran.group(1) == "0":
        return "no test"
    failed = re.search(r"^FAILED \((.*)\)$", stderr, re.MULTILINE)
    if failed is not None:
        counts = dict(re.findall(r"(failures|errors)=([0-9]+)", failed.group(1)))
        return f"failed (failures={counts.get('failures', 0)}, errors={counts.get('errors', 0)})"
    if returncode == 0 and ran is not None:
        return "ok"
    last = stderr.strip().splitlines()[-1:] or [f"exit {returncode}"]
    return f"unknown: {last[0]}"


def failures(stderr: str) -> list[str]:
    """Each failing test of a run, and each assertion message, as ``unittest`` names them."""
    return re.findall(r"^(?:FAIL|ERROR): .*$|^\w*(?:Error|Exception): .*$", stderr, re.MULTILINE)


def run(name: str, hook: Path | None) -> tuple[str, list[str]]:
    """Run the tests ``name`` selects against ``hook``, or the working copy's; their result."""
    # `-B`, as `make test` runs them: no bytecode next to the hooks in `plugin/`
    ran = subprocess.run(  # noqa: S603 - the interpreter and fixed arguments, `name` to `-k`
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-k", name],
        cwd=ROOT,
        env=tests_environment(hook),
        capture_output=True,
        text=True,
        check=False,
    )
    return result(ran.stderr, ran.returncode), failures(ran.stderr)


def main(argv: list[str] | None = None) -> int:
    """Print each name's result against both hooks."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    other = parser.add_mutually_exclusive_group(required=True)
    other.add_argument("--base", help="the git revision of the other hook, e.g. origin/main")
    other.add_argument("--before", type=Path, help="the other hook, as a file")
    parser.add_argument("--verbose", "-v", action="store_true", help="name each failing test")
    parser.add_argument("names", nargs="+", help="a test's name, or part of it, as for -k")
    args = parser.parse_args(argv)

    stray = untracked(SCRIPTS)
    if stray:
        sys.exit(f"{SCRIPTS} holds untracked files, which a local install would ship: {stray}")
    with tempfile.TemporaryDirectory() as scratch:
        if args.base is not None:
            source = verdict_diff.show(
                args.base, verdict_diff.HOOK_PATH, Path(scratch, "sh_auto_approve.py")
            )
        else:
            source = args.before
        text = source.read_bytes()
    with tempfile.NamedTemporaryFile(
        dir=SCRIPTS, prefix=PREFIX, suffix=".py", delete=False
    ) as stream:
        stream.write(text)
        other_hook = Path(stream.name)
    selected_none = False
    try:
        for name in args.names:
            working, working_failed = run(name, None)
            others, others_failed = run(name, other_hook)
            print(name, working, others, sep="\t", flush=True)
            selected_none |= "no test" in (working, others)
            if args.verbose:
                for hook, lines in (("working copy", working_failed), ("other", others_failed)):
                    for line in lines:
                        print(f"{name}\t{hook}\t{line}", file=sys.stderr)
    finally:
        other_hook.unlink(missing_ok=True)
    return 1 if selected_none else 0


if __name__ == "__main__":
    sys.exit(main())
