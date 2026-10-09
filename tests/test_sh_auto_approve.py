#!/usr/bin/env python3
"""
Tests for the read-only Bash classifier behind the `PreToolUse` hook.

Run from the repository root, with no third-party dependency:

    python3 -m unittest discover --start-directory tests

What these cases are for: the hook grants permission, so a mistake here is not a failing
check but a command that runs without being asked about. The rejection cases matter more
than the approval ones, and every approval case is a command Claude Code would already
run unprompted if it were written out flat instead of built in a loop.

Environment variables
---------------------

    SH_AUTO_APPROVE_HOOK        the hook under test, when it is not at
                                `plugin/scripts/sh_auto_approve.py`
    SH_AUTO_APPROVE_STRICT      `0` turns open findings into expected failures
    SH_AUTO_APPROVE_FUZZ        how many mutants `DifferentialFuzz` generates (300)
    SH_AUTO_APPROVE_FUZZ_SEED   the seed it generates them from (20260914)

Red by default
--------------

To have clean runs meaning "the known findings are still the known findings",
set `SH_AUTO_APPROVE_STRICT=0`, so `@open_finding` applies `unittest.expectedFailure`.

`python3 tests/test_sh_auto_approve.py --findings`
prints the register without running anything.

How this file is laid out
-------------------------

The harness and the shared corpora come first. After them, test classes are grouped by
the part of the shell or of a program's surface they exercise, so everything about `sed`
is in one place whether it came from the original suite, from an adversarial pass, or
from a command that prompted in a real session.

     1  Harness
     2  Shared corpora
     3  The suite checking itself
          SuiteIntegrity, CorpusIsSafeToExecute
     4  Baseline verdicts
          ApprovesReadOnly, RefusesAnythingElse, RefusalIsMonotonicUnderComposition,
          MatchesTheHostsOwnCaution
     5  Commands observed prompting in real sessions
          ObservedCommandsStayApproved, AllowsALoopVariableBoundToLiterals,
          SplicesFlagsFromALiteralAssignment, AllowsACopyIntoTheScratchDirectory,
          AllowsAQuotedDateWhoseOutputIsUnsigned, TheWideningsHaveAnEdge
     6  Lexing, quoting, and where a command ends
          RefusesShellSyntaxTheLexerMisreads, RefusesPunctuationThatBashWouldReject,
          ResolvesQuotingBeforeLexing, RefusesQuotingBashReadsDifferently,
          RefusesMultilineQuotedText, RefusesBraceExpansion
     7  Expansion and substitution
          ApprovesCommandSubstitutionThatOnlyReads, RefusesCommandSubstitutionThatDoesNot,
          RefusesDeferredCommandSubstitution, RefusesReEvaluatingAValue,
          RefusesWordsAnExpansionSupplies
     8  Redirection, sockets, and egress
          RefusesDescriptorAndSocketRedirection, RefusesRedirectionAttachedToACompound,
          RefusesReadsOutsideTheWorkingDirectories, RefusesEgressThroughAnApprovedProgram
     9  Program identity, environment, and session state
          RefusesControlOfTheEnvironmentAndTheProgram, StripsTheWrapperTheHostStrips,
          RefusesBuiltinsThatRunAProgram, RefusesSessionScopedEnvironmentHandover,
          RefusesSessionScopedProgramDefinitions
    10  `cd`
          ApprovesCdInsideTheRepository, RefusesCdTargetsThatOnlyLookInside
    11  Allowlisted programs: flags and operands
          RefusesAllowlistedProgramsThatWrite, RefusesWritingFlagsBundledIntoAShortOption,
          RefusesOutputOperandsPastAnOptionTerminator, RefusesFindWritingPredicates,
          RefusesOutputThatIsNotInert
    12  sed and awk
          RefusesStreamEditorWrites, RefusesStreamEditorAddressForms,
          RefusesAwkFormsThatRunOrRead
    13  Vendor CLIs: git, aws, gcloud
          RefusesVendorFlagsAndSubcommands, ApprovesOrdinaryOptionForms,
          RefusesGitConfigDrivenExecution, RefusesGitSubcommandsOutsideTheReadSet,
          RefusesAwsCallsThatWriteOrExecute, RefusesAwsCallsThatPrintASecret,
          ApprovesGcloudHelpForABlockedVerb, RefusesGcloudCallsThatWriteLocallyOrExecute,
          RefusesGhApiCallsThatWriteOrLeak
    14  The operator's own rules: the second tier
          OperatorRules, OperatorRuleFileRobustness, ARepresentativeRuleFile
    15  The classifier as a function
          TheClassifierIsAPureFunction, SurvivesPathologicalInput, CostsBoundedTime
    16  Differential: ask bash instead of modeling it
          DifferentialAgainstBash, DifferentialWithAPlantedProgram,
          DifferentialAcrossOneSession, DifferentialOverTheSuitesOwnApprovals,
          DifferentialAgainstZsh, DifferentialFuzz
    17  The hook as a process
          HookProtocol, HookProcessRobustness
    18  Policy decisions, recorded as tests
          PolicyAlreadyDecidedToRefuse, PolicyStillUndecided,
          ObservedCommandsNotMadeToPass

`SuiteIntegrity` fails if this list and the file's classes disagree. The one unconditionally
skipped class is in part 18.

Five properties this file holds to
----------------------------------

1. **A case must fail for its own reason.** Where a command could be refused for more
   than one reason it is written to isolate the mechanism under test, because a case that
   passes for the wrong reason is worse than no case at all. `sed 's/a/b/w out.txt' a.md`
   is refused as a file operand, not as a write, and would keep passing with the `w`
   detector deleted; the pipeline spelling is the one that tests the detector.

2. **A case must be executable before it counts as a bypass.** An earlier version of this
   file asserted refusal for strings like `ls;(rm -rf build/` without a closing paren,
   which bash rejects outright. Those are parser hygiene, not security, and they live in
   `RefusesPunctuationThatBashWouldReject` with a guard that tells you if a future bash
   starts accepting them. Everything in `DifferentialAgainstBash` is confirmed to execute.

3. **Every test defined here must actually run.** `SuiteIntegrity` checks that, because
   the previous version defined two classes with the same name and silently dropped four
   tests -- including the only coverage of a two-operand `uniq`, which the hook approves.

4. **Ask bash rather than modeling it.** `DifferentialAgainstBash` and its siblings
   execute what the classifier approved and look for an effect. Every command in every
   corpus stays confined to relative paths inside a scratch directory whose `HOME` and
   `TMPDIR` are redirected into it, and the payloads are limited to `touch PWNED`, a
   write to `PWNED`, an edit or deletion of the scratch tree's own `AGENTS.md`, and a
   planted executable inside the same tree. `CorpusIsSafeToExecute` enforces the
   confinement mechanically -- read it before adding a case, and do not add one it
   rejects.

5. **Assert the property, not the verdict, where approval is not the point.** In the
   classes marked `@approvals_budgeted`, a case whose approval is not itself a risk does
   not get an `assert_allowed`. Guessing that the classifier approves a command buys a
   false failure; asserting that *whatever it approves leaves the tree alone* buys a real
   guarantee that survives a rewrite. `assert_refused` is used there only where approval
   is a concrete write, execution, or escape, and `SuiteIntegrity` caps the approvals
   those classes may assert, each of which guards an idiom asserted elsewhere.

The counterweight is part 5, which has no such budget because nothing in it is a guess:
each command there was copied out of a Claude Code permission prompt in a real session,
and each approval is paired with the refusal that shows where the widening stops.

Findings
--------

An open finding is a test decorated `@open_finding` with a reference from one family:

    A-  an allowlisted program that can write or execute
    B-  a flag the flag table does not match
    C-  a redirection the segmenter does not see
    D-  another finding, reproduced through the hook process
    E-  a word the shell supplies after the check has run
    G-  git surface
    H-  approving more than the host does
    P-  the lexer
    Q-  quoting resolved differently from bash
    S-  state that outlives the command that set it
    V-  gcloud surface
    W-  aws surface

The security assessment this suite was built from has one class per numbered
finding, whether or not the finding held. The ones that did not hold are kept rather than
deleted: an audit claim that was already covered is exactly the case a later refactor is
most likely to quietly uncover, and a test is how you notice. Each docstring says which
way it came out.

    1  RefusesMultilineQuotedText                    part  6
    2  RefusesSessionScopedEnvironmentHandover       part  9
    3  RefusesBuiltinsThatRunAProgram                part  9
    4  RefusesStreamEditorAddressForms               part 12
    5  RefusesFindWritingPredicates                  part 11
    6  RefusesGitConfigDrivenExecution               part 13
    7  RefusesDescriptorAndSocketRedirection         part  8
    8  RefusesOutputOperandsPastAnOptionTerminator   part 11

Host behavior this file asserts against, verified 2026-09-13
------------------------------------------------------------

* Deny and ask rules are evaluated regardless of what a PreToolUse hook returns, so an
  `allow` from this hook cannot override them. This was not true before Claude Code
  v2.1.77; the module docstring's safety argument needs that floor.
  https://code.claude.com/docs/en/permissions#extend-permissions-with-hooks
* A Bash rule matches the command text Claude writes and does not match the same program
  invoked in a different form, so a `deny` rule is not a boundary around a program. The
  forms this hook fails to recognize are largely the forms a deny rule also misses, so
  the two layers fail together rather than independently.
  https://code.claude.com/docs/en/permissions#bash-rule-limits
* The host's built-in read-only set is `ls cat echo pwd head tail grep find wc which diff
  stat du cd` plus read-only forms of `git`, and commands longer than 10,000 characters
  always prompt because they exceed what the analysis parses.
  https://code.claude.com/docs/en/permissions#read-only-commands
* A command hook that reaches its timeout is canceled and its output discarded, so it
  renders no decision and the call falls through to the normal permission flow. The
  default for a PreToolUse command hook is 600 seconds. That is why the quadratic scan in
  `_check_sed` is a latency finding rather than a bypass -- and why its budget is ten
  minutes per Bash call, not one. https://code.claude.com/docs/en/hooks

Claims verified by execution, 2026-09-14, bash 5.2.21 / GNU sed 4.9 / GNU findutils 4.9
---------------------------------------------------------------------------------------

Each of these was run before it was written down, and
`CorpusIsSafeToExecute.test_every_attack_really_mutates_the_tree` re-runs the executable
ones on every invocation so none can rot into a case that passes for free:

    echo 'a\\'; touch PWNED                     touch runs: `\\` is literal inside '...'
    echo a\\\\; touch PWNED                       touch runs: `\\\\` is an escaped backslash
    { ls; } > PWNED / (ls) > PWNED              both write
    for f in a; do echo $f; done > PWNED        writes
    ls > >(cat > PWNED) / coproc touch PWNED    both write
    sed -ni 's/one/1/p' AGENTS.md               edits in place
    sort -uo PWNED AGENTS.md                    writes PWNED
    sed "$(echo -i)" 's/one/1/' AGENTS.md       edits in place
    sort "$(echo -o)" PWNED AGENTS.md           writes PWNED
    find . -name AGENTS.md "$(echo -delete)"    deletes
    awk 'BEGIN{"touch PWNED" | getline x}'      runs touch
    cd $'\\x2ftmp'                               lands in /tmp
    f() { touch PWNED; } then f                 runs across two commands in one shell
    trap 'touch PWNED' DEBUG then wc -l         fires on the next command
    printf -v v hello                           assigns without an `=` anywhere
    echo "${p:=hello}"                          assigns as a side effect of expanding

Claims taken from vendor documentation rather than executed, because running them would
reach a real account or a real remote, are marked *documented* in their docstrings. They
are the aws, gcloud and network cases.

Every assertion in the classes marked `@approvals_budgeted` was checked, when written,
against two stand-in classifiers, one approving everything and one approving nothing, to
confirm it fails in the direction it is supposed to. A case that cannot fail is
decoration.
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import platform
import random
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

# ======================================================================================
# Part 1 -- Harness
#
# Nothing in this part is a test. It loads the hook, keeps the findings register, probes
# the machine for the tools some cases need, and provides the sandbox that the
# differential classes execute commands in.
# ======================================================================================

# --------------------------------------------------------------------------------------
# Loading the hook, with the operator's rule file switched off
# --------------------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = Path(
    os.environ.get(
        "SH_AUTO_APPROVE_HOOK",
        REPO_ROOT / "plugin" / "scripts" / "sh_auto_approve.py",
    )
)

spec = importlib.util.spec_from_file_location("sh_auto_approve", MODULE_PATH)
assert spec is not None and spec.loader is not None, f"no hook at {MODULE_PATH}"
hook = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = hook
spec.loader.exec_module(hook)

# The classifier is one tier and the operator's own rule file is the other, and almost
# every case in this file is about the first. Pointing the hook at no rule file at all
# keeps each assertion testing the thing it names, rather than passing or failing on
# whatever `.claude/settings.local.json` happens to grant this week -- `Bash(touch *)` is
# a common grant, and it is the payload half the corpus below is built from. `OperatorRules`
# turns the tier back on against a rule file it writes itself, and
# `ARepresentativeRuleFile` is the class that reads one shaped like a real file.
#
# It reaches the subprocess cases through the environment too, which is deliberate: the
# hook is exec'd with this environment, so `HookProtocol` sees the same single tier.
os.environ[hook.SETTINGS_ENV] = ""

# --------------------------------------------------------------------------------------
# The open-findings register
# --------------------------------------------------------------------------------------

# TODO(cleanup): with SH_AUTO_APPROVE_STRICT=0, 36 tests marked `@open_finding` now
# pass -- the bug each records was fixed and the decorator was left on. Each is a one-line
# removal once the fix is confirmed intended. Refs at the time of the merge:
#   A-10, B-01, B-02, C-01, C-02, C-03, D-04, E-01, E-02, E-03, E-04, E-05, G-01, G-02,
#   G-03, G-04, H-01, P-02, P-03, P-05, P-06, Q-01, Q-02, Q-03, S-01, S-02, S-03, S-04,
#   S-05, V-01, V-02, V-03, W-01, W-02, W-03, W-04
STRICT = os.environ.get("SH_AUTO_APPROVE_STRICT", "1") != "0"
FINDINGS: list[tuple[str, str, str]] = []


def open_finding(ref: str, note: str):
    """Mark a test as a known-unfixed finding.

    Marks the test as `expectedFailure` if ``STRICT`` is false; otherwise it is a no-op.
    """

    def decorate(func):
        FINDINGS.append((ref, func.__qualname__, note))
        func.__doc__ = f"{(func.__doc__ or '').rstrip()}\n\n    Open finding {ref}: {note}\n"
        return func if STRICT else unittest.expectedFailure(func)

    return decorate


# Classes that assert properties rather than verdicts: property 5 in the module docstring.
# `SuiteIntegrity.test_the_approval_assertions_stay_rare_and_guarded` caps the literal
# `assert_allowed` calls inside them.
APPROVAL_BUDGETED: set[str] = set()


def approvals_budgeted(cls):
    """Mark a test class as refusal-focused, so its approvals count against the budget."""
    APPROVAL_BUDGETED.add(cls.__name__)
    return cls


# --------------------------------------------------------------------------------------
# Environment probes
#
# Several attack strings are GNU-specific. Guarding them keeps a macOS run honest rather
# than vacuously green: a skipped case says "not tested here", an unguarded one that
# cannot reproduce says "tested and fine", which is false.
# --------------------------------------------------------------------------------------

BASH = shutil.which("bash")
IS_MACOS = platform.system() == "Darwin"


def _bash_versinfo() -> tuple[int, int]:
    if not BASH:
        return (0, 0)
    out = subprocess.run(
        [BASH, "-c", "echo ${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split()
    try:
        return (int(out[0]), int(out[1]))
    except (IndexError, ValueError):
        return (0, 0)


BASH_VERSINFO = _bash_versinfo()


def _is_gnu(program: str) -> bool:
    path = shutil.which(program)
    if not path:
        return False
    try:
        out = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return "GNU" in out.stdout


HAS_GNU_FIND = _is_gnu("find")
HAS_GNU_DATE = _is_gnu("date")
HAS_GNU_SED = _is_gnu("sed")
HAS_GAWK = shutil.which("gawk") is not None

needs_bash = unittest.skipUnless(BASH, "needs bash on PATH")

# Claude Code runs a command in the operator's login shell. Under zsh it sets these options
# first (seen in the wrapper's own command line), and they change what a glob can do, so the
# zsh differential sets them too. The rc files the wrapper also sources are left out: `-f`
# keeps the run hermetic, at the price of not seeing an alias or option the operator added.
# TODO: replace "seen in the wrapper's own command line" with an official source, the Claude
# Code documentation or the code that builds the wrapper; see the hook's module docstring.
ZSH = shutil.which("zsh")
CLAUDE_CODE_ZSH_OPTIONS = "setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL"
needs_zsh = unittest.skipUnless(ZSH, "needs zsh on PATH")
needs_bash_44 = unittest.skipUnless(
    BASH and BASH_VERSINFO >= (4, 4),
    f"needs bash >= 4.4 for ${{var@P}}; found {BASH_VERSINFO}",
)

# --------------------------------------------------------------------------------------
# What the host approves, and what this repository approves beyond it
# --------------------------------------------------------------------------------------

# Claude Code prompts for any command longer than this rather than classifying it, so a
# hook that approves past it is deciding to be more permissive than the host.
HOST_COMMAND_LENGTH_CAP = 10_000

# The host's built-in read-only set, from the docs URL in the module docstring. `git` is
# handled by its own validator and `cd` is not in the hook's allowlist at all.
HOST_READ_ONLY = frozenset(
    {
        "ls",
        "cat",
        "echo",
        "pwd",
        "head",
        "tail",
        "grep",
        "find",
        "wc",
        "which",
        "diff",
        "stat",
        "du",
        "cd",
    }
)

# Programs this repository has decided to approve beyond the host's set. Adding a name
# here is how you record the decision to be more permissive than Claude Code, and
# `test_the_allowlist_matches_the_host` prints what is missing.
#
# The decision, 2026-09-13: the hook's rule is "nothing in it can write a file, change a
# resource, or run a program the module did not read", which is broader than the host's
# set on purpose, because a pipeline is only useful if its filters are reachable inside
# it. Every name below is a filter or a reporter with no write flag and no way to spawn a
# process. Programs that can write under a flag are not here: they carry a validator.
#
# The groups are separate so one can be dropped without reasoning about the others. The
# third is the weakest: `id`, `uname` and `whoami` are reconnaissance rather than work,
# and are read-only only under "stop accidental mutation", not under "stop an agent
# acting on untrusted input" -- the same choice `UndecidedPolicy` is parked on.
SITE_APPROVED_BEYOND_HOST: frozenset[str] = frozenset(
    # Text filters a pipeline is built from
    {
        "basename",
        "cmp",
        "column",
        "comm",
        "cut",
        "dirname",
        "egrep",
        "fgrep",
        "join",
        "nl",
        "od",
        "paste",
        "printf",
        "readlink",
        "realpath",
        "rev",
        "tac",
        "tr",
    }
    # `jq` is commonly used to process JSON files. It carries a validator rather than sitting
    # here bare, because `-f` takes its program from a file and `$ENV` prints the session's
    # credentials; nothing in its grammar writes a file or runs a program.
    | {"jq"}
    # `gh`, for `gh api` GETs only; its validator gives every other subcommand back to the
    # operator's rules, and refuses any method, body, host or header that is not a read.
    | {"gh"}
    # Exit-status primitives, which run inside `if` and `while` tests
    | {"false", "test", "true"}
    # Checksums, which logbooks record when verifying a download
    | {"md5sum", "sha1sum", "sha256sum", "shasum"}
    # Machine facts
    | {"id", "uname", "whoami"}
)


# --------------------------------------------------------------------------------------
# Rule files and the scratch directory
# --------------------------------------------------------------------------------------


@contextlib.contextmanager
def settings_at(path):
    """Point the second tier at `path`, whether or not anything readable is there."""
    previous = os.environ[hook.SETTINGS_ENV]
    os.environ[hook.SETTINGS_ENV] = str(path)
    try:
        yield
    finally:
        os.environ[hook.SETTINGS_ENV] = previous


@contextlib.contextmanager
def operator_rules(allow=(), deny=()):
    """Run the second tier against a rule file written for one test."""
    document = {"permissions": {"allow": list(allow), "deny": list(deny)}}
    with tempfile.TemporaryDirectory(prefix="readonly_hook_rules_") as directory:
        path = Path(directory) / "settings.local.json"
        path.write_text(json.dumps(document))
        with settings_at(path):
            yield path


# An operator's rule file in the shape the real ones take: allow rules for the project's own
# scripts and one write-capable grant, deny rules for the commands that stage or tee.
REPRESENTATIVE_RULES = {
    "allow": [
        "Bash(scripts/check-docs.py *)",
        "Bash(scripts/check-format.sh *)",
        "Bash(scripts/lint-docs.sh *)",
        "Bash(touch *)",
    ],
    "deny": ["Bash(tee *)", "Bash(git add *)"],
}


def representative_rules():
    """Run the second tier against `REPRESENTATIVE_RULES`, written to a scratch file.

    The settings path is set to "" at import so that the classifier is tested alone. The
    cases that are about the second tier put a rule file back for their own duration, and
    it is one this suite writes, so no result depends on what a checkout has saved under
    `.claude/`.
    """
    return operator_rules(**REPRESENTATIVE_RULES)


@contextlib.contextmanager
def scratch_at(directory: str | None):
    """Point the scratch rule at an exact directory, or back at the default shape."""
    previous = os.environ.get(hook.SCRATCH_ENV)
    if directory is None:
        os.environ.pop(hook.SCRATCH_ENV, None)
    else:
        os.environ[hook.SCRATCH_ENV] = directory
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(hook.SCRATCH_ENV, None)
        else:
            os.environ[hook.SCRATCH_ENV] = previous


# --------------------------------------------------------------------------------------
# Execution sandbox
# --------------------------------------------------------------------------------------

PAYLOAD_MARKER = "PWNED"

# Anything here in a corpus entry is a bug in the corpus, not a finding. The harness
# executes what it is given, so the payload vocabulary stays small and inert.
FORBIDDEN_IN_CORPUS = (
    "rm ",
    "rmdir",
    "sudo",
    "curl",
    "wget",
    "chmod",
    "chown",
    "mv ",
    "cp ",
    "date -s",
    "hostname ",
    "shutdown",
    "reboot",
    "kill",
    "mkfs",
    ":(){",
    "..",
    "~",
    "$HOME",
)

# A path token that starts at the filesystem root, `/dev/null` excepted.
ABSOLUTE_PATH = re.compile(r"(?<!\S)/(?!dev/null\b)")


def is_corpus_safe(command: str) -> str | None:
    """The leash, as a predicate, so the fuzzer can apply it per candidate.

    Returns the reason a command must not be executed, or None.
    """
    if ABSOLUTE_PATH.search(command):
        return "reaches outside the scratch tree"
    for forbidden in FORBIDDEN_IN_CORPUS:
        if forbidden in command:
            return f"contains {forbidden!r}"
    return None


@contextlib.contextmanager
def scratch_tree():
    """A disposable working tree with one file in it, and a sealed-off environment."""
    root = tempfile.mkdtemp(prefix="readonly_hook_")
    try:
        (Path(root) / "AGENTS.md").write_text("one\ntwo\n")
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def sandbox_env(root: str) -> dict[str, str]:
    """A minimal environment with `HOME` and `TMPDIR` inside the scratch tree.

    Without this a command that writes to `~` would escape the snapshot and the test
    would pass while the finding it is checking for happened somewhere else.
    """
    keep = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env["HOME"] = root
    env["TMPDIR"] = root
    return env


def snapshot(root: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for directory, _, files in os.walk(root):
        for name in files:
            path = os.path.join(directory, name)
            try:
                with open(path, "rb") as handle:
                    out[os.path.relpath(path, root)] = hashlib.sha256(handle.read()).hexdigest()
            except OSError as exc:  # a socket or a vanished file is still a change
                out[os.path.relpath(path, root)] = f"unreadable: {exc.errno}"
    return out


def run_in_bash(command: str, root: str, timeout: float = 10.0):
    """One command, the way Claude Code hands it to a shell."""
    return subprocess.run(
        [BASH, "-c", command],
        cwd=root,
        env=sandbox_env(root),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def run_sealed(command: str, root: str, timeout: float = 10.0):
    """Like `run_in_bash`, with stdin closed.

    The harvested and fuzzed corpora contain commands nobody chose by hand, and a `cat`
    with no operand inherits the runner's stdin and blocks until the timeout. Closing it
    turns a ten-second stall into an immediate EOF.
    """
    return subprocess.run(
        [BASH, "-c", command],
        cwd=root,
        env=sandbox_env(root),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def run_in_zsh(command: str, root: str, timeout: float = 10.0):
    """One command the way Claude Code hands it to zsh: options set, then `eval`."""
    return subprocess.run(
        [ZSH, "-f", "-c", f"{CLAUDE_CODE_ZSH_OPTIONS}; eval {shlex.quote(command)}"],
        cwd=root,
        env=sandbox_env(root),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def run_session(commands, root: str, timeout: float = 10.0):
    """Several commands in one shell, the way a Claude Code session reuses one.

    State set by an approved command outlives it, which is the premise of the chained
    findings: no single command has to be dangerous for the sequence to be.
    """
    return subprocess.run(
        [BASH, "-s"],
        input="\n".join(commands) + "\n",
        cwd=root,
        env=sandbox_env(root),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def plant_executable(root: str, relative: str, body: str) -> None:
    path = Path(root) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


def bash_produces_effect(command: str, root: str) -> bool:
    """Whether bash actually does something observable with this string.

    Used to separate a real bypass from a string bash refuses to parse.
    """
    before = snapshot(root)
    try:
        run_in_bash(command, root)
    except subprocess.TimeoutExpired:
        return True
    return snapshot(root) != before


def mutates(command: str, root: str, timeout: float = 10.0) -> bool:
    before = snapshot(root)
    try:
        run_sealed(command, root, timeout)
    except subprocess.TimeoutExpired:
        return True
    return snapshot(root) != before


# --------------------------------------------------------------------------------------
# Assertions
# --------------------------------------------------------------------------------------


class Verdicts:
    """`why` is printed on failure, so a red run says what the classifier let through
    rather than only which string failed."""

    def assert_refused(self, command: str, why: str = "") -> None:
        self.assertFalse(
            hook.is_read_only(command),
            f"approved {command!r}" + (f", and bash {why}" if why else ""),
        )

    def assert_allowed(self, command: str, why: str = "") -> None:
        self.assertTrue(
            hook.is_read_only(command),
            f"refused {command!r}" + (f", though {why}" if why else ""),
        )


# --------------------------------------------------------------------------------------
# Reading this file
# --------------------------------------------------------------------------------------

# A class that installs a rule file asserts approvals that hold *with that file in
# place*. The differential below runs with the classifier tier alone, so harvesting from
# one of these collects a command the operator granted -- `Bash(touch *)` is in
# `REPRESENTATIVE_RULES` -- and reports the grant working as a bypass.
RULE_DEPENDENT = ("operator_rules",)


def _literal_first_arguments(tree: ast.AST, method: str) -> list[str]:
    """Every string literal passed as the first argument to `<object>.<method>(...)`
    anywhere under `tree`."""
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        function = node.func
        if not isinstance(function, ast.Attribute) or function.attr != method:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            found.append(first.value)
    return found


def _harvest(path: Path, method: str, skip_rule_dependent: bool = False) -> list[str]:
    """Every string literal passed as the first argument to `method` in one file.

    Only literals: a command built by an f-string is not a fixed claim about a fixed
    string, and a command held in a loop variable is already in a tuple this can see if
    it matters. `test_the_harvest_is_large_enough_to_be_working` guards against this
    silently finding nothing after a refactor.
    """
    found: list[str] = []
    for outer in ast.parse(path.read_text()).body:
        if skip_rule_dependent and isinstance(outer, ast.ClassDef):
            source = ast.unparse(outer)
            if any(marker in source for marker in RULE_DEPENDENT):
                continue
        found += _literal_first_arguments(outer, method)
    return found


# ======================================================================================
# Part 2 -- Shared corpora
#
# Command strings used by more than one class. Most of them are executed, so every entry
# here is held to `CorpusIsSafeToExecute` in part 3. A corpus that only one differential
# class uses lives on that class; `CorpusIsSafeToExecute.all_corpora` indexes all of them.
# ======================================================================================

# --------------------------------------------------------------------------------------
# Splices where bash and `shlex` disagree about where a command ends
# --------------------------------------------------------------------------------------

# Splices where bash and `shlex` disagree about where the first command ends, and bash
# executes the tail. `{payload}` is substituted with something the snapshot can see.
PUNCTUATION_BASH_EXECUTES = {
    ";(": "ls;({payload})",
    "&&(": "wc -l AGENTS.md&&({payload})",
    "||(": "false||({payload})",
    ";>": "ls;>" + PAYLOAD_MARKER,
    "&>>": "echo hi &>> " + PAYLOAD_MARKER,
    "<>": "cat AGENTS.md <> " + PAYLOAD_MARKER,
}

# Splices the classifier also mishandles, and bash rejects. Not exploitable today; kept
# because the classifier's reason for approving them is the same reason it approves the
# ones above, and because a future shell might accept them.
PUNCTUATION_BASH_REJECTS = {
    ";;": "ls;;touch " + PAYLOAD_MARKER,
    ";&": "ls;&touch " + PAYLOAD_MARKER,
    ";;&": "ls;;&touch " + PAYLOAD_MARKER,
    "|(": "ls|(touch " + PAYLOAD_MARKER,
    "spaced ;;": "ls ;; touch " + PAYLOAD_MARKER,
    "spaced ;&": "ls ;& touch " + PAYLOAD_MARKER,
}

# --------------------------------------------------------------------------------------
# Attacks proved live by running them
# --------------------------------------------------------------------------------------

# Words a substitution supplies. Each was run: the effect is in the module docstring.
EXPANSION_ATTACKS = (
    "sed \"$(echo -i)\" 's/one/1/' AGENTS.md",
    'sort "$(echo -o)" PWNED AGENTS.md',
    "awk 'BEGIN{\"touch PWNED\" | getline x}'",
)

# A redirection bound to a compound command rather than to a simple one.
COMPOUND_REDIRECT_ATTACKS = (
    "{ ls; } > PWNED",
    "(ls) > PWNED",
    "for f in a b; do echo $f; done > PWNED",
    "while false; do echo x; done >> PWNED",
    "if ls; then echo x; fi > PWNED",
    "ls > >(cat > PWNED)",
    "ls |& cat > PWNED",
)

# A writing flag hidden in the second character of a bundled short option.
BUNDLED_FLAG_ATTACKS = (
    "sed -ni 's/one/1/p' AGENTS.md",
    "sort -uo PWNED AGENTS.md",
)

# Quoting where bash ends the first command somewhere a scanner might not.
QUOTING_ATTACKS = (
    "echo 'a\\'; touch PWNED",
    "echo a\\\\; touch PWNED",
)

EXECUTED_ATTACKS = (
    EXPANSION_ATTACKS + COMPOUND_REDIRECT_ATTACKS + BUNDLED_FLAG_ATTACKS + QUOTING_ATTACKS
) + (('find . -name AGENTS.md "$(echo -delete)"',) if HAS_GNU_FIND else ())

# --------------------------------------------------------------------------------------
# Session chains
# --------------------------------------------------------------------------------------

# State an approved command leaves behind for the next one. Claude Code reuses one shell,
# so `DifferentialAcrossOneSession` runs each chain as a single bash session.
SESSION_CHAINS = (
    (
        "assemble a substitution across commands so none of them contains `$(`",
        (
            "ls; a='$'",
            "ls; b='(touch PWNED)'",
            "ls; c=${a}${b}",
            'echo "${c@P}"',
        ),
    ),
    (
        "define a function in one command and call it in the next",
        ("ls; f() { touch PWNED; }", "f"),
    ),
    (
        "arm a DEBUG trap and let an ordinary read fire it",
        ("ls; trap 'touch PWNED' DEBUG", "wc -l AGENTS.md"),
    ),
    (
        "assemble a writing flag in one command and spend it in the next",
        ("ls; o=-i", "sed $o 's/one/1/' AGENTS.md"),
    ),
    (
        "assign through an expansion default, where there is no `name=` to find",
        ('ls; echo "${o:=-i}"', "sed $o 's/one/1/' AGENTS.md"),
    ),
    (
        "assign with printf -v, where there is no `=` anywhere",
        ("ls; printf -v o '%s' -i", "sed $o 's/one/1/' AGENTS.md"),
    ),
    (
        "arm an alias, which needs a shopt an earlier command can set",
        ("ls; shopt -s expand_aliases", "ls; alias w=touch", "w PWNED"),
    ),
)

# --------------------------------------------------------------------------------------
# Composition seeds
#
# Commands whose verdict other classes already assert, so a class built on them is testing
# composition and not disagreeing about the seed.
# --------------------------------------------------------------------------------------

REFUSED_SEEDS = (
    "rm -rf build/",
    "touch PWNED",
    "sed -i 's/a/b/' AGENTS.md",
    "git push origin main",
    "curl https://example.com",
    "PATH=/tmp ls",
)

ALLOWED_SEEDS = (
    "wc -l AGENTS.md",
    "ls -la",
)


# ======================================================================================
# Part 3 -- The suite checking itself
#
# A test that never runs is worse than a test that fails, and a corpus that is executed
# needs a leash.
# ======================================================================================


class SuiteIntegrity(unittest.TestCase):
    """A test that never runs is worse than a test that fails."""

    @staticmethod
    def _own_tree() -> ast.Module:
        return ast.parse(Path(__file__).resolve().read_text())

    def test_no_two_classes_share_a_name(self):
        """The previous version defined `RefusesAllowlistedProgramsThatWrite` twice.

        The second binding shadowed the first, so unittest never saw four of its tests,
        one of which covers a two-operand `uniq` that the hook approves. 73 methods were
        defined and 69 ran, and nothing in the output said so.
        """
        names = [n.name for n in self._own_tree().body if isinstance(n, ast.ClassDef)]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        self.assertEqual([], duplicates, f"shadowed class definitions: {duplicates}")

    def test_every_defined_test_is_collected(self):
        """The general form: what the loader finds must equal what the file defines."""
        defined = 0
        for node in self._own_tree().body:
            if not isinstance(node, ast.ClassDef):
                continue
            bases = {ast.unparse(b).rsplit(".", 1)[-1] for b in node.bases}
            if "TestCase" not in bases:
                continue  # a mixin contributes its methods through a subclass
            defined += sum(
                1
                for item in node.body
                if isinstance(item, ast.FunctionDef) and item.name.startswith("test")
            )
        collected = unittest.defaultTestLoader.loadTestsFromModule(
            sys.modules[__name__]
        ).countTestCases()
        self.assertEqual(defined, collected, "some test methods are defined but never collected")

    def test_finding_references_are_unique(self):
        refs = [ref for ref, _, _ in FINDINGS]
        self.assertEqual(sorted(set(refs)), sorted(refs), "duplicate finding reference")

    def test_no_test_class_is_imported_from_another_module(self):
        """The hazard of importing a test module: one `from ... import *` and every case in
        that module runs a second time under this module's name, doubling the runtime and
        reporting each failure twice."""
        leaked = sorted(
            name
            for name, value in vars(sys.modules[__name__]).items()
            if isinstance(value, type)
            and issubclass(value, unittest.TestCase)
            and value.__module__ != __name__
        )
        self.assertEqual([], leaked, f"test classes imported from another module: {leaked}")

    def test_the_layout_in_the_module_docstring_matches_the_file(self):
        """The layout is how a reader finds a class, so it has to name every test class,
        in the order this file defines them. Only the indented entries count, so the prose
        around the list can name classes freely."""
        tree = self._own_tree()
        defined = [
            node.name
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and "TestCase" in {ast.unparse(b).rsplit(".", 1)[-1] for b in node.bases}
        ]
        section = (ast.get_docstring(tree) or "").split("How this file is laid out", 1)[-1]
        section = re.split(r"\n\S[^\n]*\n-{3,}\n", section, maxsplit=1)[0]
        section = "\n".join(line for line in section.splitlines() if line.startswith(" "))
        listed = [word for word in re.findall(r"\b[A-Z]\w+\b", section) if word in defined]
        self.assertEqual(defined, listed, "the module docstring's layout is out of date")

    # Raising this number is a decision, not a formality: every `assert_allowed` in a
    # budgeted class is a claim about what the classifier does rather than about what it
    # must not do, and a wrong one is a false failure that teaches people to ignore a red
    # run. Each of the five guards an idiom the rest of this file already asserts.
    APPROVAL_ASSERTIONS = 5

    def test_the_approval_assertions_stay_rare_and_guarded(self):
        """Counted over the classes marked `@approvals_budgeted`, literal commands only."""
        budgeted = [
            node
            for node in self._own_tree().body
            if isinstance(node, ast.ClassDef) and node.name in APPROVAL_BUDGETED
        ]
        self.assertTrue(budgeted, "no class is marked @approvals_budgeted")
        calls = [
            command
            for node in budgeted
            for command in _literal_first_arguments(node, "assert_allowed")
        ]
        self.assertLessEqual(
            len(calls),
            self.APPROVAL_ASSERTIONS,
            "the budgeted classes assert more approvals than they are budgeted for; each "
            "one has to guard an idiom asserted elsewhere, or it is a guess",
        )


class CorpusIsSafeToExecute(unittest.TestCase):
    """The differential classes run what they are given. This is the leash, and the proof
    that what is on it can bite.

    Read `is_corpus_safe` and `FORBIDDEN_IN_CORPUS` before adding a case, and do not add
    one they reject. `all_corpora` indexes every executed string in this file except the
    fuzzer's, which `DifferentialFuzz` leashes one candidate at a time.

    A case is proved live one of two ways. The hand-written differential corpus carries
    the payload marker, which `test_every_attack_leaves_a_detectable_mark` looks for. That
    misses `sed -ni`, whose payload is an edit to an existing file and contains no marker
    at all, so `EXECUTED_ATTACKS` and `SESSION_CHAINS` are proved by running them with the
    classifier out of the picture instead.
    """

    def all_corpora(self):
        yield from ((c, "differential") for c in DifferentialAgainstBash.ATTACKS)
        yield from ((c, "control") for c in DifferentialAgainstBash.CONTROLS)
        planted = DifferentialWithAPlantedProgram
        yield from ((c, "planted path") for c in planted.PATH_ATTACKS)
        yield from ((c, "planted spelling") for c in planted.SPELLING_ATTACKS)
        for _, chain in DifferentialAcrossOneSession.CHAINS:
            yield from ((c, "session") for c in chain)
        yield from ((c, "hygiene") for c in PUNCTUATION_BASH_REJECTS.values())
        yield from ((c, "executed") for c in EXECUTED_ATTACKS)
        yield from ((c, "differential") for c in DifferentialAgainstZsh.ATTACKS)

    def test_no_command_reaches_outside_the_scratch_tree(self):
        for command, origin in self.all_corpora():
            reason = is_corpus_safe(command)
            with self.subTest(origin=origin, command=command):
                self.assertIsNone(reason, reason)

    def test_every_attack_leaves_a_detectable_mark(self):
        """A payload the snapshot cannot see is a case that passes for free.

        Only the hand-written differential corpus is checked this way. The planted and
        session corpora are exempt: their payload lives in the planted executable or is
        assembled across commands at runtime, both of which the harness writes, so
        `plant_executable` and the chain itself carry the marker instead. The executed
        corpus is proved by running it, below.
        """
        for command, origin in self.all_corpora():
            if origin != "differential":
                continue
            with self.subTest(command=command):
                self.assertIn(PAYLOAD_MARKER, command)

    def test_the_planted_path_corpus_names_programs_inside_the_tree(self):
        """`plant_executable` puts the marker in the program; the command must resolve
        to it rather than to anything on the real PATH."""
        for command in DifferentialWithAPlantedProgram.PATH_ATTACKS:
            with self.subTest(command=command):
                self.assertTrue(
                    command.startswith(("./", "bin/", "PATH=bin ")),
                    "a planted-program case that could resolve outside the scratch tree",
                )

    def test_the_planted_spelling_corpus_cannot_resolve_to_a_system_program(self):
        """`plant_executable` writes the program; the command has to be a name that can
        only find it. A candidate that matches something already on PATH would run the
        real one and the case would pass for free."""
        for command in DifferentialWithAPlantedProgram.SPELLING_ATTACKS:
            with self.subTest(command=command):
                self.assertNotIn("/", command, "a path would resolve outside the tree")

    @needs_bash
    def test_every_attack_really_mutates_the_tree(self):
        """Run each one with the classifier out of the picture. A case bash declines to
        execute is a case that would pass whatever the hook decided."""
        self.maxDiff = None
        inert: list[str] = []
        for command in EXECUTED_ATTACKS:
            with scratch_tree() as root:
                if not mutates(command, root):
                    inert.append(command)
        self.assertEqual([], inert, "attacks with no effect:\n  " + "\n  ".join(inert))

    @needs_bash
    @needs_bash_44
    def test_every_session_chain_really_mutates_the_tree(self):
        inert: list[str] = []
        for description, chain in SESSION_CHAINS:
            with scratch_tree() as root:
                before = snapshot(root)
                run_session(chain, root)
                if snapshot(root) == before:
                    inert.append(description)
        self.assertEqual([], inert, "chains with no effect:\n  " + "\n  ".join(inert))


# ======================================================================================
# Part 4 -- Baseline verdicts
#
# The broad strokes: ordinary reads that should stop prompting, the writes that must keep
# prompting, the same property stated over composition, and the allowlist measured
# against the host's own read-only set.
# ======================================================================================


class ApprovesReadOnly(Verdicts, unittest.TestCase):
    """Commands that only read, which should stop prompting."""

    def test_plain_read(self):
        self.assert_allowed("wc -l AGENTS.md")
        self.assert_allowed("ls -la 'docs/'")
        self.assert_allowed("grep -n FIXME 'docs/a.md'")

    def test_pipeline(self):
        self.assert_allowed("cat 'a.md' | head -n 40 | tail -n +10")
        self.assert_allowed("grep -c . 'a.md' | sort -k2 | head -80")

    def test_stream_redirect_is_not_a_write(self):
        self.assert_allowed("gcloud organizations get-iam-policy '1' 2>&1 | sort")
        self.assert_allowed("ls 'scripts/' 2>/dev/null")
        self.assert_allowed("ls 'scripts/' 2>&1; wc -l AGENTS.md")
        self.assert_allowed("ls 'scripts/' 2>&1|wc -l")

    def test_read_only_vendor_calls(self):
        self.assert_allowed("aws ecs list-clusters --output text")
        self.assert_allowed("aws sts get-caller-identity")
        self.assert_allowed("aws --version", "the Local dependencies table of every logbook")
        self.assert_refused("aws --version s3 cp s3://b/k out", "only the bare shape is exempt")
        self.assert_allowed("gcloud projects list --format='value(projectId)'")
        self.assert_allowed("git log --oneline -5")
        self.assert_allowed("git stash list")
        self.assert_allowed("git stash show")

    def test_the_loop_that_prompted_over_ranges(self):
        """The `head`/`tail` range idiom, parameterized -- notes example 4."""
        self.assert_allowed(
            "f='docs/x.md'; for r in 209:222 254:268; do s=\"${r%%:*}\"; "
            'e="${r##*:}"; echo "=== ${s}-${e} ==="; '
            'head -n "${e}" "${f}" | tail -n 4 | cat -A | sed \'s/\\$$//\' '
            "| cut -c1-200; done"
        )

    def test_the_loop_that_prompted_over_projects(self):
        """Read-only `gcloud` over a list of projects -- notes example 1."""
        self.assert_allowed(
            "echo '=== group bindings ==='; "
            "for _p in lorem ipsum dolor; do "
            'gcloud projects get-iam-policy "${_p}-project" '
            "--flatten='bindings[].members' --format='value(bindings.role)' 2>&1 "
            '| sed "s/^/${_p}|/"; done'
        )

    def test_the_chain_that_prompted(self):
        """Notes example 3, whose `gcloud config configurations list` matched no rule."""
        self.assert_allowed(
            "echo '### configurations'; gcloud config configurations list 2>&1; echo; "
            "gcloud services list --enabled --project=my-project "
            "--format='value(config.name)' 2>&1 | grep -E '^orgpolicy' | sort; "
            "ls scripts/"
        )

    def test_git_diff_and_awk_line_inspection_chain(self):
        """Inspection pipeline chaining git diff, printf, and formatted line extraction with awk."""
        self.assert_allowed(
            "git diff --stat AGENTS.md; printf '%s\\n' '--- the 3 long lines ---'; "
            "awk 'NR==114 || NR==140 || NR==289 "
            '{printf "%d: %s\\n", NR, substr($0,1,60)}\' AGENTS.md'
        )


class RefusesAnythingElse(Verdicts, unittest.TestCase):
    """Silence, so the command prompts as it does today. The important half."""

    def test_file_writes(self):
        for command in (
            "echo hi > AGENTS.md",
            "echo hi >> AGENTS.md",
            "cat a.md | tee b.md",
            "truncate -s 0 AGENTS.md",
            "cp a.md b.md",
            "mv a.md b.md",
            "rm -rf build/",
        ):
            self.assert_refused(command)

    def test_redirection_shapes(self):
        """Every redirection token, including the ones that are not a bare `>`."""
        for command in (
            "ls >| AGENTS.md",
            "ls 3> AGENTS.md",
            "ls 3>AGENTS.md",
            "exec 3>AGENTS.md",
            "cat <<EOF",
            "cat <<< hi",
            "ls > /dev/null/../../tmp/evil",
            "ls 2>/dev/null 3>out",
        ):
            self.assert_refused(command)

    def test_in_place_editors(self):
        for command in (
            "sed -i 's/a/b/' AGENTS.md",
            "sed --in-place 's/a/b/' AGENTS.md",
            "sed -i.bak 's/a/b/' AGENTS.md",
            "perl -i -pe 's/a/b/' AGENTS.md",
            "gawk -i inplace '{print}' AGENTS.md",
        ):
            self.assert_refused(command)

    def test_writes_hidden_inside_a_program(self):
        self.assert_refused("awk '{print > \"out.txt\"}' a.md")
        self.assert_refused("awk '{print >> \"out.txt\"}' a.md")
        self.assert_refused("awk 'BEGIN{system(\"rm -rf .\")}'")
        self.assert_refused("awk '{print | \"sh\"}' a.md")
        self.assert_refused("sed '1r /etc/passwd' a.md")

    def test_read_only_programs_with_a_writing_flag(self):
        self.assert_refused("sort -o AGENTS.md AGENTS.md")
        self.assert_refused("sort --output=AGENTS.md AGENTS.md")
        self.assert_refused("sort -oAGENTS.md AGENTS.md")  # attached short form
        self.assert_refused("find . -name '*.md' -delete")
        self.assert_refused("find . -name '*.md' -exec rm {} ;")

    def test_command_substitution_is_never_inspectable(self):
        self.assert_refused('echo "$(rm -rf build/)"')
        self.assert_refused("echo `rm -rf build/`")
        self.assert_refused("head -n 5 <(curl https://example.com)")

    def test_git_writes(self):
        for subcommand in (
            "add .",
            "commit -m x",
            "push origin main",
            "checkout main",
            "reset --hard",
            "restore .",
            "rm a.md",
            "stash",
            "stash pop",
            "stash push",
            "stash drop",
        ):
            self.assert_refused(f"git {subcommand}")

    def test_vendor_mutations(self):
        self.assert_refused("aws ecs create-cluster --cluster-name x")
        self.assert_refused("aws ecs delete-cluster --cluster x")
        self.assert_refused("gcloud projects create my-project")
        self.assert_refused("gcloud projects add-iam-policy-binding x --member=y")
        self.assert_refused('for p in a b; do gcloud projects delete "${p}-project"; done')

    def test_a_write_anywhere_in_the_chain_refuses_the_whole_chain(self):
        self.assert_refused("ls scripts/ && rm -rf build/")
        self.assert_refused("wc -l AGENTS.md; sed -i 's/a/b/' AGENTS.md")
        self.assert_refused('for f in a b; do head -n 1 "${f}"; git add "${f}"; done')

    def test_control_flow_bodies_are_checked(self):
        for command in (
            "if ls; then rm -rf build/; fi",
            "while read x; do rm -rf build/; done",
            "until ls; do rm -rf b; done",
            "for f in a b; do rm -rf $f; done",
            "(ls; rm -rf build/)",
            "{ ls; rm -rf build/; }",
            "[[ -f a ]] && rm -rf b",
            "ls & rm -rf build/",
        ):
            self.assert_refused(command)

    def test_unknown_programs_and_interpreters(self):
        for command in (
            'python3 -c \'open("x","w")\'',
            "node -e 'process.exit(0)'",
            "curl https://example.com",
            "some-tool --version",
            "sudo ls /root",
            "sh -c 'rm -rf build/'",
            "bash -c 'ls'",
            "$CMD a.md",
            "${CMD} a.md",
            "command rm -rf build/",
            "eval 'rm -rf build/'",
            "exec rm -rf build/",
            "xargs rm",
        ):
            self.assert_refused(command)

    def test_unparseable_text(self):
        self.assert_refused("echo 'unbalanced")
        self.assert_refused("")
        self.assert_refused("   ")


@approvals_budgeted
class RefusalIsMonotonicUnderComposition(Verdicts, unittest.TestCase):
    """Adding a refused fragment to a command can never produce an approval.

    Almost every lexer finding in this file is a special case of this being false:
    a segment that is skipped rather than refused, a punctuation run that lands as an
    argument, a `case` body that rides along. Stating it as a property means the next
    separator nobody thought of is covered before it is discovered, and it is cheap --
    the cross product below is forty-eight commands and one `is_read_only` call each.

    The seeds are commands other classes already assert a verdict for, so a failure
    here is a composition bug and not a disagreement about the seed.
    """

    SEPARATORS = ("; ", " && ", " || ", " | ", " & ")

    def test_the_seeds_are_what_this_class_thinks_they_are(self):
        """The premise, asserted rather than assumed: if a `REFUSED_SEED` were approved
        on its own, every case below would pass for the wrong reason."""
        for command in REFUSED_SEEDS:
            with self.subTest(seed=command):
                self.assert_refused(command)
        for command in ALLOWED_SEEDS:
            with self.subTest(seed=command):
                self.assert_allowed(command, "asserted elsewhere in this file")

    def test_a_refusal_survives_being_appended_to(self):
        for allowed in ALLOWED_SEEDS:
            for refused in REFUSED_SEEDS:
                for separator in self.SEPARATORS:
                    command = f"{allowed}{separator}{refused}"
                    with self.subTest(command=command):
                        self.assert_refused(command)

    def test_a_refusal_survives_being_prepended_to(self):
        for refused in REFUSED_SEEDS:
            for allowed in ALLOWED_SEEDS:
                for separator in self.SEPARATORS:
                    command = f"{refused}{separator}{allowed}"
                    with self.subTest(command=command):
                        self.assert_refused(command)

    @open_finding(
        "S-01",
        "the composition form of P-02: a newline is not treated as a separator",
    )
    def test_a_refusal_survives_a_newline_separator(self):
        """Split out because `RefusesShellSyntaxTheLexerMisreads` records the newline
        defect as P-02, and a class-wide failure would hide the other five separators
        behind it."""
        for allowed in ALLOWED_SEEDS:
            for refused in REFUSED_SEEDS:
                for command in (f"{allowed}\n{refused}", f"{refused}\n{allowed}"):
                    with self.subTest(command=command):
                        self.assert_refused(command)

    def test_a_refusal_survives_being_wrapped_in_a_compound(self):
        wrappers = (
            "if ls; then {}; fi",
            "while false; do {}; done",
            "until true; do {}; done",
            "for f in a b; do {}; done",
            "({})",
            "{{ {}; }}",
            "ls && {{ {}; }}",
            "case x in a) {};; esac",
        )
        for wrapper in wrappers:
            for refused in REFUSED_SEEDS:
                command = wrapper.format(refused)
                with self.subTest(command=command):
                    self.assert_refused(command)

    def test_a_refusal_survives_being_moved_into_a_substitution(self):
        shapes = ('echo "$({})"', "x=$({})", "for f in $({}); do ls; done", "ls $({})")
        for shape in shapes:
            for refused in REFUSED_SEEDS:
                command = shape.format(refused)
                with self.subTest(command=command):
                    self.assert_refused(command)

    def test_whitespace_is_not_a_way_around_a_refusal(self):
        for refused in REFUSED_SEEDS:
            for command in (f"  {refused}", f"{refused}  ", f"\t{refused}", f"{refused}\n"):
                with self.subTest(command=repr(command)):
                    self.assert_refused(command)


class MatchesTheHostsOwnCaution(Verdicts, unittest.TestCase):
    """Being more permissive than the host contradicts the module docstring's invariant
    ("it approves only what Claude Code already approves outside a loop"). Each of these
    is documented host behavior, not an inference."""

    @open_finding("H-01", "READ_ONLY is far broader than the host's read-only set")
    def test_the_allowlist_matches_the_host(self):
        """The structural version of this class.

        The host's set is fourteen names plus read-only `git`. The hook adds roughly
        thirty more -- `sed`, `awk`, `sort`, `uniq`, `xxd`, `od`, `date`, `hostname`,
        `file` among them -- none of which Claude Code runs unprompted on its own. The
        invariant fails here before any parser bug is involved. Record a decision by
        adding names to `SITE_APPROVED_BEYOND_HOST`, not by widening the host set.
        """
        extra = set(hook.READ_ONLY) - HOST_READ_ONLY - SITE_APPROVED_BEYOND_HOST
        self.assertEqual(
            set(),
            extra,
            "approved beyond the host's read-only set without a recorded decision: "
            + ", ".join(sorted(extra)),
        )

    def test_an_unquoted_glob_can_expand_into_a_flag(self):
        """With a file named `-o` in the directory, `sort *` becomes `sort -o a b` and
        overwrites `a`. The host prompts for `find`, `sort`, `sed` and `git`."""
        self.assert_refused("sort *", "a file named -o makes this a write")
        self.assert_refused("find . *", "a file named -delete makes this a write")
        self.assert_refused("git log *", "a glob can supply a git flag")

    def test_file_with_path_opening_flags(self):
        self.assert_refused("file -m /tmp/magic a.md", "opens /tmp/magic")
        self.assert_refused("file -f /tmp/list a.md", "opens /tmp/list")

    def test_a_command_too_long_to_analyze(self):
        command = "wc -l " + " ".join(f"f{i}.md" for i in range(2_000))
        self.assertGreater(len(command), HOST_COMMAND_LENGTH_CAP)
        self.assert_refused(command, "is longer than the host will analyze")


# ======================================================================================
# Part 5 -- Commands observed prompting in real sessions
#
# The counterweight to the refusal-focused classes, and the reason this part has no
# approval budget: nothing in it is a guess. Each command here was copied out of a Claude
# Code permission prompt in an actual working session, which is the strongest evidence
# available that a refusal is costing something real.
#
# That does not make them safe by virtue of having been typed. Each one was read, and the
# three that were not made to pass are recorded in `ObservedCommandsNotMadeToPass`
# (part 18) with the reason and a working rewrite, so a later reader does not mistake their
# absence for an oversight.
#
# Four capabilities were opened to make the rest pass. Each is paired with the case that
# shows where it stops:
#
#   jq                        a filter with no write and no exec | `$ENV` still refused
#   sed with file operands    reading a file is what sed is for  | `-i`, `-ni`, `w` refused
#   quoted globs              `-name '*.md'` is find's to match  | unquoted `*.md` refused
#   `<(...)`, scratch writes  a body that is classified; a write | `>(...)`, other paths
#                             whose path the module can resolve  | refused
#
# The boundary case is the half that matters. An approval with no paired refusal records
# that something was widened without recording how far, which is the shape of every
# allowlist finding elsewhere in this file.
# ======================================================================================

ROOT = str(hook.REPO_ROOT)

# A document name with the spaces, punctuation and timestamp formate we like, because
# the quoting those force is half of why these commands are shaped the way they are.
LOG = "docs/2026-12-01T15-23-10Z Lorem - Ipsum dolor-sit - ABC.md"
TASKDEF = "my/dir/12345678:my.house-1:lorem_ipsum:6.x.y.gz"

# The observed scratch directory layout: /tmp/claude-<uid>/<cwd-slug>/<session-uuid>/scratchpad
SCRATCH = "/tmp/claude-1000/-home-dir1-dir2/00000000-0000-4000-8000-000000000000/scratchpad"


class ObservedCommandsStayApproved(Verdicts, unittest.TestCase):
    """The prompts that prompted. Each docstring names what was blocking it before.

    These are regression guards, not a specification: a later tightening that refuses one
    of them is not necessarily wrong, but it is a decision someone has to make on purpose
    rather than discover in a session three weeks later.
    """

    def test_a_sed_range_read_from_a_named_file(self):
        """`sed` was pipeline-only: one script plus a file operand was refused outright,
        so every `sed -n '/a/,/b/p' file` had to be rewritten as a `cat` into a pipe."""
        self.assert_allowed(f"sed -n '/^unset _service/,/^The target group/p' '{LOG}' | head -n 30")

    def test_jq_over_an_exported_task_definition(self):
        """`unrecognized program: jq`, which is most of this repository's analysis."""
        self.assert_allowed(f"jq -r '.containerDefinitions[0].environment[].name' '{TASKDEF}'")

    def test_a_loop_reading_json(self):
        """Same, inside the `for` loop the comparison work is actually written in. The
        `${f}` in the operand was never the blocker: an expansion in an operand position
        has always been approved."""
        self.assert_allowed(
            "for f in 'lorem-ipsum:618' 'dolor_sit:108'; do "
            "echo \"=== $f\"; jq -r '.containerDefinitions[0].environment[].name' "
            '"my/dir/12345678:my.house-1:${f}.x.y.gz" | sort; done'
        )

    def test_a_relative_cd_then_jq(self):
        self.assert_allowed(
            "cd my/dir && "
            "jq -r '.containerDefinitions[0].environment[] | .name' "
            "'12345678:my.house-1:lorem_ipsum:6.x.y.gz' | sort"
        )

    def test_an_absolute_cd_to_the_repository_root(self):
        """Never a classifier problem -- the target resolves to the root -- and worth
        pinning because the host prompts on it for its own reasons."""
        self.assert_allowed(f"cd '{ROOT}' && grep -nE 'CREATE ROLE|app' \"{LOG}\" | head -30")

    def test_a_diff_of_two_process_substitutions(self):
        """`process substitution` refused the whole form. Both bodies are classified by
        the same rules as any other command now, so what is approved is a `diff` of two
        pipelines that were each read."""
        self.assert_allowed(
            "echo '=== names' && diff "
            f"<(jq -r '.containerDefinitions[0].environment[].name' '{TASKDEF}' | sort) "
            f"<(jq -r '.containerDefinitions[0].environment[].name' '{TASKDEF}' | sort)"
        )

    def test_find_with_a_quoted_name_pattern(self):
        """`glob operand in find` fired on `-not -path './.git/*'`, a pattern the shell
        never expands and `find` matches for itself."""
        self.assert_allowed("find . -name 'CLAUDE.md' -not -path './.git/*'")
        self.assert_allowed("find .claude/agents -name '*.md' 2>/dev/null")

    def test_a_write_into_the_session_scratch_directory(self):
        """A `>` was refused wherever it pointed. The scratch directory carries the
        session id, dies with the session, and is where Claude Code tells the model to put
        working files, so a write landing inside it is contained by construction."""
        with scratch_at(None):
            self.assert_allowed(
                f"awk 'NR>=740 && NR<=903' \"{LOG}\" | sort -u > {SCRATCH}/core-expected.txt"
            )

    def test_reading_a_file_through_an_input_redirect(self):
        """`wc -l < file` is a read spelled with punctuation, and was refused as one."""
        with scratch_at(None):
            self.assert_allowed(f"wc -l < {SCRATCH}/core-expected.txt")
        self.assert_allowed("wc -l < AGENTS.md")

    def test_the_repository_scripts_through_the_operator_rules(self):
        """Not a classifier change at all: `scripts/check-docs.py` is a non-bare path the
        module declines to read, and an allow rule for it covers it. Pinned
        because it looks like the others and is fixed somewhere else entirely."""
        with representative_rules():
            self.assert_allowed(
                f't="guides/tracker.md"; f1="{LOG}"; echo \'--- check-docs\'; '
                'scripts/check-docs.py "$t" "$f1" --no-fixme 2>&1 | tail -10'
            )


class AllowsALoopVariableBoundToLiterals(Verdicts, unittest.TestCase):
    """`for f in 'a.json' 'b.json'; do jq -r '.x' "$f"; done` and the edge of the
    exemption that makes it pass.

    `"$f"` is a word the shell builds, and for a program with a validator -- `jq`, `sed`,
    `sort` -- `EXPANSION_UNSAFE` refuses that, because `f` could hold `-f` and turn the
    program into a loader. The carve-out: when the loop's `in` list is entirely literal
    words and none begins with `-`, every value `f` can take is written out in the command
    and none is a flag, so a *quoted* `"$f"` cannot arrive as one. This is the shape most
    of the repository's multi-file analysis is written in.

    Three conditions hold the exemption in, and each has its own refusal below:

    * **the list is literal** -- a `$(...)`, a `${arr[@]}`, or a `-flag` in the list says
      nothing safe about `f`, so none of those loops is exempt;
    * **the use is quoted** -- an unquoted `$f` is re-split and re-globbed where it is used,
      so even a literal value like `*.json` could expand into filenames there, one of which
      might be `-o`; only `"$f"` is exactly the value;
    * **the word is nothing but the variable** -- `"${f}-x"` and `"$f$g"` are governed by
      the suffix rule in `_word_the_shell_decides`, not by this exemption.

    The exemption also does not make the rest of the body a read: a flag in a different
    position, or a write, is refused as it would be anywhere.
    """

    def test_the_idiom_the_repository_writes(self):
        self.assert_allowed(
            "for f in 'a.json' 'b.json'; do jq -r '.a' \"$f\"; done",
            "the list is all literals, so $f cannot be a flag",
        )
        self.assert_allowed("for f in a.md b.md; do sed -n '1,5p' \"$f\"; done")
        self.assert_allowed(
            "for f in 'svc-A:523683' 'SvC-X:2'; do "
            "jq -r '.containerDefinitions[0].environment[].name' "
            '"abc/def-1/123456789012: hello : ${f}.json" | sort; done',
            "the operand glues a literal path around ${f}; that was always allowed",
        )

    def test_a_non_literal_list_does_not_exempt_the_variable(self):
        self.assert_refused('for f in $(ls); do jq . "$f"; done', "the list is built by a command")
        self.assert_refused('for f in "${arr[@]}"; do jq . "$f"; done', "the list is an expansion")
        self.assert_refused(
            "for f in -i x; do sed \"$f\" 's/a/b/' g.md; done", "the list contains a flag"
        )

    def test_an_unquoted_use_is_not_exempt(self):
        """`$f` without quotes re-globs and re-splits at the use site, so a literal
        `*.json` in the list can still reach the program as a `-o` filename."""
        self.assert_refused("for f in '*.json'; do sort $f; done", "unquoted, re-globbed")
        self.assert_refused("for f in a.md; do jq . $f; done", "unquoted, re-split")

    def test_a_glued_expansion_is_not_this_exemption(self):
        self.assert_refused(
            'for f in a b; do jq . "$f$g"; done', "$g is a second, unbound variable"
        )

    def test_a_bare_expansion_with_no_binding_loop_is_still_refused(self):
        self.assert_refused('jq . "$f"', "nothing binds f")
        self.assert_refused('for g in a.md; do jq . "$f"; done', "the loop binds g, not f")

    def test_the_exemption_does_not_cover_a_write_in_the_body(self):
        self.assert_refused(
            'for f in a.md; do sort "$f" -o PWNED; done', "an output flag is still a write"
        )
        self.assert_refused(
            "for f in a.md; do sed -i 's/a/b/' \"$f\"; done", "-i still edits in place"
        )


class SplicesFlagsFromALiteralAssignment(Verdicts, unittest.TestCase):
    """`_p='--profile admin --region us-east-1'; aws ... ${=_p} ...` and its edge.

    A variable assigned a literal string and then word-split into an argument list --
    `${=_p}` in zsh, or bare `$_p`/`${_p}` in any shell -- was refused, because the flags
    it carries are a word the shell builds and `aws` is in `EXPANSION_UNSAFE`. That rule is
    right in general: the value could hold `s3 rm` or `--endpoint-url`. But the assignment
    is in the same command as the use, so the value is here to read. The hook resolves it,
    splices its words into the argument list, and runs the normal validator on the result,
    so `aws ... ${=_p} ...` is checked as the `aws ... --profile admin --region us-east-1
    ...` it becomes -- approved when that is a read, refused when it is not.

    The splice is never more than typing the value out. Every refusal below is a value
    whose spelled-out form the hook refuses too, plus the cases where the value cannot be
    resolved at all. Four conditions gate it, each with a test:

    * **the value is fully literal** -- a `$(...)`, a nested `$var`, a glob or a brace means
      the final words are not fixed, so no splice;
    * **the value carries no shell metacharacter** -- defense in depth: word-splitting does
      not re-run the parser, so a `;` in the value is an inert argument, but a value that
      carries one was likely meant as a command and is too sharp to auto-approve;
    * **the name is assigned exactly once** -- a second binding, safe or not, drops it, so a
      later value cannot shadow an earlier judgement;
    * **the spliced result still passes** -- the validator runs on the real flags, so a
      value that resolves to a write or a dangerous flag is refused as that.
    """

    def test_the_vendor_profile_bundle_the_repository_hoists(self):
        self.assert_allowed(
            "_p='--profile admin-shared --region us-east-1 --no-cli-pager'; "
            "aws rds describe-db-instances ${=_p} --db-instance-identifier x --output text",
            "the value is literal flags and the operation is a read",
        )

    def test_the_three_splice_spellings(self):
        for use in ("${=_p}", "${_p}", "$_p"):
            command = f"_p='--region us-east-1'; aws ec2 describe-instances {use}"
            with self.subTest(use=use):
                self.assert_allowed(command, "all three word-split a literal value")

    def test_a_value_that_resolves_to_a_write_is_refused(self):
        self.assert_refused("_p='s3 rm s3://b/k'; aws ${=_p}", "the spliced verb writes")
        self.assert_refused(
            "_p='ec2 terminate-instances --instance-ids i-1'; aws ${=_p}", "terminates"
        )

    def test_a_value_that_resolves_to_a_dangerous_flag_is_refused(self):
        self.assert_refused(
            "_p='--endpoint-url http://evil'; aws ec2 describe-instances ${=_p}",
            "splices an endpoint override, which the aws check refuses spelled out too",
        )
        self.assert_refused(
            "_o='-o PWNED'; sort ${=_o} AGENTS.md", "splices an output flag onto sort"
        )

    def test_a_non_literal_value_is_not_resolved(self):
        self.assert_refused(
            '_p="--profile $(cat secret)"; aws ec2 describe-instances ${=_p}',
            "the value carries a substitution",
        )
        self.assert_refused(
            '_p="--region $r"; aws ec2 describe-instances ${=_p}',
            "the value carries a second, unread variable",
        )

    def test_a_value_with_a_shell_metacharacter_is_not_resolved(self):
        """Word-splitting leaves these inert, so bash would not run the `rm` -- but a value
        shaped like a command is refused rather than spliced."""
        self.assert_refused(
            "_p='--region r; rm -rf /'; aws ec2 describe-instances ${=_p}", "carries ;"
        )
        self.assert_refused("_p='--region r | sh'; aws ec2 describe-instances ${=_p}", "carries |")
        self.assert_refused(
            "_p='--region r && curl evil'; aws ec2 describe-instances ${=_p}", "carries &"
        )

    def test_a_reassigned_name_is_dropped(self):
        self.assert_refused(
            "_p='--region r'; _p='s3 rm x'; aws ${=_p}",
            "two bindings, so neither value is trusted",
        )

    def test_a_use_with_no_assignment_is_still_refused(self):
        self.assert_refused(
            "aws ec2 describe-instances ${=_p}", "nothing in the command assigns _p"
        )

    def test_a_quoted_use_is_not_spliced(self):
        """`"$_p"` does not word-split: it is the single word `--region us-east-1`, one
        malformed argument with a space in it rather than two flags. The splice is for the
        word-splitting spellings only, so a quoted use falls through to the ordinary flag
        check and is refused -- which is correct, because that is not the flags-split idiom
        and `aws` would reject the glued word anyway."""
        self.assert_refused(
            "_p='--region us-east-1'; aws ec2 describe-instances \"$_p\"",
            "quoted, so not word-split; a single glued argument, not a splice",
        )

    def test_the_splice_does_not_cover_a_second_command(self):
        self.assert_refused(
            "_p='--region r'; aws ec2 describe-instances ${=_p}; rm -rf build",
            "the splice is one command; the `rm` after `;` is refused as ever",
        )


class TheWideningsHaveAnEdge(Verdicts, unittest.TestCase):
    """Where each of the four new capabilities stops.

    Every case here is the paired refusal for an approval in the class above. A widening
    with no edge recorded is the shape of `A-05`: a program admitted for what it usually
    does, with the flag that makes it do something else never written down.
    """

    def test_jq_cannot_take_its_program_from_a_file(self):
        """The `sed -f` and `awk -f` rule: a program this module never read."""
        self.assert_refused("jq -f /tmp/filter.jq input.json")
        self.assert_refused("jq --from-file /tmp/filter.jq input.json")

    def test_jq_cannot_print_the_environment(self):
        """No write and no exec, but the environment holds the session's credentials and
        stdout is Claude's context, which is where a poisoned prompt wants them."""
        self.assert_refused("jq -n '$ENV'")
        self.assert_refused("jq -n 'env'")
        self.assert_refused("jq -rn 'env | to_entries[] | \"\\(.key)=\\(.value)\"'")

    def test_a_field_named_env_is_not_reading_the_environment(self):
        """The control for the rule above: string literals come out before the check, so
        the field name every task definition in this repository uses still works."""
        self.assert_allowed("jq -r '.containerDefinitions[0].environment[].name' x.json")
        self.assert_allowed("jq -r '.[] | select(.name==\"env\")' x.json")

    def test_sed_still_cannot_edit_or_write(self):
        self.assert_refused("sed -i 's/a/b/' AGENTS.md")
        self.assert_refused("sed -n 'w /tmp/out' AGENTS.md")
        self.assert_refused("sed -n 's/a/b/w /tmp/out' AGENTS.md")
        self.assert_refused("sed -n '1e touch PWNED' AGENTS.md")

    def test_a_writing_flag_bundled_behind_another_short_flag(self):
        """The cost of letting sed take operands, paid up front. Before it did, `sed -ni
        'x' file` was refused because it had two non-flag words, not because anything read
        the `-i` -- so the operand change would have opened it."""
        self.assert_refused("sed -ni 's/one/1/p' AGENTS.md")
        self.assert_refused("sed -nri 's/one/1/' AGENTS.md")
        self.assert_refused("sed -nf /tmp/prog.sed AGENTS.md")

    def test_the_letter_after_a_value_taking_flag_is_a_value(self):
        """The other half: `-t` takes the separator, so the `o` in a bundle after it is
        that separator and not an output flag. Over-refusing here is how a fix for the
        case above turns into a new prompt."""
        self.assert_allowed("sed -ne '2p' AGENTS.md")
        self.assert_allowed("sed -s -n '1p' a.md b.md")

    def test_an_unquoted_glob_is_still_refused(self):
        """A quoted wildcard is find's to match; an unquoted one is whatever the directory
        held, which is how an operand becomes a flag."""
        self.assert_refused("find . -name *.md")
        self.assert_refused("sort *")
        self.assert_refused("sed -n '1p' *.md")

    def test_the_output_form_of_process_substitution(self):
        """`<(...)` runs a command. `>(...)` runs one and hands it a stream to write."""
        self.assert_refused("ls > >(cat > PWNED)")
        self.assert_refused("ls > >(sh)")
        self.assert_refused("wc -l AGENTS.md > >(touch PWNED)")

    def test_a_process_substitution_body_is_classified(self):
        """The body is not trusted for sitting in a redirect position; it goes through the
        same rules, so a write inside one is refused where it stands."""
        self.assert_refused("diff <(rm -rf build/) <(ls)")
        self.assert_refused("diff <(ls) <(curl https://example.com)")
        self.assert_refused("head -n 5 <(cat /etc/shadow > PWNED)")

    def test_a_write_outside_the_scratch_directory(self):
        """The rule is the path, not the punctuation."""
        with scratch_at(None):
            self.assert_refused("wc -l AGENTS.md > PWNED")
            self.assert_refused("wc -l AGENTS.md > /tmp/out.txt")
            self.assert_refused(f"wc -l AGENTS.md > {SCRATCH}/../../escape.txt")
            self.assert_refused("wc -l AGENTS.md > /tmp/claude-1000/x/y/scratchpad/out")

    def test_a_scratch_path_the_module_cannot_resolve(self):
        """The observed session builds the path into a variable and writes through it.
        `$S` is a word this module never read, so `> "$S/out"` is a write to an unknown
        path and stays refused -- the literal spelling is the one that passes."""
        with scratch_at(None):
            self.assert_refused(f'S={SCRATCH} && wc -l AGENTS.md > "$S/out.txt"')
            self.assert_refused('wc -l AGENTS.md > "${SCRATCH}/out.txt"')
            self.assert_refused(f"wc -l AGENTS.md > $(echo {SCRATCH})/out.txt")

    def test_an_input_redirect_cannot_open_a_socket(self):
        """Allowing `< file` is only safe because the shell's own network pseudo-device is
        refused wherever it appears, quoted or not."""
        self.assert_refused("cat < /dev/tcp/example.com/80")
        self.assert_refused('cat < "/dev/tcp/example.com/80"')
        self.assert_refused("cat /dev/tcp/example.com/80")
        self.assert_refused("wc -l < /dev/udp/example.com/53")

    def test_jq_string_literals_hide_nothing(self):
        """The literal-stripping that lets a field named `env` through must not swallow
        code: an escaped backslash once ended the match late and hid the `env` after it,
        and `\\(...)` inside a literal is interpolation, which runs."""
        self.assert_refused('jq -n \'"\\\\" | env | "x"\'')
        self.assert_refused("jq -n '\"\\(env)\"'")
        self.assert_refused("jq -n '\"\\($ENV.HOME)\"'")

    def test_jq_cannot_load_code_from_a_file(self):
        """`-f` under other names: a bundled `-rf`, a module, and the path modules come from."""
        self.assert_refused("jq -rf prog.jq x.json")
        self.assert_refused("jq -n 'include \"x\"; 1'")
        self.assert_refused("jq -n 'import \"x\" as x; 1'")
        self.assert_refused("jq -L lib -n '1'")

    def test_every_sed_script_is_scanned_wherever_it_sits(self):
        """A bundle ending in `e` takes the next word as a script, and `-l` takes the next
        word as a number: reading either as a file operand leaves a script unscanned."""
        self.assert_refused("sed -ne 'w PWNED' -e p AGENTS.md")
        self.assert_refused("sed -l 5 'w PWNED' AGENTS.md")
        self.assert_refused("sed -nl 5 -e 'w PWNED' AGENTS.md")

    def test_an_input_redirect_target_the_shell_computes(self):
        """The pseudo-device check reads literal text, so a target assembled at runtime is
        exactly what it cannot see."""
        self.assert_refused('x=/dev/t; y=cp/example.com/80; cat < "$x$y"')
        self.assert_refused("cat < \"/dev/\"'tcp/example.com/80'")
        self.assert_refused("cat < $f")
        self.assert_refused("cat < *.md")

    def test_a_scratch_path_spelled_so_the_shell_decides_it(self):
        """Every component has to be literal text: a quoted `..` is a placeholder by the
        time the pattern sees it, `$d` is filled in later, and `..*` is globbed."""
        with scratch_at(None):
            self.assert_refused(f'wc -l AGENTS.md > {SCRATCH}/"../../../escape.txt"')
            self.assert_refused(f"wc -l AGENTS.md > {SCRATCH}/$d")
            self.assert_refused(f"wc -l AGENTS.md > {SCRATCH}/..*")
            self.assert_refused(f"wc -l AGENTS.md > {SCRATCH}/./../escape.txt")
            self.assert_refused(
                "wc -l AGENTS.md > /tmp/claude-1000/../"
                "00000000-0000-4000-8000-000000000000/scratchpad/out"
            )

    def test_the_redirection_spellings_that_stay_refused(self):
        """Nothing here is a read or a contained write, and the scratch rule must not have
        widened the lexer's idea of what a redirection is."""
        with scratch_at(None):
            for command in (
                f"wc -l AGENTS.md >| {SCRATCH}/out.txt",
                f"cat <> {SCRATCH}/out.txt",
                f"exec 3> {SCRATCH}/out.txt",
                f"cat 2< {SCRATCH}/out.txt",
                "cat <<EOF",
                "cat <<< hi",
            ):
                with self.subTest(command=command):
                    self.assert_refused(command)


# ======================================================================================
# Part 6 -- Lexing, quoting, and where a command ends
#
# Where the classifier and bash can disagree about where one command stops and the next
# begins. The splice tables these classes use are in part 2.
# ======================================================================================


class RefusesShellSyntaxTheLexerMisreads(Verdicts, unittest.TestCase):
    """Where `shlex` and bash disagree, and bash runs the tail.

    Not variations on one bug: the causes are `shlex.commenters`, newline-as-whitespace,
    punctuation-run gluing, and a segment that is skipped instead of refused.
    """

    def test_a_hash_inside_a_word_does_not_start_a_comment(self):
        """Fix: `lexer.commenters = ""`, making `#` ordinary as it is to bash in a word."""
        self.assert_refused("wc -l AGENTS.md#; rm -rf build/", "runs rm -rf build/")
        self.assert_refused("ls#; git push origin main", "pushes")
        self.assert_refused("echo hi#>/tmp/evil", "writes through the surviving redirect")

    @open_finding("P-02", "`\\n` is in SEPARATORS but shlex never emits it as a token")
    def test_a_newline_separates_two_commands(self):
        """Every line after the first is read as arguments to the first line's program.

        Claude Code's own matcher counts a newline as a separator, so this diverges from
        the host as well as from bash.
        """
        self.assert_refused("ls\nrm -rf build/", "runs rm -rf build/")
        self.assert_refused("git log --oneline -5\ngit push", "pushes")
        self.assert_refused("ls # count them\nrm -rf build/", "runs the line after")

    @open_finding(
        "P-03",
        "a punctuation run is not an exact separator, so it lands as a word",
    )
    def test_a_separator_glued_to_the_next_token(self):
        """`punctuation_chars=True` groups `;(` into one token that matches nothing.

        `_segments` splits on an exact list and lets anything else through. The safe
        shape is the inverse: a token containing any of `();<>|&` that is not an exact
        known separator has no reading under which it is an argument.
        """
        for glue, template in PUNCTUATION_BASH_EXECUTES.items():
            with self.subTest(glue=glue):
                command = template.format(payload="rm -rf build/")
                self.assertFalse(hook.is_read_only(command), f"approved {command!r}")

    def test_a_case_body_is_a_command(self):
        """`)` and `;;` are not separators, so the body rides along in the discarded
        segment, and `checked` is still non-zero from the leading read."""
        self.assert_refused("ls; case x in *) rm -rf build/;; esac", "runs the case body")
        self.assert_refused("wc -l AGENTS.md; case $x in a) git push;; esac", "pushes")


class RefusesPunctuationThatBashWouldReject(Verdicts, unittest.TestCase):
    """The same classifier defect on strings bash refuses to parse.

    Separated from the class above because a case that cannot execute is not a bypass,
    and filing it as one inflates the finding count and hides which fixes matter.
    """

    @open_finding(
        "P-05",
        "unknown punctuation is treated as an argument, exploitable or not",
    )
    def test_the_classifier_still_should_not_approve_them(self):
        for glue, command in PUNCTUATION_BASH_REJECTS.items():
            with self.subTest(glue=glue):
                self.assertFalse(hook.is_read_only(command), f"approved {command!r}")

    @needs_bash
    def test_bash_really_does_reject_them(self):
        """The guard. If a shell upgrade starts executing one of these, this test fails
        and the case is promoted into the executable corpus."""
        with scratch_tree() as root:
            for glue, command in PUNCTUATION_BASH_REJECTS.items():
                with self.subTest(glue=glue):
                    self.assertFalse(
                        bash_produces_effect(command, root),
                        f"{command!r} now executes; move it to the executable corpus",
                    )


class ResolvesQuotingBeforeLexing(Verdicts, unittest.TestCase):
    """What is quoted is data; what is not is syntax. `shlex` cannot say which.

    `posix=True` strips quotes and returns a token identical to an unquoted one, so every
    check downstream had to treat `>` and `|` as syntax wherever they appeared. That is
    one refusal per `awk` comparison and per `sed` script whose delimiter is a pipe --
    both idioms this repository writes constantly.

    `_scan` resolves quoting first and hands the lexer a command with nothing quoted left
    in it, so a `>` that survives to the lexer is one bash will act on. Each case below
    comes in a pair: the quoted spelling that is now approved, and the unquoted one with
    the same characters that must still be refused.
    """

    def test_a_comparison_in_an_awk_program(self):
        """The over-length check every Markdown review in this repository runs."""
        self.assert_allowed(
            "awk 'length($0)>100 {printf \"%d (%d)\\n\", NR, length($0)}' 'p/t.md'",
            "`>` compares here; awk redirects only out of a print statement",
        )
        self.assert_allowed("awk 'NR>=10 {print}' 'p/t.md'", "a comparison")
        self.assert_allowed("awk '/foo|bar/ {print}' 'a.md'", "alternation, not a pipe")
        self.assert_allowed("awk -F'|' '{print $2}' 'a.md'", "a column separator, not a pipe")
        self.assert_allowed(
            "awk '{printf \"%s|%s\\n\", $1, $2}' 'a.md'", "a separator in a format string"
        )

    def test_an_awk_program_that_really_writes(self):
        """The half that matters: reading the program must not stop refusing a write."""
        self.assert_refused("awk '{print > \"PWNED\"}' a.md", "writes PWNED")
        self.assert_refused("awk 'NR>1 {print >> \"PWNED\"}' a.md", "appends to PWNED")
        self.assert_refused('awk \'{printf "%s", $0 > "PWNED"}\' a.md', "writes PWNED")
        self.assert_refused("awk '{print | \"sh\"}' a.md", "pipes into a shell")
        self.assert_refused("awk '{print |& \"sh\"}' a.md", "gawk's coprocess")
        self.assert_refused("awk 'BEGIN{system(\"touch PWNED\")}'", "runs touch")

    def test_a_quoted_redirection_is_an_argument(self):
        self.assert_allowed("grep -n '>' AGENTS.md", "searches for a character")
        self.assert_allowed('grep -n "2>&1" AGENTS.md', "searches for a redirection")
        self.assert_allowed("grep -rn 'a | b' 'docs/'", "a table row, not a pipeline")

    def test_the_same_characters_unquoted_are_still_syntax(self):
        self.assert_refused("grep -n x AGENTS.md > PWNED", "writes PWNED")
        self.assert_refused("grep -n x AGENTS.md | touch PWNED", "runs touch")

    def test_single_quotes_make_an_expansion_inert(self):
        """Bash substitutes nothing inside `'...'`, so neither does the classifier."""
        self.assert_allowed("grep -n '$(touch PWNED)' AGENTS.md", "is a literal string")
        self.assert_allowed("grep -n '${x@P}' AGENTS.md", "is a literal string")
        self.assert_allowed("grep -n '`id`' AGENTS.md", "is a literal string")

    def test_double_quotes_do_not(self):
        """The classic scanner bug: `'` inside `"..."` is a character, not a quote."""
        self.assert_refused("echo \"'$(touch PWNED)'\"", "substitutes and runs touch")
        self.assert_refused('echo "${x@P}"', "prompt expansion substitutes")
        self.assert_refused('echo "`touch PWNED`"', "a backtick still substitutes")

    def test_a_closing_paren_inside_quotes_does_not_end_a_substitution(self):
        """Counting parentheses without reading quotes ends the span early and leaves
        the rest of the body outside everything this module inspects."""
        self.assert_refused("echo $(grep -n ')' AGENTS.md; touch PWNED)", "the body runs touch")

    def test_a_line_continuation_still_joins(self):
        self.assert_allowed("wc -l \\\n    AGENTS.md", "is one command in bash too")
        self.assert_refused("wc -l AGENTS.md \\\n && touch PWNED", "runs touch")

    def test_an_unbalanced_quote_is_refused(self):
        for command in ("echo 'unbalanced", 'echo "unbalanced', "echo \\", "echo $(ls"):
            with self.subTest(command=command):
                self.assert_refused(command)


@approvals_budgeted
class RefusesQuotingBashReadsDifferently(Verdicts, unittest.TestCase):
    """Two ways to get the end of a word wrong, in the direction that costs a write.

    Resolving quoting before lexing is the right design, and
    `ResolvesQuotingBeforeLexing` covers the ordinary cases. What it does not cover is
    the two rules a hand-written resolver is most likely to get backwards:

    * inside `'...'` a backslash is an ordinary character, so `'a\\'` is a complete word
      and everything after the closing quote is syntax;
    * inside `$'...'` a backslash *is* an escape, and `\\x2f` is a slash that was not
      there before the shell expanded it.

    A resolver that honours backslashes inside `'...'` reads `echo 'a\\'; touch PWNED` as
    one quoted string and approves it. Both forms were executed; both run touch.
    """

    @open_finding(
        "Q-01",
        "a backslash inside single quotes must not escape the closing quote",
    )
    def test_a_backslash_inside_single_quotes_is_an_ordinary_character(self):
        self.assert_refused("echo 'a\\'; touch PWNED", "runs touch")
        self.assert_refused("grep -n 'a\\' AGENTS.md; rm -rf build/", "runs rm")

    @open_finding(
        "Q-02",
        "`\\\\` outside quotes is an escaped backslash, not an escaped separator",
    )
    def test_an_escaped_backslash_does_not_escape_what_follows(self):
        self.assert_refused("echo a\\\\; touch PWNED", "runs touch")
        self.assert_refused("echo a\\\\| sh", "pipes into a shell")

    def test_an_escaped_separator_really_is_one_word(self):
        """The control for Q-02, so a fix cannot be "treat every backslash as nothing".
        Bash makes `\\;` a literal semicolon in the argument list, and nothing runs."""
        with scratch_tree() as root:
            self.assertFalse(
                mutates("echo a\\; touch PWNED", root),
                "bash no longer treats `\\;` as a literal; promote this to an attack",
            )

    @open_finding(
        "Q-03",
        "`$'...'` decodes escapes, so its text is not the text in the command",
    )
    def test_ansi_c_quoting_produces_characters_that_were_not_written(self):
        """The sharpest instance is a `cd` target, where the check is a path prefix:
        `$'\\x2ftmp'` is five ordinary characters to a scanner and `/tmp` to bash."""
        for command in (
            "cd $'\\x2ftmp' && ls",
            "cd $'\\057tmp' && ls",
            "cd $'\\u002ftmp' && ls",
        ):
            with self.subTest(command=command):
                self.assert_refused(command, "lands in /tmp")

    def test_locale_translation_quoting_is_still_quoting(self):
        """`$"..."` is a double-quoted string with a translation step in front, so it
        expands exactly as `"..."` does, including substitutions."""
        self.assert_refused('echo $"$(touch PWNED)"', "substitutes and runs touch")


class RefusesMultilineQuotedText(Verdicts, unittest.TestCase):
    """Finding 1: it did not hold, and the remediation it proposed would have caused it.

    Splitting on newline before tokenizing is what the finding calls the bug. It is
    instead what keeps `ls\\nrm` from being glued into one word, which is finding P-02.

    What has changed since is which newlines reach that split. `_scan` resolves quoting
    first, so a newline inside a quoted string is a character in the table and only an
    unquoted one still separates two commands. The refusals below are now refusals of the
    command after the newline, rather than of a fragment the lexer could not balance --
    the same verdict for the reason that was meant all along.
    """

    def test_the_exploit_string_from_the_assessment(self):
        self.assert_refused("echo 'foo\n'; touch PWNED; echo '\nbar'", "would run touch")

    def test_a_newline_inside_quotes_is_text_and_not_a_separator(self):
        """Both of these are one command in bash, and neither writes anything."""
        self.assert_allowed("echo 'foo\nbar'", "the newline is inside the quotes")
        self.assert_allowed('grep -n "a\nb" AGENTS.md', "the newline is inside the quotes")

    def test_an_unquoted_newline_still_separates(self):
        self.assert_refused("echo foo\ntouch PWNED", "runs touch on the second line")

    def test_a_line_continuation_still_joins(self):
        """The one multi-line shape the repository writes: one flag per line."""
        self.assert_allowed("wc -l \\\n    AGENTS.md", "is one command in bash too")


class RefusesBraceExpansion(Verdicts, unittest.TestCase):
    """A `{a,b}` list and an `{N..M}` range are rewritten by the shell before the command
    runs, splitting one word into several, and the classifier refuses any word that still
    carries one after quoting resolves -- the same rule as for an unquoted glob.

    The hazard is clearest in operand position, which is where it used to get through:
    `cat {AGENTS,extra}.md` is one word to an operand check and two files to `cat`, the
    second placed wherever the brace says, including outside the tree. A flag can be
    rebuilt the same way (`sort -o{,}X` -> `-oX -oX`) and so can a program name
    (`{t,}ouch`), and those were already refused -- but incidentally, by the output-flag
    check and the program allowlist -- so a braced word whose pieces resolved to an
    allowlisted flag or program would have slipped past. The check below refuses the
    construct itself, in any position, so the guard no longer depends on what the pieces
    happen to spell.

    The brace-expansion grammar is finicky and was pinned against bash rather than
    assumed: a comma or a `..` inside unnested braces expands, while `{a}`, `{}` and
    `a{}b` stay literal, and `${x:-a}` is a parameter expansion whose brace does not.
    """

    def test_a_braced_operand_places_a_second_word_the_check_never_saw(self):
        """The second word is wherever the brace says, including outside the tree."""
        self.assert_refused("cat {AGENTS,extra}.md", "two operands reach cat, not one")
        self.assert_refused("head {AGENTS,../../etc/hosts}.md", "the second climbs out")

    def test_a_braced_flag_or_program_is_refused_as_the_brace_it_is(self):
        """Refused before, but by the output-flag check and the allowlist; now by the
        brace check, so a braced word resolving to an allowlisted flag cannot slip past."""
        self.assert_refused("sort -o{,}PWNED AGENTS.md", "bash passes -oPWNED twice")
        self.assert_refused("{t,}ouch PWNED", "bash runs touch")
        self.assert_refused("{r,}m build", "bash runs rm")

    def test_a_brace_range_is_expansion_too(self):
        self.assert_refused("echo a{1..3} > out", "bash expands the range into three words")
        self.assert_refused("wc -l file{1..9}.md", "nine operands, not one")

    def test_a_quoted_brace_is_one_literal_and_stays_read_only(self):
        """The control: quoting takes the brace out of the shell's hands, so these are
        single literal words and the check must not refuse them."""
        self.assert_allowed("grep -n '{a,b}' AGENTS.md", "a literal pattern, not a list")
        self.assert_allowed('echo "{a,b}"', "one literal word to bash")

    def test_a_non_expanding_brace_stays_read_only(self):
        """The other control: a brace bash does not expand must not be refused as if it
        did. A single element, an empty pair, and a parameter expansion all stay."""
        self.assert_allowed("echo {a}", "a single-element brace is literal in bash")
        self.assert_allowed('echo "${x:-a}"', "a parameter expansion, not a brace list")

    @needs_bash
    def test_the_operand_case_really_splits(self):
        """Liveness: confirm bash puts a second operand on the program, so the refusal is
        not vacuous. `cat {A,B}.md` reading two files is the observable proof it split."""
        with scratch_tree() as root:
            (Path(root) / "extra.md").write_text("LEAK\n")
            result = run_sealed("cat {AGENTS,extra}.md", root, timeout=5.0)
            self.assertIn(
                "LEAK",
                result.stdout,
                "bash did not split the brace into a second operand; the test is moot",
            )


# ======================================================================================
# Part 7 -- Expansion and substitution
#
# A substitution runs a command, and that command can be classified like any other. What
# the classifier cannot vouch for is the word the substitution produces, or a substitution
# spelled without `$(` or a backtick.
# ======================================================================================


class ApprovesCommandSubstitutionThatOnlyReads(Verdicts, unittest.TestCase):
    """A substitution runs a command, and that command can be read like any other.

    Refusing every `$(...)` cost two of the prompts this work started from, both of them
    a read-only vendor call whose output names the next one. The body is classified by
    these same rules before the word it produces is looked at, and the word itself is
    inert: `SUBSTITUTION_MARKER` is what every validator sees in its place.
    """

    def test_the_capture_that_prompted(self):
        self.assert_allowed(
            "sa=$(gcloud iam service-accounts list --project='my-project' "
            "--format='value(email)' | grep 'firebase-adminsdk'); echo \"SA: ${sa}\"",
            "every command in it only reads",
        )

    def test_the_loop_list_that_prompted(self):
        self.assert_allowed(
            "for p in $(gcloud projects list --format='value(projectId)' "
            "| grep -- '-project$'); do "
            'gcloud iam service-accounts list --project="${p}" '
            "--format='value(email)' 2>/dev/null | grep -c 'firebase-adminsdk'; done",
            "every command in it only reads",
        )

    def test_an_operand_and_a_nested_body(self):
        self.assert_allowed('head -n "$(grep -c . AGENTS.md)" AGENTS.md', "only reads")
        self.assert_allowed('echo "$(basename "$(pwd)")"', "nested, and only reads")


class RefusesCommandSubstitutionThatDoesNot(Verdicts, unittest.TestCase):
    """The body is a command; the position it sits in is a second question."""

    def test_a_body_that_is_not_read_only(self):
        for command in (
            'echo "$(rm -rf build/)"',
            "x=$(touch PWNED)",
            "for f in $(touch PWNED); do ls; done",
            "ls $(git push origin main)",
            'echo "$(gcloud projects delete my-project)"',
            "head -n \"$(sed -i 's/a/b/' AGENTS.md)\" AGENTS.md",
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_a_program_name_the_shell_builds(self):
        """The one position no recursion can vouch for: what the body prints becomes the
        program, and this module never saw it."""
        self.assert_refused("$(echo ls) -la", "the program is whatever the body printed")
        self.assert_refused("$(echo rm) -rf build/", "runs rm")
        self.assert_refused('"$(echo ls)"', "quoted makes no difference")
        self.assert_refused("$(echo l)s", "glued to a literal makes no difference")

    def test_the_substitution_spellings_that_stay_refused(self):
        self.assert_refused("echo `id`", "a backtick is never read")
        self.assert_refused("head -n 5 <(curl https://example.com)", "process substitution")
        self.assert_refused("echo $(($(id)))", "an expansion inside arithmetic")
        self.assert_refused("echo ${ id; }", "runs id on bash >= 5.3")

    def test_nesting_past_the_cap(self):
        self.assert_refused("echo $(echo $(echo $(echo $(echo $(id)))))", "nested past the cap")


class RefusesDeferredCommandSubstitution(Verdicts, unittest.TestCase):
    """Substitution spelled without `$(` or a backtick, which the substring check misses."""

    @open_finding(
        "P-06",
        "${var@P} runs command substitution on an expanded value; live on bash >= 4.4",
    )
    def test_prompt_expansion_is_command_substitution(self):
        """`@P` expands its value as a prompt string, and prompt expansion substitutes.

        The value need never appear in one command: `_strip_structure` skips assignments
        without reading them, and a Claude Code session reuses one shell, so the payload
        can be assembled across several separately-approved commands. See
        `DifferentialAcrossOneSession` for the end-to-end form.
        """
        self.assert_refused('echo "${x@P}"', "expands $(...) out of x")
        self.assert_refused("echo ${x@P}", "expands $(...) out of x")

    def test_bash_5_3_command_substitution(self):
        """Latent rather than live: bash 5.2, which Ubuntu 25.04 ships, rejects both.
        They execute after the next release upgrade."""
        self.assert_refused("echo ${ id; }", "runs id on bash >= 5.3")
        self.assert_refused("echo ${| id; }", "runs id on bash >= 5.3")


class RefusesReEvaluatingAValue(Verdicts, unittest.TestCase):
    """Expansions that evaluate a variable's value as code rather than pass it through.

    The value need not appear in the command: a session reuses one shell, so `x` can be
    set by an earlier, separately approved command. What is refused is therefore the place
    the value is evaluated, not the assignment. Commands run in zsh on this machine, so its
    forms are here alongside bash's.
    """

    def test_arithmetic_naming_a_variable(self):
        """`x='a[$(touch PWNED)]'; echo $((x))` writes, in bash and in zsh."""
        self.assert_refused("echo $((x))")
        self.assert_refused('echo "$((x + 1))"')
        self.assert_refused("echo $[x]")

    def test_a_subscript_or_offset_that_is_not_a_literal(self):
        self.assert_refused('echo "${a[x]}"')
        self.assert_refused("echo ${#a[x]}")
        self.assert_refused('echo "${PWD:x}"')
        self.assert_refused('echo "${PWD:0:x}"')
        self.assert_refused("echo $a[x]")

    def test_indirection(self):
        """`${!x}` looks up the name held in `x`, and a subscript in that name is evaluated."""
        self.assert_refused('echo "${!x}"')

    def test_zsh_flags_and_glob_substitution(self):
        """`${(e)x}` re-expands the value, command substitution included. `${~x}` globs it,
        and a zsh glob qualifier `*(e:cmd:)` runs a command."""
        self.assert_refused('echo "${(e)x}"')
        self.assert_refused("echo ${(e)x}")
        self.assert_refused('echo "${(P)x}"')
        self.assert_refused("echo ${~x}")
        self.assert_refused("echo $~x")

    def test_zsh_printf_evaluates_numeric_arguments(self):
        """zsh's `printf '%d' "$x"` is `$((x))`."""
        self.assert_refused("printf '%d\\n' \"$x\"")
        self.assert_refused("printf '%*s|\\n' \"$w\" x")
        self.assert_refused("printf '%d\\n' \"$(wc -l < AGENTS.md)\"")

    def test_what_evaluates_nothing_stays_approved(self):
        """The forms that look alike and run nothing: whole-array and literal subscripts,
        literal offsets, defaults, key listing, constant arithmetic, and numbers spelled out."""
        self.assert_allowed(
            'echo "${arr[@]}" "${#arr[@]}" "${arr[1]}" "${x:0:8}" "${x: -4}" "${x:-d}"'
        )
        self.assert_allowed('echo "${!arr[@]}" $((1 + 2))')
        self.assert_allowed("printf '%d %5.2f\\n' 42 3.14159")
        self.assert_allowed("printf '%s\\n' \"$x\"")


@approvals_budgeted
class RefusesWordsAnExpansionSupplies(Verdicts, unittest.TestCase):
    """Reading the body of a `$(...)` does not make the word it produces readable.

    The 2026-09-14 front end recurses into a substitution, classifies the body, and puts
    `SUBSTITUTION_MARKER` in its place so the validators downstream see an inert word.
    That is right for an *operand*: `head -n "$(grep -c . AGENTS.md)" AGENTS.md` reads a
    number and the number cannot hurt anyone. It is wrong everywhere a word is read as
    syntax by the program receiving it, because the marker is exactly as inert as the
    validator assumes and exactly as dangerous as whatever the body printed.

    `RefusesCommandSubstitutionThatDoesNot.test_a_program_name_the_shell_builds` covers
    the one position that was already known, the program name. These are the others. All
    three executed forms are in `EXPANSION_ATTACKS` and are re-run every time.

    The same argument applies to `${var}`, and more sharply: the body of a substitution
    is at least present in the command, and a parameter's value was set by some earlier
    command in the same shell. `DifferentialAcrossOneSession` chains that end to end.
    """

    @open_finding(
        "E-01",
        "a substitution can supply a writing flag to an allowlisted program",
    )
    def test_a_flag_from_a_substitution(self):
        self.assert_refused("sed \"$(echo -i)\" 's/one/1/' AGENTS.md", "edits AGENTS.md in place")
        self.assert_refused('sort "$(echo -o)" PWNED AGENTS.md', "writes PWNED")
        self.assert_refused('find . -name x "$(echo -delete)"', "deletes")
        self.assert_refused('uniq "$(echo AGENTS.md)" PWNED', "writes the second operand")

    @open_finding("E-02", "a substitution can supply a subcommand to a vendor validator")
    def test_a_subcommand_from_a_substitution(self):
        """`_check_git` and `_check_gcloud` decide on a positional word. A marker is not
        in the write set, which is the same as not being a write only if the marker is
        what runs, and it is not."""
        self.assert_refused('git "$(echo push)" origin main', "pushes")
        self.assert_refused('gcloud projects "$(echo delete)" x', "deletes a project")
        self.assert_refused('aws ecs "$(echo delete-cluster)" --cluster x', "deletes")

    @open_finding(
        "E-03",
        "a substitution can supply a cd target that passes the prefix check",
    )
    def test_a_cd_target_from_a_substitution(self):
        """`cd` is the one validator whose whole job is reading a path, so handing it a
        placeholder is handing it the answer it wants."""
        self.assert_refused('cd "$(echo /tmp)" && ls', "lands outside the repository")
        self.assert_refused("cd $(pwd)/../.. && ls", "the body only reads, the cd escapes")

    @open_finding(
        "E-04",
        "a parameter expansion in a flag position is a flag the hook never read",
    )
    def test_a_flag_from_a_parameter_expansion(self):
        """Unlike a substitution there is no body to recurse into: the value came from an
        earlier command in the same shell, or from the environment Claude Code was
        started with. A word that could be a flag has to be a literal."""
        for command in (
            "sed \"${o}\" 's/one/1/' AGENTS.md",
            "sed $o 's/one/1/' AGENTS.md",
            "sort ${o} AGENTS.md",
            "find . ${o}",
            "git ${o} log",
            "git log ${o}",
        ):
            with self.subTest(command=command):
                self.assert_refused(command, "the word could be a writing flag")

    def test_the_operand_idiom_the_repository_writes_is_untouched(self):
        """The guard on the fix. An expansion in an operand position is the shape many
        approved cases in this file are built from, and narrowing E-01 to flag positions
        is what keeps it."""
        self.assert_allowed(
            'head -n "$(grep -c . AGENTS.md)" AGENTS.md',
            "`ApprovesCommandSubstitutionThatOnlyReads` asserts this exact command",
        )
        self.assert_allowed("f='docs/x.md'; head -n 5 \"${f}\"", "an operand, not a flag")


# ======================================================================================
# Part 8 -- Redirection, sockets, and egress
#
# Descriptors, redirections bound to compound commands, and the harm class the mutation
# differential cannot see: data leaving the machine while the tree stays unchanged.
# ======================================================================================


class RefusesDescriptorAndSocketRedirection(Verdicts, unittest.TestCase):
    """Finding 7: it did not hold. `SAFE_REDIRECTS` matches descriptors 1 and 2 only, and
    everything it does not match reaches `_segments` as punctuation and is refused."""

    def test_a_descriptor_the_safe_pattern_does_not_cover(self):
        self.assert_refused("ls 3> PWNED", "writes PWNED on descriptor 3")
        self.assert_refused("ls 2>> PWNED", "appends to PWNED")
        self.assert_refused("ls &> PWNED", "writes both streams to PWNED")

    def test_a_socket_is_not_a_discard(self):
        self.assert_refused("exec 3<> /dev/tcp/127.0.0.1/9", "opens a socket")

    def test_the_discards_stay_approved(self):
        self.assert_allowed("ls 2>&1 > /dev/null", "merges and discards, writing nothing")
        self.assert_allowed("ls > /dev/null 2>&1", "the other order")


@approvals_budgeted
class RefusesRedirectionAttachedToACompound(Verdicts, unittest.TestCase):
    """A redirection can be bound to a group, a subshell, a loop or a conditional.

    The redirection cases in `RefusesAnythingElse` put the `>` inside a simple command,
    where a per-segment splitter is looking. These put it after `}`, after `)`, after
    `done` and after `fi` -- positions where the segment holding it has no program in it
    at all, and a splitter that skips a segment with nothing to validate skips the write.

    Every one of these was executed and every one writes.
    """

    @open_finding(
        "C-01",
        "a redirection bound to a compound command lands in an empty segment",
    )
    def test_a_redirect_after_a_group_or_a_subshell(self):
        self.assert_refused("{ ls; } > PWNED", "writes PWNED")
        self.assert_refused("{ wc -l AGENTS.md; } >> PWNED", "appends to PWNED")
        self.assert_refused("(ls) > PWNED", "writes PWNED")
        self.assert_refused("(cd docs && ls) > PWNED", "writes PWNED")

    @open_finding("C-02", "a redirection after `done` or `fi` is in the same blind spot")
    def test_a_redirect_after_a_loop_or_a_conditional(self):
        self.assert_refused("for f in a b; do echo $f; done > PWNED", "writes PWNED")
        self.assert_refused("while false; do echo x; done >> PWNED", "appends to PWNED")
        self.assert_refused("until true; do echo x; done > PWNED", "writes PWNED")
        self.assert_refused("if ls; then echo x; fi > PWNED", "writes PWNED")
        self.assert_refused("case x in a) ls;; esac > PWNED", "writes PWNED")

    @open_finding(
        "C-03",
        "an output process substitution is a command in a redirect position",
    )
    def test_a_redirect_into_a_process_substitution(self):
        """The input form, `<(...)`, is approved when its body only reads; see
        `ObservedCommandsStayApproved`. The output form is the one that runs a program
        *and* writes, and `>(` is not `$(`. `TheWideningsHaveAnEdge` asserts the same three
        commands as the edge of that widening."""
        self.assert_refused("ls > >(cat > PWNED)", "writes PWNED")
        self.assert_refused("ls > >(sh)", "runs a shell")
        self.assert_refused("wc -l AGENTS.md > >(touch PWNED)", "runs touch")

    def test_the_stderr_merging_pipe(self):
        """`|&` is one token meaning `2>&1 |`. Splitting it into `|` and `&` puts a
        background operator where bash sees none, and the tail of the pipeline where a
        splitter sees a new command."""
        self.assert_refused("ls |& cat > PWNED", "writes PWNED")
        self.assert_refused("ls |& sh", "pipes into a shell")

    def test_a_coprocess(self):
        """`coproc` backgrounds a command and leaves two descriptors open in the shell
        that outlive it, which a later approved command can write to."""
        self.assert_refused("coproc touch PWNED", "runs touch")
        self.assert_refused("coproc sh", "leaves a shell attached to the session")
        self.assert_refused("coproc CAT { cat; }", "the named form")

    def test_every_heredoc_spelling(self):
        """`RefusesAnythingElse` refuses `<<EOF` and `<<< hi`. These are the rest, and the
        body of a heredoc is text no validator in the module ever looks at.

        `<<-` strips tabs, `<<\\EOF` and the quoted forms suppress expansion; none of
        that changes what a splitter does with the delimiter word.
        """
        for command in (
            "cat <<EOF",
            "cat << EOF",
            "cat <<-EOF",
            "cat <<\\EOF",
            "cat <<'EOF'",
            'cat <<"EOF"',
            "cat <<EOF | sh",
            'wc -l <<< "$(touch PWNED)"',
        ):
            with self.subTest(command=command):
                self.assert_refused(command)


class RefusesReadsOutsideTheWorkingDirectories(Verdicts, unittest.TestCase):
    """A read is the attack when the prompt is poisoned: what a command prints lands in
    Claude's context, where the injected instruction is waiting for it.

    Two layers in the hook, tested separately because they fail separately:

    * **Layer B, credential stores, refused outright.** A short list -- `~/.aws`, `~/.ssh`,
      `~/.config/gcloud`, shell histories, `/proc/*/environ`, and so on -- checked on every
      word of every command before the operator tier runs. That ordering is the point: a
      program the module cannot read still passes on an operator rule, and `shellcheck`,
      `dig -f` and the repository's own scripts all open whatever path they are given.
    * **Layer A, the read scope.** A reader the module knows -- `cat`, `head`, `grep`, `jq`
      and the rest of `READER_SPECS` -- may only open files inside the repository, an
      `additionalDirectories` entry, or this session's scratch directory. Outside them, or
      unresolvable, falls through to the operator's own rules, which here means a prompt.

    B is a denylist and fragile the way denylists are, so it is the backstop; A is the
    boundary. A third layer belongs outside the hook entirely -- native `Read()` deny rules,
    which Claude Code evaluates even when the hook says allow -- and is configuration, not
    something this file can assert.
    """

    SCRATCH = (
        "/tmp/claude-1000/-home-user-dir1-subdir2/00000000-0000-4000-8000-000000000000/scratchpad"
    )

    def test_the_report_that_started_this(self):
        self.assert_refused(
            f"cat ~/.aws/credentials > {self.SCRATCH}/x",
            "stages a long-lived key where a later read can pick it up",
        )
        self.assert_refused("cat ~/.aws/credentials", "prints it straight into the context")

    def test_every_spelling_of_home(self):
        for command in (
            "cat ~/.ssh/id_rsa",
            'cat "$HOME/.aws/credentials"',
            "cat ${HOME}/.aws/credentials",
            'x=~/.aws/credentials; cat "$x"',
            "y=~; cat $y/.ssh/id_rsa",
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_a_credential_reached_through_any_reader_or_redirect(self):
        for command in (
            "head -n 50 ~/.config/gcloud/credentials.db",
            "grep -r key ~/.aws",
            "grep -f ~/.aws/credentials AGENTS.md",
            "jq . ~/.docker/config.json",
            "jq --rawfile k ~/.ssh/id_rsa -n '$k'",
            "sort ~/.netrc",
            "tail ~/.bash_history",
            "diff ~/.aws/credentials AGENTS.md",
            "wc -l < ~/.aws/credentials",
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_a_credential_reached_through_a_program_the_module_cannot_read(self):
        """Layer B's reason for running before the operator tier. With a rule file
        that allows the project's scripts, each is approved on its name alone."""
        with representative_rules():
            for command in (
                "scripts/check-docs.py ~/.ssh/id_rsa",
                "scripts/lint-docs.sh ~/.aws/credentials",
            ):
                with self.subTest(command=command):
                    self.assert_refused(command)

    def test_a_credential_path_the_shell_finishes(self):
        """A glob or expansion is judged by its literal prefix: if what follows could land
        in a credential store, it is refused before the shell decides."""
        for command in (
            "cat ~/.a*/cred*",
            "cat /e*/shadow",
            'for f in /etc/*; do cat "$f"; done',
            'cat "$(printf %s ~/.aws/credentials)"',
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_process_secrets(self):
        self.assert_refused("cat /proc/self/environ", "this process's environment")
        self.assert_refused("cat /proc/1/environ", "another process's environment")

    def test_reads_outside_the_tree_that_are_not_credentials(self):
        """Layer A on its own: nothing secret, and still not this module's to approve."""
        for command in (
            "cat /etc/os-release",
            "cat /sys/class/net/eth0/address",
            "cat ../../outside.txt",
            'x=/etc/os-release; cat "$x"',
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_a_path_that_cannot_be_resolved_is_not_vouched_for(self):
        """The case that makes layer A necessary: `printf '/etc/%s' shadow` never names a
        credential store literally, so layer B cannot see it. Only the refusal to vouch for
        a path built at runtime stops it."""
        self.assert_refused(
            "for f in $(printf '/etc/%s' shadow); do wc -l \"$f\"; done",
            "the list is built by a command, so f could be anything",
        )
        self.assert_refused('for f in $(ls -a); do wc -l "$f"; done', "-a lists ..")
        self.assert_refused('for f in .*; do cat "$f"; done', "may match ..")
        self.assert_refused('for f in ../*; do cat "$f"; done', "starts outside")

    def test_a_nul_byte_is_refused_rather_than_crashing(self):
        """Bash ends a string at a NUL, so the hook and bash would read different commands."""
        self.assert_refused("cat AGENTS.md\x00 ~/.aws/credentials", "bash truncates here")

    def test_reads_inside_the_scope_stay_approved(self):
        for command in (
            "cat AGENTS.md",
            "grep -n '/etc/passwd' AGENTS.md",
            "cut -d / -f 2 AGENTS.md",
            f"wc -l < {self.SCRATCH}/x",
            "diff <(sort AGENTS.md) <(sort docs/a.md)",
            'for f in $(ls); do wc -l "${f}"; done',
            'for f in docs/*.md; do head -n 3 "$f"; done',
            "f='docs/a.md'; head -n 5 \"${f}\"",
            "cat AGENTS.md > /dev/null",
        ):
            with self.subTest(command=command):
                self.assert_allowed(command)


@approvals_budgeted
class RefusesEgressThroughAnApprovedProgram(Verdicts, unittest.TestCase):
    """`DifferentialAgainstBash` can only see the working tree change.

    Everything here leaves the machine without touching it, which is the harm class
    `DifferentialAgainstBash`'s docstring names and parks. Most are refused by absence
    from the allowlist; they are asserted anyway, because the cost of a name being added
    to a pipeline-friendly allowlist should be a red run rather than a quiet capability.
    """

    def test_the_shell_pseudo_device(self):
        """`/dev/tcp` needs no program at all: bash opens the socket itself."""
        for command in (
            "cat < /dev/tcp/example.com/80",
            "exec 3<>/dev/tcp/example.com/80",
            "wc -l < /dev/tcp/example.com/80",
            "cat /dev/tcp/example.com/80",
            "cat < /dev/udp/example.com/53",
        ):
            with self.subTest(command=command):
                self.assert_refused(command, "opens a socket")

    def test_the_programs_that_exist_to_reach_the_network(self):
        for command in (
            "curl https://example.com",
            "wget https://example.com",
            "nc example.com 80",
            "ssh host id",
            "scp a host:b",
            "rsync -a . host:/",
            "ftp example.com",
            "telnet example.com 80",
            "dig example.com",
            "host example.com",
            "nslookup example.com",
            "getent hosts example.com",
            "ping -c1 example.com",
            "python3 -m http.server",
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_git_reaching_a_remote_without_writing_anything(self):
        """`ls-remote` writes no ref and still puts a URL of the caller's choosing on the
        wire, with whatever credential helper the environment provides."""
        self.assert_refused("git ls-remote https://example.com/x", "contacts a remote")


# ======================================================================================
# Part 9 -- Program identity, environment, and session state
#
# The program that runs is not always the program that was checked, and state an approved
# command sets outlives it in the shell Claude Code reuses.
# ======================================================================================


class RefusesControlOfTheEnvironmentAndTheProgram(Verdicts, unittest.TestCase):
    """The program that runs is not the program that was checked."""

    def test_an_assignment_prefix_is_not_harmless(self):
        self.assert_refused("PATH=/tmp ls", "runs /tmp/ls")
        self.assert_refused("LD_PRELOAD=/tmp/e.so ls", "loads /tmp/e.so into ls")
        self.assert_refused("BASH_ENV=/tmp/exploit.sh ls", "sources /tmp/exploit.sh")
        self.assert_refused("PYTHONPATH=/tmp ls", "repoints module resolution")
        self.assert_refused("GIT_EXTERNAL_DIFF=/tmp/x git diff HEAD~1", "runs /tmp/x per file")

    def test_a_bare_assignment_persists_in_the_session(self):
        """The segment is skipped, `checked` is still 1 from the `ls`, and the variable
        is set for everything that follows in that session."""
        self.assert_refused("ls; PATH=/tmp:/usr/bin", "repoints PATH for the session")
        self.assert_refused("ls; BASH_ENV=/tmp/x", "repoints BASH_ENV for the session")

    def test_a_basename_is_not_an_identity(self):
        """Any executable renamed to an allowlisted name is approved from anywhere on
        disk, and a `Bash(cat *)` deny rule does not match the absolute-path spelling
        either, so neither layer sees it."""
        self.assert_refused("./ls", "runs ./ls out of the working tree")
        self.assert_refused("/tmp/ls -la", "runs /tmp/ls")
        self.assert_refused("/tmp/evil/cat AGENTS.md", "is not the system cat")
        self.assert_refused("bin/grep -n x AGENTS.md", "is not the system grep")


class StripsTheWrapperTheHostStrips(Verdicts, unittest.TestCase):
    """Claude Code strips `timeout` before it matches a rule; so does this.

    `time` is a bash reserved word rather than a program, and `_strip_structure` has
    always dropped it. The others the host strips -- `nice`, `nohup`, `stdbuf`, `command`,
    `builtin` -- are left out: nothing here writes them, and `command` and `builtin` are
    already refused by name in `RefusesBuiltinsThatRunAProgram`.
    """

    def test_a_timeout_in_front_of_a_read(self):
        self.assert_allowed("timeout 90 gcloud projects list", "only reads")
        self.assert_allowed("timeout -s KILL 10 wc -l AGENTS.md", "a signal option")
        self.assert_allowed("timeout --signal=KILL 10 ls", "the attached spelling")
        self.assert_allowed("timeout -k 5 10 ls", "a kill-after option")
        self.assert_allowed("time wc -l AGENTS.md", "a reserved word")

    def test_a_timeout_in_front_of_anything_else(self):
        self.assert_refused("timeout 90 rm -rf build/", "runs rm")
        self.assert_refused("timeout 90 touch PWNED", "runs touch")
        self.assert_refused("timeout 90", "has no command to run")
        self.assert_refused("timeout", "has no command to run")
        self.assert_refused("time touch PWNED", "runs touch")


class RefusesBuiltinsThatRunAProgram(Verdicts, unittest.TestCase):
    """Finding 3: it did not hold. Every name it listed was already refused.

    `READ_ONLY` is an allowlist, so a builtin is refused by being absent rather than by
    being denied, which is why reading the file makes this look like a gap.
    """

    def test_the_indirect_execution_builtins(self):
        for command in (
            "eval 'touch PWNED'",
            "source x.sh",
            ". x.sh",
            "builtin cd tmp",
            "command touch PWNED",
            "exec touch PWNED",
            "read x",
            "[ -f a ]",
        ):
            with self.subTest(command=command):
                self.assertFalse(hook.is_read_only(command), f"approved {command!r}")


class RefusesSessionScopedEnvironmentHandover(Verdicts, unittest.TestCase):
    """Finding 2, in part.

    The two bypasses it named do not work: `path=/tmp ls` is refused because the check
    upper-cases the name, and any prefix assignment before a command is refused whatever
    the variable is. What did hold is the case it did not name -- a *bare* assignment,
    which sets a variable for the rest of the session without running anything, and so
    reaches the vendor call two commands later.
    """

    def test_a_bare_assignment_that_redirects_later_traffic(self):
        self.assert_refused("ls; http_proxy=http://x", "redirects a later aws call")
        self.assert_refused("ls; https_proxy=http://x", "redirects a later gcloud call")
        self.assert_refused("ls; no_proxy=", "un-exempts an internal host")

    def test_a_bare_assignment_that_changes_what_is_trusted(self):
        self.assert_refused("ls; curl_ca_bundle=ca.pem", "changes what TLS will accept")
        self.assert_refused("ls; ssl_cert_file=ca.pem", "changes what TLS will accept")

    def test_a_bare_assignment_that_moves_configuration(self):
        self.assert_refused("ls; HOME=tmp", "repoints ~/.aws and ~/.config/gcloud")
        self.assert_refused("ls; TMPDIR=tmp", "repoints where tools spill")

    def test_the_claims_that_did_not_hold(self):
        """Kept as regression guards: these were already refused."""
        self.assert_refused("path=/tmp ls", "the check upper-cases the name")
        self.assert_refused("http_proxy=http://x ls", "any prefix assignment is refused")

    def test_an_ordinary_loop_variable_is_still_approved(self):
        """The rule is about which names carry meaning to a later command, not about
        assignment. The logbook idiom assigns constantly."""
        self.assert_allowed('f=AGENTS.md; wc -l "${f}"', "an ordinary variable")
        self.assert_allowed("ls; r=209:222", "a bare loop bound")


@approvals_budgeted
class RefusesSessionScopedProgramDefinitions(Verdicts, unittest.TestCase):
    """Assessment finding 2, in the four shapes it did not name.

    `RefusesSessionScopedEnvironmentHandover` covers a bare `NAME=value`, on the
    reasoning that the variable reaches a later command. Every mechanism below reaches a
    later command the same way and none of them contains an assignment a `NAME=` check
    would find:

    * a function definition, which supplies a *program* rather than a value;
    * a `trap`, which needs no later command to cooperate at all -- a DEBUG trap fires
      before every subsequent one;
    * an alias plus the `shopt` that arms it in a non-interactive shell;
    * `printf -v`, which assigns with no `=` anywhere in the command, and `${name:=value}`,
      which assigns as a side effect of expanding.

    All five were executed across a two-command session; see the module docstring.
    """

    @open_finding("S-02", "a function definition supplies a program to every later command")
    def test_a_function_definition(self):
        for command in (
            "ls; f() { touch PWNED; }",
            "f() { touch PWNED; }",
            "function f { touch PWNED; }",
            "ls; ls() { touch PWNED; }",
        ):
            with self.subTest(command=command):
                self.assert_refused(command, "defines a program for the rest of the shell")

    @open_finding("S-03", "a trap runs on an event, so no later command has to cooperate")
    def test_a_trap(self):
        for command in (
            "ls; trap 'touch PWNED' DEBUG",
            "trap 'touch PWNED' EXIT",
            "ls; trap 'touch PWNED' ERR",
            "trap 'rm -rf build/' SIGINT",
        ):
            with self.subTest(command=command):
                self.assert_refused(command, "arms code that runs later")

    @open_finding("S-04", "an alias plus the shopt that arms it is two approved commands")
    def test_an_alias_and_the_option_that_arms_it(self):
        self.assert_refused("ls; alias w=touch", "renames a program for the session")
        self.assert_refused(
            "ls; shopt -s expand_aliases", "makes aliases work in a non-interactive shell"
        )
        self.assert_refused("ls; set -o allexport", "changes how later commands behave")

    @open_finding(
        "S-05",
        "an assignment with no `=`, and an assignment inside an expansion",
    )
    def test_an_assignment_a_name_equals_check_cannot_see(self):
        self.assert_refused("ls; printf -v o '%s' -i", "assigns with no `=` in the command")
        self.assert_refused("printf -v PATH '%s' /tmp", "and it reaches PATH")
        self.assert_refused('ls; echo "${o:=-i}"', "assigns as a side effect of expanding")
        self.assert_refused('echo "${o:=-i}"', "the same, standalone")
        self.assert_refused('ls; echo "${PATH:=/tmp}"', "and it reaches PATH")

    def test_the_declaration_builtins(self):
        """Not a finding: an allowlist refuses these by absence. Asserted so that adding
        `export` or `declare` to a pipeline-friendly allowlist is a red run."""
        for command in (
            "export PATH=/tmp",
            "ls; export PATH=/tmp",
            "declare -x PATH=/tmp",
            "typeset -x PATH=/tmp",
            "let x=1",
            "unset PATH",
            "ls; umask 000",
            "ls; ulimit -n 1",
            "ls; hash -p /tmp/ls ls",
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_an_ordinary_loop_variable_is_still_approved(self):
        """The guard, matching the one in `RefusesSessionScopedEnvironmentHandover`: the
        rule is about what the name reaches, not about assignment."""
        self.assert_allowed(
            'f=AGENTS.md; wc -l "${f}"',
            "`RefusesSessionScopedEnvironmentHandover` asserts this",
        )


# ======================================================================================
# Part 10 -- `cd`
#
# A `cd` is judged by where its target is, and a target can be spelled to look like
# somewhere it is not.
# ======================================================================================


class ApprovesCdInsideTheRepository(Verdicts, unittest.TestCase):
    """The project's shell rules say not to write commands this way.

    The rule stands; this is about what a slip costs. Seven of the twenty prompts that
    started this work were a `cd` to the repository root followed by reads that were
    read-only on their own -- the prompt comes from the relative `Read()` deny rules in
    the operator's user settings, which the host cannot resolve once a `cd` is in the
    command.
    """

    def test_a_target_inside_the_repository(self):
        self.assert_allowed(f"cd '{hook.REPO_ROOT}' && wc -l AGENTS.md", "the root")
        self.assert_allowed("cd docs && ls", "a directory inside it")
        self.assert_allowed("cd . && ls", "a no-op")
        self.assert_allowed(f"cd -P '{hook.REPO_ROOT}/docs' && ls", "a flag it may carry")

    def test_a_target_anywhere_else(self):
        for command in (
            "cd /tmp && ls",
            "cd /etc && cat passwd",
            "cd ~ && ls",
            "cd ../.. && ls",
            "cd - && ls",
            "cd && ls",
            'cd "${elsewhere}" && ls',
            "cd a b && ls",
            f"cd '{hook.REPO_ROOT}'/../other && ls",
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_the_rest_of_the_command_is_still_checked(self):
        self.assert_refused("cd docs && touch PWNED", "runs touch")
        self.assert_refused(f"cd '{hook.REPO_ROOT}' && rm -rf build/", "runs rm")


@approvals_budgeted
class RefusesCdTargetsThatOnlyLookInside(Verdicts, unittest.TestCase):
    """A prefix test on the written path answers a different question than "where does
    this land".

    `ApprovesCdInsideTheRepository` covers the targets that *look* outside: `/tmp`, `~`,
    `../..`, `-`, and
    a bare `cd`. These are the ones that look inside and are not: an escape the shell
    decodes (Q-03 in its `cd` position), an escape the shell computes, and an escape the
    filesystem provides.
    """

    def test_the_targets_already_refused_elsewhere_stay_refused(self):
        """One shared case, so a rewrite of the `cd` check that breaks the old contract
        fails here too rather than only in `ApprovesCdInsideTheRepository`."""
        self.assert_refused("cd /tmp && ls")
        self.assert_allowed("cd docs && ls", "`ApprovesCdInsideTheRepository` asserts this")

    @open_finding(
        "E-05",
        "a cd target that only exists after expansion is checked before it",
    )
    def test_a_target_the_shell_computes(self):
        self.assert_refused('cd "$(echo /tmp)" && ls', "lands in /tmp")
        self.assert_refused("cd $'\\x2ftmp' && ls", "lands in /tmp")
        self.assert_refused('cd "${HOME}" && ls', "lands wherever HOME points")
        self.assert_refused("cd docs/$(echo ..)/.. && ls", "climbs out")

    @unittest.skipUnless(
        os.access(hook.REPO_ROOT, os.W_OK), "needs to plant a symlink inside the repository"
    )
    def test_a_symlink_out_of_the_tree(self):
        """A textual prefix check cannot see a symlink, and `cd` follows one by default.

        The probe directory is created inside the repository and removed again, because
        the check is against `hook.REPO_ROOT` and there is nowhere else to put it. If
        this test is interrupted it leaves one empty directory named `readonly_hook_*`.
        """
        with tempfile.TemporaryDirectory(
            prefix="readonly_hook_symlink_", dir=hook.REPO_ROOT
        ) as probe:
            relative = Path(probe).relative_to(hook.REPO_ROOT)
            link = Path(probe) / "out"
            link.symlink_to(tempfile.gettempdir())
            self.assert_refused(
                f"cd '{relative}/out' && ls", "follows a symlink out of the repository"
            )


# ======================================================================================
# Part 11 -- Allowlisted programs: flags and operands
#
# Programs admitted for what they usually do, and the operand, flag spelling or predicate
# that makes them do something else.
# ======================================================================================


class RefusesAllowlistedProgramsThatWrite(Verdicts, unittest.TestCase):
    """READ_ONLY members that take an output operand or change machine state.

    One class, not two. The previous file had two with this name and lost the first.
    """

    def test_a_second_operand_can_be_an_output_file(self):
        """`uniq [INPUT [OUTPUT]]` and `xxd [infile [outfile]]` both truncate operand two.

        This is the case the shadowed class was the only home for, and the hook approves
        every spelling of it.
        """
        self.assert_refused("uniq a.md AGENTS.md", "overwrites AGENTS.md")
        self.assert_refused("xxd a.md AGENTS.md", "overwrites AGENTS.md")
        self.assert_refused("xxd -r a.hex AGENTS.md", "overwrites AGENTS.md")
        self.assert_refused("echo x | uniq - /tmp/evil", "writes /tmp/evil from the pipe")
        self.assert_refused("printf 'x' | xxd -r - /tmp/evil", "writes /tmp/evil")

    def test_writing_flags_the_table_omits(self):
        """`WRITING_FLAGS` matches `flag`, `flag=`, and attached two-character shorts.

        `-fprint0` is none of those: it starts with `-fprint` but is longer, so the
        `startswith` guard that catches `-oOUT` does not apply.
        """
        self.assert_refused("find . -name AGENTS.md -fprint0 out.bin", "writes out.bin")
        self.assert_refused("find . -name x -fprintf out.bin %p", "writes out.bin")
        self.assert_refused("find . -name x -fls out.bin", "writes out.bin")

    @unittest.skipIf(IS_MACOS, "GNU spellings; see the BSD case below")
    def test_a_program_that_changes_machine_state(self):
        self.assert_refused("date -s '2020-01-01'", "sets the system clock")
        self.assert_refused("hostname pwned", "sets the hostname")
        self.assert_refused("hostname -F /tmp/name", "sets the hostname from a file")
        self.assert_refused("file -C -m /tmp/m", "compiles a magic file to disk")

    @unittest.skipUnless(IS_MACOS, "BSD spellings")
    def test_a_program_that_changes_machine_state_bsd(self):
        self.assert_refused("date 202001010000", "sets the system clock on BSD date")
        self.assert_refused("hostname pwned", "sets the hostname")

    def test_git_read_subcommands_that_write(self):
        """Same shape as the `stash` special case the classifier already handles."""
        for command in (
            "git tag v9",
            "git tag -d v1.0",
            "git tag -f v1 HEAD~3",
            "git worktree add /tmp/w",
            "git worktree remove x",
            "git worktree prune",
        ):
            self.assert_refused(command, "mutates refs or the worktree list")

    def test_the_listing_forms_stay_approved(self):
        """The fix for A-05 must not cost the read forms."""
        self.assert_allowed("git tag -l", "listing tags only reads")
        self.assert_allowed("git worktree list", "listing worktrees only reads")


@approvals_budgeted
class RefusesWritingFlagsBundledIntoAShortOption(Verdicts, unittest.TestCase):
    """`WRITING_FLAGS` matches `-i`, `-i=value` and an attached two-character short.

    A bundle is none of those. `-ni` is a single argument whose *second* letter is the
    write flag, so a table keyed on the argument as a whole does not see it and the
    `startswith` guard that catches `-oOUT` does not fire either: `-ni` does not start
    with `-i`.

    Both cases below were executed. `sed -ni 's/one/1/p' AGENTS.md` rewrites the file and
    `sort -uo PWNED AGENTS.md` creates it.

    `TheWideningsHaveAnEdge.test_a_writing_flag_bundled_behind_another_short_flag` pins the
    `sed` half again, as the edge of letting `sed` take file operands.
    """

    @open_finding(
        "B-01",
        "a writing short flag bundled behind another short flag is not matched",
    )
    def test_sed_in_place_bundled_behind_another_flag(self):
        for command in (
            "sed -ni 's/one/1/p' AGENTS.md",
            "sed -nri 's/one/1/' AGENTS.md",
            "sed -sni 's/one/1/p' AGENTS.md",
            "sed -Ei 's/one/1/' AGENTS.md",
        ):
            with self.subTest(command=command):
                self.assert_refused(command, "edits AGENTS.md in place")

    @open_finding("B-02", "`sort -uo FILE` hides the output flag behind `-u`")
    def test_sort_output_bundled_behind_another_flag(self):
        for command in (
            "sort -uo PWNED AGENTS.md",
            "sort -buo PWNED AGENTS.md",
            "sort -rno PWNED AGENTS.md",
        ):
            with self.subTest(command=command):
                self.assert_refused(command, "writes PWNED")

    @unittest.skipIf(IS_MACOS, "GNU spellings")
    def test_the_machine_state_flags_bundle_too(self):
        """Same shape on the two programs `RefusesAllowlistedProgramsThatWrite` covers only
        unbundled. Not
        executed: `date -s` needs root and `file -C` writes a compiled magic file, and
        neither belongs in a corpus that runs."""
        self.assert_refused("date -us '2020-01-01'", "sets the system clock")
        self.assert_refused("file -Cm /tmp/m", "compiles a magic file to disk")

    def test_the_separator_does_not_help_either(self):
        """`--` ends option parsing for the program, not for the flags before it."""
        self.assert_refused("sed -ni -- 's/one/1/p' AGENTS.md", "still edits in place")
        self.assert_refused("sort -uo PWNED -- AGENTS.md", "still writes PWNED")


class RefusesOutputOperandsPastAnOptionTerminator(Verdicts, unittest.TestCase):
    """Finding 8: it did not hold, and said so itself -- `--` starts with `-`, so it is
    filtered out of the operand list and the second operand is still counted."""

    def test_the_terminator_does_not_hide_the_operand(self):
        self.assert_refused("uniq -- AGENTS.md PWNED", "PWNED is still the second operand")
        self.assert_refused("xxd -- AGENTS.md PWNED", "PWNED is still the second operand")

    def test_one_operand_stays_approved(self):
        self.assert_allowed("uniq AGENTS.md", "reads one file")
        self.assert_allowed("uniq -- AGENTS.md", "reads one file past the terminator")


class RefusesFindWritingPredicates(Verdicts, unittest.TestCase):
    """Finding 5: it did not hold. Every predicate it listed was already covered, by
    prefix rather than by exact name, which is what the reading missed."""

    def test_the_writing_and_executing_predicates(self):
        predicates = (
            "-execdir touch PWNED ;",
            "-exec touch {} +",
            "-delete",
            "-fprint PWNED",
            "-fprint0 PWNED",
            "-fprintf PWNED %p",
            "-fls PWNED",
            "-ok touch {} ;",
            "-okdir touch {} ;",
        )
        for predicate in predicates:
            with self.subTest(predicate=predicate):
                command = f"find . -name AGENTS.md {predicate}"
                self.assertFalse(hook.is_read_only(command), f"approved {command!r}")


class RefusesOutputThatIsNotInert(Verdicts, unittest.TestCase):
    """What a program that only reads still does by printing: a field wide enough to fill
    memory and Claude's context, and an escape sequence the terminal acts on. The cases
    recorded as decided are in `PolicyAlreadyDecidedToRefuse`; these are the other
    spellings, and the controls that keep the rules narrow."""

    def test_a_field_wider_than_the_cap(self):
        self.assert_refused("printf '%.99999999f' 1", "through the precision")
        self.assert_refused("printf '%*d' 99999999 1", "through a width argument")

    def test_a_terminal_escape_that_echo_or_printf_interprets(self):
        self.assert_refused("printf '\\e]8;;https://example.com\\a'", "OSC 8, spelled \\e")
        self.assert_refused("echo '\\x1b]52;c;cm9vdA==\\a'", "zsh's echo interprets it")
        self.assert_refused(
            "x='\\033]52;c;cm9vdA==\\a'; echo \"$x\"", "the value is interpreted, not the word"
        )

    def test_a_raw_control_byte_in_any_command(self):
        self.assert_refused("cat '\x1b]52;c;cm9vdA==\x07'", "a raw ESC byte anywhere")

    def test_what_stays_approved(self):
        """An escape spelled where nothing interprets it, and a width that is alignment."""
        self.assert_allowed(
            "cat AGENTS.md | sed 's/\\x1b\\[[0-9;]*m//g'", "strips colors from a help page"
        )
        self.assert_allowed("printf '%-60s|\\n' x", "a width under the cap")


# ======================================================================================
# Part 12 -- sed and awk
#
# Both write files and run programs from inside their own program text, which is where the
# classifier has to read the program rather than tokenize the command.
# ======================================================================================


class RefusesStreamEditorWrites(Verdicts, unittest.TestCase):
    """`sed` and `awk` write from inside their own program text.

    Every command here pipes its input, so the script is the only operand and the
    operand-count rule in `_check_sed` cannot be what refuses it.
    """

    def test_the_s_command_w_flag(self):
        """Both patterns anchor `w` to the start of the script or to a `;`."""
        self.assert_refused("cat a.md | sed 's/a/b/w /tmp/evil'", "writes /tmp/evil")
        self.assert_refused("cat a.md | sed 's/a/b/w/tmp/evil'", "writes with no space")
        self.assert_refused("cat a.md | sed 's/a/b/gw /tmp/evil'", "writes with flags first")

    @unittest.skipUnless(HAS_GNU_SED, "the e command is GNU-only")
    def test_the_s_command_e_flag(self):
        self.assert_refused("echo t | sed 's/.*/touch x/eg'", "executes the pattern space")
        self.assert_refused("echo t | sed 's/a/b/ge'", "executes the pattern space")

    def test_sed_reading_its_script_from_a_file(self):
        """In a pipeline there is one non-dash operand, so `len(scripts) != 1` does not
        fire, and the file can hold `w`, `r` or GNU `e`."""
        self.assert_refused("cat a.md | sed -f /tmp/p.sed", "the script is in a file")
        self.assert_refused("cat a.md | sed --file=/tmp/p.sed", "the script is in a file")
        self.assert_refused("cat a.md | sed -f/tmp/p.sed", "attached short form")

    def test_awk_program_text_in_an_attached_flag(self):
        """`--include=` is blocked and `--source=`, `--file=` and `-e` are not, though
        each names or carries a program that is never scanned."""
        self.assert_refused("gawk --source='BEGIN{system(\"id\")}'", "runs id")
        self.assert_refused("gawk -e'BEGIN{system(\"id\")}'", "runs id")
        self.assert_refused("gawk --file=/tmp/evil.awk", "runs /tmp/evil.awk")
        self.assert_refused("awk -f/tmp/script.awk", "runs /tmp/script.awk")

    def test_awk_extension_loading(self):
        """-l/--load is not in the blocked flag set, and an extension's functions are not
        in the blocked word list. Conditional on the extensions being installed; the
        point is that the denylist shape cannot cover them."""
        self.assert_refused("awk -lfilefuncs 'BEGIN{}'", "loads an extension")
        self.assert_refused("awk -l filefuncs 'BEGIN{}'", "loads an extension")
        self.assert_refused("gawk --load=filefuncs 'BEGIN{}'", "loads an extension")
        self.assert_refused(
            "gawk -l rwarray 'BEGIN{a[1]=1; writea(\"/tmp/x\", a)}'",
            "writes /tmp/x through the rwarray extension",
        )


class RefusesStreamEditorAddressForms(Verdicts, unittest.TestCase):
    """Finding 4, and the one that mattered most: it held, in eight spellings.

    The denylist it replaced looked for a command letter after `[0-9,$~+]*`, so it saw
    `1,2 w out` and `$w out` and missed every address sed also accepts. `w` writes a file
    the repository's own rules forbid the shell to touch, and `e` runs a program, so this
    was arbitrary execution behind an approved-looking `sed`.
    """

    def test_a_regexp_address_before_a_write(self):
        self.assert_refused("cat AGENTS.md | sed '/one/w PWNED'", "writes PWNED")
        self.assert_refused("cat AGENTS.md | sed '/a/,/b/w PWNED'", "writes PWNED")
        self.assert_refused("cat AGENTS.md | sed '\\%one%w PWNED'", "writes PWNED")

    def test_a_negated_address_before_a_write(self):
        self.assert_refused("cat AGENTS.md | sed '1!w PWNED'", "writes on every other line")

    def test_a_write_after_an_earlier_command(self):
        self.assert_refused("cat AGENTS.md | sed '2d;/one/w PWNED'", "writes PWNED")

    def test_the_other_file_commands(self):
        self.assert_refused("cat AGENTS.md | sed -n '/one/W PWNED'", "writes first lines")
        self.assert_refused("cat AGENTS.md | sed '/one/r AGENTS.md'", "reads a named file")
        self.assert_refused("cat AGENTS.md | sed '/one/e touch PWNED'", "runs touch")

    def test_the_spellings_the_old_denylist_did_catch(self):
        """Kept so the rewrite is a superset, not a trade."""
        self.assert_refused("cat AGENTS.md | sed '1,2 w PWNED'", "writes PWNED")
        self.assert_refused("cat AGENTS.md | sed '$w PWNED'", "writes PWNED")
        self.assert_refused("cat AGENTS.md | sed 's/one/1/w PWNED'", "writes PWNED")

    def test_a_branch_label_is_refused_rather_than_parsed(self):
        """`b`, `t`, `:` and `{}` take labels, which would need their own parser to read
        safely. Refusing costs a prompt; parsing badly costs a write."""
        self.assert_refused("cat AGENTS.md | sed ':a;N;$!ba;s/\\n/ /g'", "is not parsed")

    def test_the_transformations_the_repository_actually_writes(self):
        """The other half: the rewrite must not start prompting for ordinary work."""
        self.assert_allowed("cat AGENTS.md | sed 's/one/two/'", "transforms a stream")
        self.assert_allowed("cat AGENTS.md | sed 's/one/two/g'", "a flag is not a file")
        self.assert_allowed("cat AGENTS.md | sed -n '2,4p'", "prints a range")
        self.assert_allowed("cat AGENTS.md | sed '/one/d'", "deletes from the stream")
        self.assert_allowed("cat AGENTS.md | sed 'y/abc/xyz/'", "transliterates")
        self.assert_allowed("cat AGENTS.md | sed 's#one#two#'", "any delimiter")
        self.assert_allowed("cat AGENTS.md | sed 's/\\$$//'", "the docs range idiom")

    def test_the_ansi_stripping_one_liner(self):
        """Color codes off captured output, before it goes into a note's code fence.

        The idiom the repository will reach for often enough to pin: it names no file,
        its replacement is empty, and `g` is a flag rather than a destination.

        It needs no understanding of `[...]`: the `\\[` is an escape pair outside a class,
        and the `[0-9;]` that follows holds no `/`, so the scan finds the real delimiter
        either way. That is why this one is approved while `s/[/]//g` is not.
        """
        self.assert_allowed(
            "cat AGENTS.md | sed 's/\\x1b\\[[0-9;]*m//g'", "only transforms a stream"
        )
        self.assert_allowed("cat AGENTS.md | sed -E 's/\\x1b\\[[0-9;]*m//g'", "extended regexp too")

    def test_a_bracket_expression_holding_the_delimiter_is_refused(self):
        """The scanner does not parse `[...]`, so a `/` inside a class reads as the end
        of the pattern and the rest becomes nonsense flags. An over-refusal: it costs a
        prompt, and `s#[/]##g` is the spelling that does not.

        Teaching it about classes is not the free win it looks like. A scanner that also
        treated `\\` as an escape inside the class would skip past the `]` that closes it
        -- sed treats a backslash there as a literal, so `[\\]` is a class holding a
        backslash -- and would then find the command letter in the wrong place. On
        `/[\\]/w ev]il/d` sed reads `w` and writes a file where such a scanner reads `d`.
        Refusing the whole shape costs a prompt; parsing it halfway costs a write.
        """
        self.assert_refused("cat AGENTS.md | sed 's/[/]/-/g'", "the class holds /")
        self.assert_refused("cat AGENTS.md | sed '/[/]/d'", "a class in an address")

    def test_a_bracket_expression_cannot_hide_a_write(self):
        """The half that matters, and it holds whether or not classes are parsed."""
        self.assert_refused("cat AGENTS.md | sed 's/[]]/x/w PWNED'", "writes PWNED")
        self.assert_refused("cat AGENTS.md | sed 's/[/]/x/w PWNED'", "writes PWNED")
        self.assert_refused("cat AGENTS.md | sed '/[/]/w PWNED'", "writes PWNED")
        self.assert_refused("cat AGENTS.md | sed '/[\\]/w ev]il/d'", "writes ev]il/d")

    def test_a_delimiter_the_lexer_cannot_tell_from_a_pipe(self):
        """The over-refusal that carrying quoting through the lexer removes.

        `posix=True` strips the quotes, so the token `s|one|two|` used to be the same
        object as an unquoted one, where the trailing `|` is a pipe, and `_segments`
        refused it. `_scan` now resolves quoting before the lexer runs, so the whole
        script is one part of the table and the `|` inside it is never syntax. The
        refusing half is `test_a_real_trailing_pipe_is_still_a_pipe` below.
        """
        self.assert_allowed("cat AGENTS.md | sed 's|one|two|'", "the pipe is quoted")

    def test_a_real_trailing_pipe_is_still_a_pipe(self):
        """The same characters unquoted, where bash does pipe into the next command."""
        self.assert_refused("cat AGENTS.md | sed s|one|touch PWNED", "pipes into touch")


@approvals_budgeted
class RefusesAwkFormsThatRunOrRead(Verdicts, unittest.TestCase):
    """`getline` is the half of awk's I/O the other awk cases in this file do not reach.

    `"cmd" | getline x` runs a shell command and reads its output, with no `system` and
    no `print` anywhere in the program. It was executed: the first case below creates
    PWNED and is in `EXPANSION_ATTACKS`.
    """

    @open_finding(
        "A-10",
        '`"cmd" | getline` runs a program without `system` or `print |`',
    )
    def test_getline_from_a_command(self):
        self.assert_refused("awk 'BEGIN{\"touch PWNED\" | getline x}'", "runs touch")
        self.assert_refused("awk 'BEGIN{while ((\"id\" | getline l) > 0) print l}'", "runs id")
        self.assert_refused(
            "awk 'BEGIN{cmd = \"touch PWNED\"; cmd | getline}'", "the command is a variable"
        )
        self.assert_refused('awk \'BEGIN{print "x" |& "sh"; "sh" |& getline}\'', "a gawk coprocess")

    def test_an_include_directive_inside_the_program_text(self):
        """`--include` is blocked as a flag. The same thing spelled inside the program
        is not a flag."""
        self.assert_refused("gawk '@include \"/tmp/evil.awk\"; BEGIN{}'", "loads another program")

    def test_printf_to_a_file_in_a_begin_block(self):
        self.assert_refused(
            'awk \'BEGIN{printf "x" > "PWNED"}\'', "writes PWNED with no input at all"
        )
        self.assert_refused('awk \'BEGIN{print "x" >> "PWNED"}\'', "appends to PWNED")


# ======================================================================================
# Part 13 -- Vendor CLIs: git, aws, gcloud
#
# Per-program validators that decide on positional words. Nothing in this part is
# executed: the claims are each CLI's documented behavior, because running them would reach
# a real account or remote, or need a repository fixture the scratch tree does not provide.
# ======================================================================================


class RefusesVendorFlagsAndSubcommands(Verdicts, unittest.TestCase):
    """`_check_git`, `_check_gcloud` and `_check_aws` drop every `-` argument before they
    validate anything, and the writes are in the dropped arguments."""

    def test_a_git_global_option(self):
        self.assert_refused("git --exec-path=/tmp log", "runs /tmp/git-log")

    def test_git_pager_execution(self):
        """-O/--open-files-in-pager runs its argument with stdout on a pipe, so this is
        execution and not a tty quirk."""
        self.assert_refused("git grep -O'sh -c \"id\"' needle", "runs id through the pager")

    def test_a_git_diff_option_that_writes(self):
        self.assert_refused("git diff --output=/tmp/evil", "writes /tmp/evil")
        self.assert_refused("git log --output=/tmp/evil", "writes /tmp/evil")
        self.assert_refused("git show --output=/tmp/evil", "writes /tmp/evil")

    def test_gcloud_flag_injection(self):
        self.assert_refused(
            "gcloud --flags-file=/tmp/f projects list", "takes its flags from /tmp/f"
        )

    def test_the_gcloud_verb_is_positional(self):
        """An argument that happens to spell a read verb launders a write verb that is in
        neither set, and the write list omits `ssh`, `scp`, `call`, `submit`, `run`,
        `login`, `cp`, `rm`, `sync`, `stop` and `start`."""
        self.assert_refused(
            "gcloud pubsub topics publish list --message=x", "publishes to topic `list`"
        )
        self.assert_refused("gcloud compute ssh list --command whoami", "runs a remote command")
        self.assert_refused("gcloud functions call list --data {}", "invokes the function")
        self.assert_refused("gcloud builds submit --config list", "starts a build")
        self.assert_refused("gcloud compute instances stop list", "stops an instance")
        self.assert_refused("gcloud compute instances stop my-vm --zone list", "stops a vm")

    def test_an_aws_output_file_operand(self):
        self.assert_refused("aws s3api get-object --bucket b --key k /tmp/out", "writes /tmp/out")


class ApprovesOrdinaryOptionForms(Verdicts, unittest.TestCase):
    """The same heuristic failing in the other direction.

    Filtering `-` arguments makes an option's value an operand, which shifts the
    positions the vendor validators index into. These are read-only commands that prompt
    today. They cost a prompt rather than granting one, so they are the cheaper half, but
    a per-program table that knows which options take a value is what fixes both halves,
    which is why they belong in the same suite.
    """

    def test_a_global_option_with_a_separate_value(self):
        self.assert_allowed("aws --profile prod sts get-caller-identity", "it only reads")
        self.assert_allowed("aws --region us-east-1 ecs list-clusters", "it only reads")
        self.assert_allowed("git -C docs log --oneline -5", "the subcommand only reads")

    def test_arithmetic_expansion_is_not_command_substitution(self):
        """`$((` contains `$(`, so `echo $((1+1))` prompts. Harmless, and a sign the
        check is lexical where it needs to be structural."""
        self.assert_allowed("echo $((1+1))", "arithmetic expansion runs no command")


class RefusesGitConfigDrivenExecution(Verdicts, unittest.TestCase):
    """Finding 6: it held. A read of a checkout is an execution of its configuration.

    `-c` names a program inline, and `--ext-diff`, `--textconv` and `--filters` run
    whatever the repository's own config or `.gitattributes` names. None needs a poisoned
    repository that the agent wrote: cloning one is enough.
    """

    def test_an_inline_configuration_override(self):
        self.assert_refused("git -c diff.external=touch diff", "runs touch per file")
        self.assert_refused("git -c core.pager=touch log", "runs touch as the pager")
        self.assert_refused("git --config-env=core.pager=V log", "names a program too")

    def test_the_flags_that_run_what_the_repository_configured(self):
        self.assert_refused("git diff --ext-diff", "runs diff.external")
        self.assert_refused("git diff --textconv", "runs the configured textconv")
        self.assert_refused("git cat-file --filters HEAD", "runs the smudge filter")

    def test_the_same_flags_abbreviated(self):
        """git's option parser takes any unambiguous prefix of a long option, checked
        against git 2.48.1: `git grep --open='printf ...'` ran the printf. Each of these was
        approved while the module matched the full spelling."""
        self.assert_refused("git grep --open=vi -e x", "runs vi as the pager")
        self.assert_refused("git grep --open-f=vi -e x", "the same")
        self.assert_refused("git cat-file --textc HEAD:AGENTS.md", "runs the textconv")
        self.assert_refused("git cat-file --filt HEAD:AGENTS.md", "runs the smudge filter")

    def test_the_ordinary_forms_stay_approved(self):
        self.assert_allowed("git -C docs log --oneline -5", "-C is a directory, not config")
        self.assert_allowed("git diff --no-ext-diff", "the --no- spelling is the safe one")
        self.assert_allowed("git diff --stat AGENTS.md", "only reads")
        self.assert_allowed("git grep --text -e x", "an exact option, not --textconv")


@approvals_budgeted
class RefusesGitSubcommandsOutsideTheReadSet(Verdicts, unittest.TestCase):
    """`git` is not one program. `RefusesAnythingElse.test_git_writes` covers the dozen
    subcommands an agent writes by hand; this covers the plumbing, which is where the
    writes are quiet.

    Every claim here is git's documented behavior. None is executed: a `git` case that
    ran would need a repository to run against, and a repository inside the scratch tree
    is a different fixture than the one the rest of this file uses.
    """

    def test_the_subcommands_that_reach_a_remote(self):
        for subcommand in (
            "fetch",
            "fetch --all",
            "pull",
            "pull --rebase",
            "clone https://example.com/x .",
            "remote add o https://x",
            "remote set-url o https://x",
            "submodule update --init",
            "push --dry-run",
        ):
            with self.subTest(subcommand=subcommand):
                self.assert_refused(f"git {subcommand}", "contacts a remote and writes refs")

    def test_the_subcommands_that_rewrite_history(self):
        for subcommand in (
            "rebase main",
            "merge main",
            "cherry-pick HEAD~1",
            "revert HEAD",
            "am patch",
            "apply patch",
            "replace a b",
            "filter-branch",
            "bisect start",
        ):
            with self.subTest(subcommand=subcommand):
                self.assert_refused(f"git {subcommand}")

    @open_finding(
        "G-01",
        "the object and ref plumbing writes without a verb that reads as a write",
    )
    def test_the_object_and_ref_writers(self):
        for subcommand in (
            "update-ref refs/heads/x HEAD",
            "symbolic-ref HEAD refs/heads/x",
            "hash-object -w AGENTS.md",
            "update-index --add AGENTS.md",
            "write-tree",
            "commit-tree HEAD^{tree}",
            "mktree",
            "mktag",
            "pack-refs --all",
            "repack -a",
            "gc --prune=now",
            "prune",
            "reflog expire --expire=now",
            "notes add -m x",
            "bundle create out.bundle HEAD",
            "archive -o out.tar HEAD",
            "checkout-index -a",
            "sparse-checkout set x",
            "maintenance run",
            "rerere clear",
        ):
            with self.subTest(subcommand=subcommand):
                self.assert_refused(f"git {subcommand}")

    @open_finding("G-02", "`git config` writes unless it is asked to read")
    def test_the_configuration_writers(self):
        for subcommand in (
            "config user.name x",
            "config --global user.name x",
            "config --add core.pager touch",
            "config --unset core.pager",
            "config --edit",
            "config core.hooksPath /tmp",
        ):
            with self.subTest(subcommand=subcommand):
                self.assert_refused(f"git {subcommand}", "writes a config file")

    @open_finding("G-03", "the stash verbs `test_git_writes` stops short of")
    def test_the_remaining_stash_verbs(self):
        for subcommand in (
            "stash apply",
            "stash clear",
            "stash save x",
            "stash create",
            "stash store x",
            "stash branch b",
        ):
            with self.subTest(subcommand=subcommand):
                self.assert_refused(f"git {subcommand}", "mutates the stash or the tree")

    @open_finding(
        "G-04",
        "`--git-dir` reaches a repository whose config names programs to run",
    )
    def test_the_repository_location_overrides(self):
        """`RefusesGitConfigDrivenExecution` refuses `-c core.pager=touch`. Pointing at a
        repository that
        already carries that setting gets the same execution with no `-c` in the command,
        and a cloned repository is enough to supply one."""
        self.assert_refused("git --git-dir=/tmp/x.git log", "reads a foreign config")
        self.assert_refused("git --work-tree=/tmp status", "operates on another tree")
        self.assert_refused("git --namespace=x log", "reads another ref namespace")

    def test_submodule_foreach_runs_a_shell_command(self):
        self.assert_refused("git submodule foreach 'touch PWNED'", "runs a shell per module")
        self.assert_refused("git submodule foreach --recursive id", "runs id per module")

    def test_the_read_forms_stay_approved(self):
        """The guard on all of the above: these are asserted in `ApprovesReadOnly` too, and
        a fix that tightens `git` must not reach them."""
        self.assert_allowed("git log --oneline -5", "`ApprovesReadOnly` asserts this")


@approvals_budgeted
class RefusesAwsCallsThatWriteOrExecute(Verdicts, unittest.TestCase):
    """Documented CLI behavior, not executed: running any of these reaches an account.

    `RefusesAnythingElse` covers `create-`/`delete-` style verbs, and
    `RefusesVendorFlagsAndSubcommands` the one output operand found there. These are the
    shapes that do not look like a write: a verb that writes a *local* file, a verb that
    runs something on a remote host, input the hook never reads, a flag that changes which
    endpoint a signed request is sent to, and an option abbreviated past an exact match.
    `RefusesAwsCallsThatPrintASecret` holds the reads whose output is the harm.
    """

    def test_the_s3_transfer_verbs(self):
        for command in (
            "aws s3 cp s3://b/k out",
            "aws s3 cp out s3://b/k",
            "aws s3 sync s3://b .",
            "aws s3 mv a b",
            "aws s3 rm s3://b/k",
            "aws s3 mb s3://b",
            "aws s3 rb s3://b",
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    @open_finding("W-01", "a verb whose output operand or --outfile writes a local file")
    def test_a_verb_that_writes_a_local_file(self):
        self.assert_refused(
            "aws lambda invoke --function-name f out.json", "invokes and writes out.json"
        )
        self.assert_refused("aws configure set aws_access_key_id x", "writes ~/.aws/config")
        self.assert_refused("aws configure import --csv file://k.csv", "writes credentials")

    @open_finding("W-02", "the verbs that run a command on a remote host")
    def test_remote_execution(self):
        for command in (
            "aws ssm start-session --target i-1",
            "aws ssm send-command --document-name AWS-RunShellScript",
            "aws ecs execute-command --command /bin/sh --interactive",
            "aws ec2-instance-connect send-ssh-public-key",
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    @open_finding(
        "W-03",
        "`file://` and `--cli-input-json` name a file the hook never reads",
    )
    def test_input_the_hook_never_sees(self):
        self.assert_refused(
            "aws ec2 describe-instances --cli-input-json file:///tmp/in.json",
            "takes its whole argument list from a file",
        )
        self.assert_refused(
            "aws ec2 describe-instances --cli-input-yaml file:///tmp/in.yaml", "the same"
        )
        self.assert_refused(
            "aws ec2 describe-instances --filters file:///tmp/f.json", "reads a file"
        )

    @open_finding("W-04", "`--endpoint-url` sends a signed request wherever it is told to")
    def test_an_endpoint_the_operator_did_not_choose(self):
        """A read verb pointed at another host is still a read, and the thing it reads
        with is a credential. The counter-argument is that this is how anyone drives
        localstack -- which is what the operator rule tier is for, since a rule naming
        the endpoint is narrower than a classifier that ignores the flag."""
        self.assert_refused(
            "aws --endpoint-url http://example.com sts get-caller-identity",
            "signs a request to somewhere else",
        )
        self.assert_refused(
            "aws --ca-bundle /tmp/ca.pem sts get-caller-identity",
            "changes what TLS will accept",
        )

    def test_a_blocked_option_abbreviated(self):
        """
        The CLI takes any unambiguous prefix of a long option, checked against aws-cli 2.31.17.

        Matched exactly, `--no-verify` and `--endpoint=...` were approved, and `--endpoint`
        and `--ca-b` with a separate value were refused only because the module read the value
        as the service.
        """
        self.assert_refused("aws --no-verify sts get-caller-identity", "is --no-verify-ssl")
        self.assert_refused("aws --endpoint=http://example.com sts get-caller-identity")
        self.assert_refused("aws --ca-b /tmp/ca.pem sts get-caller-identity")
        self.assert_refused(
            'aws ssm get-parameter --cli-input-j \'{"Name": "x"}\'',
            "inline input replaces every other argument, WithDecryption included",
        )

    def test_a_write_behind_an_abbreviated_global_option(self):
        """The CLI reads a global option after the service too, so `--qu list` is a
        `--query` and the operation is the next word. Matched exactly, `list` was read as
        the operation and the terminate was approved, checked against aws-cli 2.31.17."""
        self.assert_refused(
            "aws ec2 --qu list terminate-instances --instance-ids i-1", "terminates"
        )
        self.assert_refused(
            "aws ec2 --reg get-x terminate-instances --instance-ids i-1", "the same, --region"
        )


class RefusesAwsCallsThatPrintASecret(Verdicts, unittest.TestCase):
    """Reads whose output is a credential. The cases recorded as decided are in
    `PolicyAlreadyDecidedToRefuse`; these are the siblings and spellings found while
    fixing them, and the control that keeps the `ssm` rule narrow."""

    def test_secrets_manager_and_the_credentials_file(self):
        self.assert_refused(
            "aws secretsmanager batch-get-secret-value --secret-id-list a b", "prints secrets"
        )
        self.assert_refused(
            "aws --profile p configure get aws_secret_access_key",
            "prints the long-lived secret key, past a global option",
        )

    def test_ssm_with_decryption(self):
        """Including a Secrets Manager secret through the reserved path, and the flag
        abbreviated, which the CLI accepts down to `--w`."""
        for command in (
            "aws ssm get-parameter --name /x --with-decryption",
            "aws ssm get-parameters --names /x /y --with-decryption",
            "aws ssm get-parameters-by-path --path / --recursive --with-decryption",
            "aws ssm get-parameter-history --name /x --with-decryption",
            "aws ssm get-parameter --name /aws/reference/secretsmanager/prod --with-decryption",
            "aws ssm get-parameter --name /x --with-decr",
            "aws ssm get-parameter --name /x --w",
        ):
            with self.subTest(command=command):
                self.assert_refused(command, "prints a SecureString in plain text")

    def test_ssm_reads_without_decryption_stay_approved(self):
        """Without the flag, a `SecureString` comes back as ciphertext."""
        self.assert_allowed("aws ssm get-parameter --name /x")
        self.assert_allowed("aws ssm get-parameter --name /x --no-with-decryption")


class ApprovesGcloudHelpForABlockedVerb(Verdicts, unittest.TestCase):
    """`--help` is a parse-time action, so it clears a blocked verb.

    gcloud prints the page and exits before the verb runs, which makes
    `gcloud services disable --help` as read-only as `gcloud services list`. `_check_gcloud`
    held the escape hatch below the blocked-verb set until 2026-09-13, so the only shape
    anyone writes never reached it and every `<verb> --help` refused. Nothing in the suite
    named `--help`, which is how a dead branch stayed dead.

    The cost was never a bare prompt. The hook goes silent on a refusal rather than denying,
    so the decision falls back to the per-sub-command allow rules, and the `sed` that strips
    ANSI escapes from a help page matches none of them. Refusing the gcloud head of the
    pipeline is what surfaces a prompt about its tail.
    """

    def test_the_pipeline_that_prompted(self):
        """Both spellings of the help-page idiom, in full."""
        self.assert_allowed(
            "gcloud services disable --help 2>&1 | sed 's/\\x1b\\[[0-9;]*m//g' | head -45",
            "prints a help page and exits",
        )
        self.assert_allowed(
            "gcloud beta services disable --help 2>&1 | sed 's/\\x1b\\[[0-9;]*m//g' "
            "| grep -B 2 -A 14 'bypass-dependency-service-check'",
            "prints a help page and exits",
        )

    def test_help_clears_every_blocked_verb(self):
        self.assert_allowed("gcloud services enable --help", "prints and exits")
        self.assert_allowed("gcloud projects create --help", "prints and exits")
        self.assert_allowed("gcloud compute instances delete --help", "prints and exits")
        self.assert_allowed("gcloud auth login --help", "prints and exits")

    def test_the_help_subcommand_form(self):
        """`gcloud help <group> <verb>` renders the same page through a read-only verb."""
        self.assert_allowed("gcloud help services disable", "renders a man page")
        self.assert_allowed("gcloud help projects create", "renders a man page")

    def test_help_does_not_cover_a_flags_file(self):
        """`--flags-file` is read before argument parsing, so it is not a parse-time action
        the way `--help` is, and the file it names is one the hook never sees."""
        self.assert_refused("gcloud --flags-file=/tmp/f services disable --help", "reads /tmp/f")

    def test_help_is_still_required_to_be_present(self):
        """The reorder moves the escape hatch; it does not widen it."""
        self.assert_refused("gcloud services disable my-api", "disables the service")
        self.assert_refused("gcloud projects create my-project", "creates a project")
        self.assert_refused("gcloud services disable --helpful", "not the help flag")


@approvals_budgeted
class RefusesGcloudCallsThatWriteLocallyOrExecute(Verdicts, unittest.TestCase):
    """Documented CLI behavior, not executed.

    The `_check_gcloud` cases in `RefusesVendorFlagsAndSubcommands` are about the verb
    being positional. These are about verbs whose *name* reads as a query and whose
    effect is not one.
    """

    @open_finding("V-01", "`get-credentials` reads nothing and writes a kubeconfig")
    def test_a_get_verb_that_writes(self):
        self.assert_refused(
            "gcloud container clusters get-credentials c --region us-central1",
            "writes ~/.kube/config and a credential helper entry",
        )

    def test_the_configuration_and_identity_writers(self):
        for command in (
            "gcloud config set project x",
            "gcloud config unset project",
            "gcloud config configurations create x",
            "gcloud config configurations activate x",
            "gcloud auth login",
            "gcloud auth revoke",
            "gcloud auth activate-service-account --key-file=k.json",
            "gcloud auth application-default login",
            "gcloud components install kubectl",
            "gcloud components update",
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_the_deployment_verbs(self):
        for command in (
            "gcloud run deploy s --image x",
            "gcloud app deploy",
            "gcloud functions deploy f",
            "gcloud compute scp a i:b",
            "gcloud sql connect i",
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    @open_finding("V-02", "the alpha and beta prefixes shift the verb one position right")
    def test_the_release_track_prefixes(self):
        """`gcloud beta services disable --help` is approved by
        `ApprovesGcloudHelpForABlockedVerb`, so the prefix is already handled somewhere.
        These check the write half of the same shift."""
        for command in (
            "gcloud beta projects delete x",
            "gcloud alpha projects delete x",
            "gcloud beta compute instances delete i",
            "gcloud alpha run deploy s --image x",
        ):
            with self.subTest(command=command):
                self.assert_refused(command)

    @open_finding(
        "V-03",
        "`--configuration` selects a config file that can override endpoints",
    )
    def test_a_flag_that_moves_where_the_call_goes(self):
        self.assert_refused(
            "gcloud --configuration=evil projects list",
            "a named configuration can set api_endpoint_overrides",
        )
        self.assert_refused("gcloud --account=x@y.z projects list", "runs as another identity")


class RefusesGhApiCallsThatWriteOrLeak(Verdicts, unittest.TestCase):
    """`gh api` is a generic HTTP client holding the operator's token. A GET to a REST path
    is a read; everything that changes the method, sends a body, picks the host, or prints
    the token is not. Other `gh` subcommands are the operator's rules' to grant."""

    def test_a_get_to_a_rest_path_is_approved(self):
        self.assert_allowed(
            "gh api -H 'Accept: application/vnd.github.raw+json' repos/o/r/contents/x.sh"
        )
        self.assert_allowed("gh api --paginate repos/o/r/commits --jq '.[].sha'")
        self.assert_allowed("gh api -f q=x -X GET search/code")

    def test_a_method_other_than_get(self):
        self.assert_refused("gh api repos/o/r -X DELETE")
        self.assert_refused("gh api repos/o/r --method=PATCH")
        self.assert_refused("gh api -X GET search/code -f q=x -X POST", "the last -X wins")
        self.assert_refused("gh api -iX DELETE repos/o/r", "a bundle is not guessed at")

    def test_a_body_without_an_explicit_get(self):
        """A field turns the default method into POST."""
        self.assert_refused("gh api repos/o/r/issues -f title=x")
        self.assert_refused("gh api repos/o/r/issues --raw-field title=x")
        self.assert_refused("gh api repos/o/r/issues --input body.json")

    def test_a_field_read_from_a_file(self):
        """`@path` sends the file's contents to GitHub, even as a query parameter."""
        self.assert_refused("gh api -X GET search/code -F q=@AGENTS.md")
        self.assert_refused("gh api -X GET search/code --field q=@-")

    def test_another_host_or_a_non_rest_endpoint(self):
        self.assert_refused("gh api https://example.com/x")
        self.assert_refused("gh api --hostname example.com repos/o/r")
        self.assert_refused("gh api graphql -f query='{viewer{login}}'", "mutations live here")

    def test_what_can_print_or_override(self):
        self.assert_refused("gh api -H 'X-HTTP-Method-Override: DELETE' repos/o/r")
        self.assert_refused("gh api repos/o/r --jq 'env'", "gh's jq reads the environment")
        self.assert_refused("gh api repos/o/r --verbose", "prints the request, token included")

    def test_help_and_a_scheme_relative_endpoint(self):
        """Merged from the parallel validator. `--help` sends nothing and is the call that first
        prompted; `//host/path` is refused whichever way gh reads it."""
        self.assert_allowed("gh api --help", "prints help, no request")
        self.assert_refused("gh api //evil.example/x", "no REST path begins with //")
        self.assert_refused(
            "gh api --help repos/o/r -X DELETE", "help only when it is all there is"
        )

    def test_other_subcommands_are_left_to_the_rules(self):
        """No opinion, so a rule can still grant them, as before `gh` had a validator."""
        with self.assertRaises(hook.NoOpinion):
            hook._classify("gh issue view 6 -R o/r --json title")
        with operator_rules(allow=["Bash(gh issue view *)"]):
            self.assert_allowed("gh issue view 6 -R o/r --json title")


# ======================================================================================
# Part 14 -- The operator's own rules: the second tier
#
# What `.claude/settings.local.json` already grants, made to survive compounding. The rest
# of the file runs with this tier switched off (part 1); these classes turn it back on.
# ======================================================================================


class OperatorRules(Verdicts, unittest.TestCase):
    """What `.claude/settings.local.json` already grants, made to survive compounding.

    The safety argument is one sentence: every command this tier approves is one Claude
    Code would run with no prompt if it stood on its own, and the host requires each
    sub-command of a compound to match a rule independently, which is what `_classify`
    does with these. It is not a way to grant anything new.

    Each test writes its own rule file, because asserting against whatever the operator
    saved last is asserting against a moving target; `ARepresentativeRuleFile` is the
    class that reads one shaped like a real file.
    """

    def test_a_rule_supplies_a_program_the_module_does_not_know(self):
        with operator_rules(allow=["Bash(gh issue list *)"]):
            self.assert_allowed("gh issue list --repo org-slug/repo-name --state all")
            self.assert_allowed(
                "printf '=== issues ===\\n'; gh issue list --repo org-slug/repo-name "
                "--limit 400 --json number,title 2>&1 | grep -iE 'key|secret'",
                "the rule covers the one segment the classifier cannot read",
            )

    def test_a_rule_covers_only_what_it_says(self):
        with operator_rules(allow=["Bash(gh issue list *)"]):
            self.assert_refused("gh pr merge 1", "no rule covers it")
            self.assert_refused("gh issue delete 1", "no rule covers it")
            self.assert_refused("ls; gh pr merge 1", "no rule covers the second segment")

    def test_a_rule_cannot_overrule_a_finding(self):
        """A validator that read the command and found a write keeps its verdict. This is
        the one place the tier is deliberately stricter than the host, which would run
        all of these on the strength of the rule alone."""
        with operator_rules(allow=["Bash(git diff *)", "Bash(sed *)", "Bash(find *)"]):
            self.assert_refused("git diff --output=PWNED", "writes PWNED")
            self.assert_refused("sed -i 's/a/b/' AGENTS.md", "edits in place")
            self.assert_refused("find . -name x -delete", "deletes")

    def test_a_deny_rule_refuses_whatever_else_matches(self):
        with operator_rules(allow=["Bash(ls *)"], deny=["Bash(ls *)"]):
            self.assert_refused("ls -la", "a deny rule matches")
        with operator_rules(deny=["Bash(wc *)"]):
            self.assert_refused("wc -l AGENTS.md", "a deny rule beats the classifier")
            self.assert_refused("cat AGENTS.md | wc -l", "in any segment")

    def test_a_blanket_allow_rule_is_not_honored(self):
        """`Bash(*)` grants everything, and a hook that reads it silently is not how an
        operator should end up there. A blanket deny keeps its reach."""
        with operator_rules(allow=["Bash(*)"]):
            self.assert_refused("touch PWNED", "a blanket rule is not read")
        with operator_rules(deny=["Bash(*)"]):
            self.assert_refused("wc -l AGENTS.md", "a blanket deny is")

    def test_quoting_is_not_part_of_the_match(self):
        """The text a segment is matched against has been through the lexer, so the rule
        and the command differ by their quotes alone."""
        with operator_rules(allow=["Bash(firebase database:get '/.settings/rules' *)"]):
            self.assert_allowed("firebase database:get '/.settings/rules' --project x")
            self.assert_allowed('firebase database:get "/.settings/rules" --project x')

    def test_a_rule_reaches_inside_a_substitution(self):
        with operator_rules(allow=["Bash(gh issue list *)"]):
            self.assert_allowed("n=$(gh issue list --repo x --json number)")
        with operator_rules():
            self.assert_refused("n=$(gh issue list --repo x --json number)")

    def test_no_rule_file_leaves_the_classifier_alone(self):
        with settings_at(Path(tempfile.gettempdir()) / "no-such-file"):
            self.assert_allowed("wc -l AGENTS.md", "the classifier still decides")
            self.assert_refused("gh issue list --repo x", "and nothing else does")

    def test_a_malformed_rule_file_is_not_a_crash(self):
        with tempfile.TemporaryDirectory(prefix="readonly_hook_rules_") as directory:
            path = Path(directory) / "settings.local.json"
            for content in ("{", "[]", "null", '{"permissions": "no"}', ""):
                path.write_text(content)
                with settings_at(path), self.subTest(content=content):
                    self.assert_allowed("wc -l AGENTS.md")
                    self.assert_refused("gh issue list --repo x")


@approvals_budgeted
class OperatorRuleFileRobustness(Verdicts, unittest.TestCase):
    """`.claude/settings.local.json` is operator-controlled and *agent-written*: Claude
    Code appends to it whenever someone clicks "always allow".

    `OperatorRules.test_a_malformed_rule_file_is_not_a_crash` checks that five malformed
    documents do not crash. These are the
    shapes that do something worse than crash -- block, or take unbounded time -- plus
    the rule entries a permissive reader might act on.
    """

    def test_a_settings_path_that_is_a_directory(self):
        with (
            tempfile.TemporaryDirectory(prefix="readonly_hook_rules_") as directory,
            settings_at(directory),
        ):
            self.assert_refused("gh issue list --repo x", "no rule can be read")

    def test_rule_entries_that_are_not_strings(self):
        document = {
            "permissions": {
                "allow": [1, None, {"a": 1}, ["Bash(ls *)"], "Bash(ls *)"],
                "deny": [None, 2],
            }
        }
        with tempfile.TemporaryDirectory(prefix="readonly_hook_rules_") as directory:
            path = Path(directory) / "settings.local.json"
            path.write_text(json.dumps(document))
            with settings_at(path):
                self.assert_refused("gh issue list --repo x", "no rule covers it")

    def test_rules_for_other_tools_are_not_bash_rules(self):
        document = {
            "permissions": {
                "allow": [
                    "Read(//tmp/**)",
                    "WebFetch(domain:x)",
                    "Bash",
                    "Bash()",
                    "",
                    "bash(ls *)",
                ]
            }
        }
        with tempfile.TemporaryDirectory(prefix="readonly_hook_rules_") as directory:
            path = Path(directory) / "settings.local.json"
            path.write_text(json.dumps(document))
            with settings_at(path):
                self.assert_refused("gh issue list --repo x", "none of these is a Bash rule")
                self.assert_refused("touch PWNED", "and none of them grants a write")

    def test_a_deeply_nested_document(self):
        """`json.loads` raises `RecursionError` past about a thousand levels, which is an
        exception a handler written for `JSONDecodeError` and `OSError` does not catch."""
        with tempfile.TemporaryDirectory(prefix="readonly_hook_rules_") as directory:
            path = Path(directory) / "settings.local.json"
            path.write_text("[" * 200_000 + "]" * 200_000)
            with settings_at(path):
                self.assertIsInstance(hook.is_read_only("wc -l AGENTS.md"), bool)

    def test_an_enormous_document(self):
        with tempfile.TemporaryDirectory(prefix="readonly_hook_rules_") as directory:
            path = Path(directory) / "settings.local.json"
            padding = "x" * 1_000_000
            path.write_text(json.dumps({"permissions": {"allow": ["Bash(ls *)"]}, "note": padding}))
            with settings_at(path):
                started = time.monotonic()
                hook.is_read_only("wc -l AGENTS.md")
                self.assertLess(time.monotonic() - started, 5.0, "reading the file is slow")


class ARepresentativeRuleFile(Verdicts, unittest.TestCase):
    """The class that reads a rule file shaped like a real one, so the parsing and the
    composition stay in step with what operators actually save.

    The file is `REPRESENTATIVE_RULES`, written to a scratch directory: nothing here
    depends on the checkout having a `.claude/settings.local.json`."""

    def test_the_file_parses_and_carries_bash_rules(self):
        with operator_rules(**REPRESENTATIVE_RULES):
            allow, deny = hook._operator_rules()
        self.assertEqual(len(allow), len(REPRESENTATIVE_RULES["allow"]), "allow rules read")
        self.assertEqual(len(deny), len(REPRESENTATIVE_RULES["deny"]), "deny rules read")

    def test_the_three_checkers_compose(self):
        """The chain from the notes: three allow-ruled scripts and a `sed` that strips
        ANSI escapes, which matched no rule and so prompted for the whole chain."""
        with operator_rules(**REPRESENTATIVE_RULES):
            self.assert_allowed(
                "scripts/check-docs.py 'docs/a.md'; echo '=== EC ==='; "
                "scripts/check-format.sh 'docs/a.md' 2>&1 "
                "| sed 's/\\x1b\\[[0-9;]*m//g' | grep -v 'line too long'; "
                "echo '=== ML ==='; scripts/lint-docs.sh 'docs/a.md' 2>&1 "
                "| grep -v 'MD010' | head -20"
            )

    def test_a_write_capable_grant_composes_too(self):
        """Recorded rather than discovered later: a rule that covers a write composes
        like any other, because the tier's rule is "no more than standalone" and the
        host would run this one on the rule alone. Drop the rule to drop the effect."""
        with operator_rules(**REPRESENTATIVE_RULES):
            self.assert_allowed("ls; touch tmp", "the operator granted `Bash(touch *)`")

    def test_the_deny_list_still_wins(self):
        with operator_rules(**REPRESENTATIVE_RULES):
            self.assert_refused("cat a.md | tee b.md", "`Bash(tee *)` is denied")
            self.assert_refused("git add .", "`Bash(git add *)` is denied")


# ======================================================================================
# Part 15 -- The classifier as a function
#
# Properties of `is_read_only` itself: deterministic, free of side effects, total over
# arbitrary text, and bounded in time. A crash or a stall is not a bypass, but it is a hook
# that has stopped deciding.
# ======================================================================================


@approvals_budgeted
class TheClassifierIsAPureFunction(Verdicts, unittest.TestCase):
    """Properties that hold for any correct implementation, asserted so a refactor that
    introduces a cache, a global, or a dependency on the working directory is a red run
    rather than a Tuesday.
    """

    PROBES = REFUSED_SEEDS + ALLOWED_SEEDS + EXECUTED_ATTACKS

    def test_it_returns_a_bool(self):
        for command in self.PROBES:
            with self.subTest(command=command[:50]):
                self.assertIsInstance(hook.is_read_only(command), bool)

    def test_it_is_deterministic(self):
        """Including when the two calls are interleaved with a different command, which
        is what a cache keyed on something other than the command would break."""
        for command in self.PROBES:
            with self.subTest(command=command[:50]):
                first = hook.is_read_only(command)
                hook.is_read_only("wc -l AGENTS.md")
                hook.is_read_only("rm -rf build/")
                self.assertEqual(first, hook.is_read_only(command))

    def test_it_does_not_mutate_the_environment(self):
        before = dict(os.environ)
        for command in self.PROBES:
            hook.is_read_only(command)
        self.assertEqual(before, dict(os.environ))

    def test_a_refusal_does_not_depend_on_the_working_directory(self):
        """A relative path means something different from somewhere else, so approvals
        are allowed to move. A refusal is not: whatever made it unsafe is in the string."""
        previous = os.getcwd()
        refused = [c for c in self.PROBES if not hook.is_read_only(c)]
        try:
            os.chdir(tempfile.gettempdir())
            for command in refused:
                with self.subTest(command=command[:50]):
                    self.assert_refused(command, "it was refused from the repository root")
        finally:
            os.chdir(previous)

    def test_it_does_not_raise_on_arbitrary_text(self):
        """A raise is not a bypass -- `main` catches it and the call prompts -- but it is
        a hook that stopped deciding, and the input is attacker-influenced text."""
        generator = random.Random(20260914)
        alphabet = "abc '\"\\`$(){}[]<>|&;#\n\t\r\x00\x01/-=*?!~^%@:,.\u00e9\u4e2d\U0001f600"
        for index in range(400):
            command = "".join(generator.choice(alphabet) for _ in range(generator.randint(0, 40)))
            with self.subTest(index=index):
                try:
                    self.assertIsInstance(hook.is_read_only(command), bool)
                except Exception as exc:  # noqa: BLE001 -- the point is to catch anything
                    self.fail(f"is_read_only({command!r}) raised {exc!r}")


class SurvivesPathologicalInput(Verdicts, unittest.TestCase):
    """The scanner walks the command character by character and recurses on nesting.

    A crash is not a bypass -- `main` catches everything and falls through to the prompt
    -- but it is a hook that has stopped deciding anything, and a slow one holds the Bash
    call for as long as it runs. Each of these is refused, quickly, rather than either.
    """

    def test_nesting_deeper_than_the_stack(self):
        self.assert_refused("echo " + "$(" * 900 + "id" + ")" * 900)
        self.assert_refused("echo " + "$(" * 900 + "id")

    def test_unbalanced_quoting_in_bulk(self):
        self.assert_refused("ls " + '"' * 999)
        self.assert_refused("ls " + "'" * 999)

    def test_a_forged_placeholder(self):
        """The reduced command means nothing if a command can spell a placeholder."""
        self.assert_refused("echo \x011\x01; touch PWNED", "contains the placeholder mark")

    def test_it_stays_fast(self):
        started = time.monotonic()
        for command in (
            "echo " + "$(" * 500 + "id" + ")" * 500,
            "echo " + "'a'" * 2_000,
            "ls " + '"' * 999,
        ):
            hook.is_read_only(command)
        self.assertLess(time.monotonic() - started, 2.0, "the scanner is too slow")


class CostsBoundedTime(unittest.TestCase):
    """The classifier runs before every Bash call, so its own cost is a budget.

    A timed-out command hook is canceled and renders no decision, so this is latency and
    not a bypass -- but the PreToolUse command-hook default is 600 seconds, which is a
    long time to sit on a stalled Bash call.
    """

    @staticmethod
    def _classify_cost(spaces: int, repeats: int = 3) -> float:
        command = "sed '" + " " * spaces + "x'"
        best = float("inf")
        for _ in range(repeats):
            started = time.monotonic()
            hook.is_read_only(command)
            best = min(best, time.monotonic() - started)
        return best

    def test_the_sed_script_scan_grows_linearly(self):
        """A ratio, not a wall clock, so a loaded CI box does not decide the verdict.

        Measured on the current code the ratio is ~4.0 per doubling: 8k 0.29s, 16k 1.14s,
        32k 4.52s. Linear would be ~2.0; the threshold below leaves room for noise.
        """
        small = self._classify_cost(8_000)
        large = self._classify_cost(16_000)
        ratio = large / max(small, 1e-6)
        self.assertLess(ratio, 2.5, f"doubling the script multiplied the cost by {ratio:.1f}")


# ======================================================================================
# Part 16 -- Differential: ask bash instead of modeling it
#
# Run what the classifier approved and look for an effect in the scratch tree. These are
# the checks that survive a rewrite of the parser.
# ======================================================================================


@needs_bash
class DifferentialAgainstBash(unittest.TestCase):
    """Run what was approved; see whether it wrote.

    This is the check that survives a rewrite of the parser, for the one harm class it
    can see: mutation of the scratch tree. It cannot see credential disclosure, network
    egress, remote-side mutation or a hijacked environment. Those have their own classes.
    """

    CONTROLS = (
        "wc -l AGENTS.md",
        "cat AGENTS.md | head -n 1",
        "ls -la",
        # The other direction for the 2026-09-14 front end: bash really does parse these
        # the way the classifier read them, and running them changes nothing. A shape
        # approved on a misreading would either fail to parse here or leave a mark.
        "awk 'length($0)>0 {printf \"%d (%d)\\n\", NR, length($0)}' AGENTS.md",
        "awk '{printf \"%s|%s\\n\", NR, $1}' AGENTS.md",
        "cat AGENTS.md | sed 's|one|two|'",
        'x=$(grep -c . AGENTS.md); echo "lines: ${x}"',
        'for f in $(ls); do wc -l "${f}"; done',
        'head -n "$(grep -c . AGENTS.md)" AGENTS.md',
        "grep -n '$(touch PWNED)' AGENTS.md; grep -n '>' AGENTS.md",
        "timeout 5 wc -l AGENTS.md",
        "cd . && ls",
        "echo 'foo\nbar'",
    )

    BASE_ATTACKS = (
        "wc -l AGENTS.md#; touch PWNED",
        "echo hi#>PWNED",
        "ls\ntouch PWNED",
        "ls; case x in *) touch PWNED;; esac",
        "uniq AGENTS.md PWNED",
        "xxd AGENTS.md PWNED",
        "cat AGENTS.md | sed 's/one/two/w PWNED'",
        # Finding 4, the address forms the old denylist walked past. These are the ones
        # worth executing rather than only classifying: each writes a real file, so if
        # the classifier ever approves one again, the tree changes and this says so.
        "cat AGENTS.md | sed '/one/w PWNED'",
        "cat AGENTS.md | sed '/one/,/two/w PWNED'",
        "cat AGENTS.md | sed '2d;/one/w PWNED'",
        "cat AGENTS.md | sed '1!w PWNED'",
        "cat AGENTS.md | sed '\\%one%w PWNED'",
        "cat AGENTS.md | sed -n '/one/W PWNED'",
        # The front end rewritten 2026-09-14: quoting resolved before the lexer, and
        # `$(...)` recursed into rather than refused on sight. Each of these is a shape a
        # scanner that reads quoting badly approves, and bash then executes -- the `'`
        # inside `"..."` most of all, which is a character there and not a quote.
        "echo \"'$(touch PWNED)'\"",
        "echo $(grep -n ')' AGENTS.md; touch PWNED)",
        "x=$(touch PWNED)",
        "for i in $(touch PWNED); do ls; done",
        "$(echo touch) PWNED",
        'head -n "$(touch PWNED)" AGENTS.md',
        "awk '{print > \"PWNED\"}' AGENTS.md",
        'awk \'length($0)>0 {printf "%s", $0 > "PWNED"}\' AGENTS.md',
        'awk \'{print | "sh -c \\"touch PWNED\\""}\' AGENTS.md',
        "timeout 5 touch PWNED",
        "cd . && touch PWNED",
        "grep -c . AGENTS.md > PWNED",
        # Arithmetic evaluates a variable's value, and the subscript in it
        # runs the substitution: see `RefusesReEvaluatingAValue`.
        "x='a[$(touch PWNED)]'; echo $((x))",
        "x='a[$(touch PWNED)]'; a=(1); echo \"${a[x]}\"",
        "x='a[$(touch PWNED)]'; echo \"${PWD:x}\"",
        "sed -ne 'w PWNED' -e p AGENTS.md",
    ) + (
        # `e` is GNU sed's execute command, and the only entry here that runs a program
        ("cat AGENTS.md | sed '/one/e touch PWNED'",) if HAS_GNU_SED else ()
    )

    # The splices, built from the same table the classifier test uses so the two cannot
    # drift apart.
    ATTACKS = (
        BASE_ATTACKS
        + tuple(
            template.format(payload="touch " + PAYLOAD_MARKER)
            for template in PUNCTUATION_BASH_EXECUTES.values()
        )
        + (("find . -name AGENTS.md -fprint0 PWNED",) if HAS_GNU_FIND else ())
        + (("gawk --source='BEGIN{system(\"touch PWNED\")}'",) if HAS_GAWK else ())
    )

    def test_controls_stay_clean(self):
        """If a control mutates the tree the harness is broken, not the hook."""
        with scratch_tree() as root:
            for command in self.CONTROLS:
                with self.subTest(command=command):
                    self.assertTrue(hook.is_read_only(command))
                    before = snapshot(root)
                    run_in_bash(command, root)
                    self.assertEqual(before, snapshot(root))

    def test_no_approved_command_mutates_the_tree(self):
        """Collected rather than sub-tested, so the finding is one entry with a list.

        A command the classifier refuses is skipped: it prompts, which is the outcome
        under test. When every entry is refused this test passes, unittest reports an
        unexpected success, and the decorator comes off.
        """
        escaped: list[str] = []
        for command in self.ATTACKS:
            if not hook.is_read_only(command):
                continue
            with scratch_tree() as root:
                before = snapshot(root)
                try:
                    run_in_bash(command, root)
                except subprocess.TimeoutExpired:
                    escaped.append(f"{command!r} did not terminate")
                    continue
                if snapshot(root) != before:
                    escaped.append(f"{command!r} changed the working tree")
        self.assertEqual([], escaped, "approved and mutating:\n  " + "\n  ".join(escaped))


@needs_bash
class DifferentialWithAPlantedProgram(unittest.TestCase):
    """The program-identity findings, executed rather than argued.

    The planted executable lives inside the scratch tree, so nothing here depends on or
    touches anything outside it. `PATH_ATTACKS` name the plant by a path or a PATH
    prefix; `SPELLING_ATTACKS` are the spellings of "not the system program" that do not
    start with `./` or `bin/`.
    """

    # Paths and a PATH prefix that reach an `ls` planted at the root and under `bin/`.
    PATH_ATTACKS = (
        "./ls",
        "bin/ls",
        "PATH=bin ls",
    )

    # Spellings of a program name that are not a plain word. Run with `.` on PATH and
    # an `ls` planted inside the scratch tree, so each resolves to the plant or to nothing.
    SPELLING_ATTACKS = ("l?", "l*", "$'ls'", '"ls"', "l''s", "\\ls")

    def test_an_allowlisted_name_is_not_an_allowlisted_program(self):
        escaped: list[str] = []
        for command in self.PATH_ATTACKS:
            if not hook.is_read_only(command):
                continue
            with scratch_tree() as root:
                plant_executable(root, "ls", f"touch {PAYLOAD_MARKER}")
                plant_executable(root, "bin/ls", f"touch {PAYLOAD_MARKER}")
                before = snapshot(root)
                run_in_bash(command, root)
                if snapshot(root) != before:
                    escaped.append(f"{command!r} ran the planted program")
        self.assertEqual([], escaped, "approved and hijacked:\n  " + "\n  ".join(escaped))

    def test_a_program_name_that_is_not_a_plain_word(self):
        """A quoted or globbed program name is the same program to bash and a different
        token to a lexer that resolved quoting into a bare word. The planted `ls` is what
        every one of these resolves to inside the scratch tree, because `.` is prepended
        to PATH only by the command itself where it needs to be.
        """
        escaped: list[str] = []
        for command in self.SPELLING_ATTACKS:
            if not hook.is_read_only(command):
                continue
            with scratch_tree() as root:
                plant_executable(root, "ls", f"touch {PAYLOAD_MARKER}")
                before = snapshot(root)
                run_sealed(f"PATH=.:$PATH; {command}", root)
                if snapshot(root) != before:
                    escaped.append(f"{command!r} ran the planted program")
        self.assertEqual([], escaped, "approved and hijacked:\n  " + "\n  ".join(escaped))


@needs_bash
@needs_bash_44
class DifferentialAcrossOneSession(unittest.TestCase):
    """Claude Code reuses one shell, so state an approved command sets outlives it.

    No single command in a chain has to be dangerous for the chain to be, which is why
    classifying commands one at a time is not sufficient even with a correct parser.

    A chain runs only if every link is approved, so each is inert until the findings it
    exercises are live: P-06 for the `@P` chain, S-02 through S-05 and E-04 for the rest.
    `CorpusIsSafeToExecute.test_every_session_chain_really_mutates_the_tree` runs every
    chain regardless, so a chain that has stopped working is reported as a broken fixture
    rather than as a clean run.
    """

    CHAINS = SESSION_CHAINS

    def test_a_chain_of_approved_commands_leaves_the_tree_alone(self):
        escaped: list[str] = []
        for description, chain in self.CHAINS:
            if any(not hook.is_read_only(c) for c in chain):
                continue  # the chain is broken: at least one link prompts
            with scratch_tree() as root:
                before = snapshot(root)
                try:
                    run_session(chain, root)
                except subprocess.TimeoutExpired:
                    escaped.append(f"{description}: did not terminate")
                    continue
                if snapshot(root) != before:
                    escaped.append(f"{description}: changed the working tree")
        self.assertEqual([], escaped, "approved chains:\n  " + "\n  ".join(escaped))


# Programs a harvested command may name and still be safe to run here: no network, no
# vendor account, no repository state, nothing that writes outside the scratch tree on
# its own. Anything naming something else is classified but not executed.
LOCALLY_EXECUTABLE = frozenset(
    {
        "awk",
        "basename",
        "cat",
        "cd",
        "cmp",
        "column",
        "comm",
        "cut",
        "dirname",
        "du",
        "echo",
        "egrep",
        "false",
        "fgrep",
        "find",
        "grep",
        "head",
        "id",
        "join",
        "ls",
        "md5sum",
        "nl",
        "od",
        "paste",
        "printf",
        "pwd",
        "readlink",
        "realpath",
        "rev",
        "sed",
        "sha1sum",
        "sha256sum",
        "sort",
        "stat",
        "tac",
        "tail",
        "test",
        "timeout",
        "tr",
        "true",
        "uname",
        "uniq",
        "wc",
        "which",
        "whoami",
        "xxd",
        "for",
        "do",
        "done",
        "if",
        "then",
        "fi",
        "while",
        "until",
        "case",
        "esac",
        "time",
    }
)

NOT_LOCALLY_EXECUTABLE = (
    "gcloud",
    "aws",
    "gh",
    "firebase",
    "git",
    "curl",
    "wget",
    "scripts/",
    "python3",
    "node",
    "perl",
    "npm",
    "sudo",
    "ssh",
)


@needs_bash
class DifferentialOverTheSuitesOwnApprovals(unittest.TestCase):
    """`DifferentialAgainstBash` executes a hand-picked set of controls. This file
    asserts that far more commands than that are approved, and an approval asserted in a
    test is an approval the hook grants in production.

    This harvests every `assert_allowed` literal from this file, keeps the ones that can
    run without an account or a network, and runs them. It is the cheapest way to turn
    "we think this is read-only" into "we ran it and the tree did not change".
    """

    @staticmethod
    def harvested() -> list[str]:
        here = Path(__file__).resolve()
        return sorted(set(_harvest(here, "assert_allowed", skip_rule_dependent=True)))

    @classmethod
    def executable(cls) -> list[str]:
        out = []
        for command in cls.harvested():
            if is_corpus_safe(command) is not None:
                continue
            if any(name in command for name in NOT_LOCALLY_EXECUTABLE):
                continue
            out.append(command)
        return out

    def test_the_harvest_is_large_enough_to_be_working(self):
        """A harvester that silently returns nothing is a test suite that silently stops
        checking. The floor is well under today's count and only has to catch zero."""
        self.assertGreaterEqual(len(self.harvested()), 30, "the harvester found almost nothing")
        self.assertGreaterEqual(
            len(self.executable()), 10, "nothing survived the local-execution filter"
        )

    def test_every_harvested_approval_leaves_the_tree_alone(self):
        self.maxDiff = None
        escaped: list[str] = []
        with scratch_tree() as root:
            for command in self.executable():
                if not hook.is_read_only(command):
                    continue  # asserted elsewhere; that assertion is where it fails
                before = snapshot(root)
                try:
                    run_sealed(command, root, timeout=10.0)
                except subprocess.TimeoutExpired:
                    escaped.append(f"{command!r} did not terminate")
                    continue
                if snapshot(root) != before:
                    escaped.append(f"{command!r} changed the working tree")
                    (Path(root) / "AGENTS.md").write_text("one\ntwo\n")
        self.assertEqual([], escaped, "approved and mutating:\n  " + "\n  ".join(escaped))


@needs_zsh
class DifferentialAgainstZsh(unittest.TestCase):
    """The approvals above, run in the shell that actually runs them when it is zsh.

    Everything else in this part asks bash, because this module models bash. zsh evaluates
    values bash passes through, and a hole there was found by hand, not by this file: these
    cases make the next one a red run instead.
    """

    # Each writes the payload in zsh under Claude Code's options, and none in bash.
    ATTACKS = (
        "x='$(touch PWNED)'; echo \"${(e)x}\"",
        "x='path[$(touch PWNED)]'; printf '%d\\n' \"$x\"",
        "x='path[$(touch PWNED)]'; echo $((x))",
    )

    def test_every_attack_really_mutates_the_tree_in_zsh(self):
        """A case zsh declines to execute would pass whatever the hook decided."""
        inert: list[str] = []
        for command in self.ATTACKS:
            with scratch_tree() as root:
                before = snapshot(root)
                run_in_zsh(command, root)
                if snapshot(root) == before:
                    inert.append(command)
        self.assertEqual([], inert, "attacks with no effect in zsh:\n  " + "\n  ".join(inert))

    def test_no_attack_is_approved(self):
        for command in self.ATTACKS:
            with self.subTest(command=command):
                self.assertFalse(hook.is_read_only(command), f"approved {command!r}")

    def test_no_approved_command_mutates_the_tree_in_zsh(self):
        """Every approval this file asserts, and every bash attack the hook approves, run
        in zsh. Collected rather than sub-tested, so a finding is one entry with a list."""
        commands = DifferentialOverTheSuitesOwnApprovals.executable() + list(
            DifferentialAgainstBash.CONTROLS + DifferentialAgainstBash.ATTACKS
        )
        escaped: list[str] = []
        for command in commands:
            if not hook.is_read_only(command):
                continue
            with scratch_tree() as root:
                before = snapshot(root)
                try:
                    run_in_zsh(command, root)
                except subprocess.TimeoutExpired:
                    escaped.append(f"{command!r} did not terminate")
                    continue
                if snapshot(root) != before:
                    escaped.append(f"{command!r} changed the working tree")
        self.assertEqual([], escaped, "approved and mutating in zsh:\n  " + "\n  ".join(escaped))


FUZZ_SEEDS = (
    "wc -l AGENTS.md",
    "ls -la",
    "cat AGENTS.md | head -n 1",
    "grep -n one AGENTS.md",
    "sed 's/one/two/' AGENTS.md",
    "awk '{print $1}' AGENTS.md",
    "sort AGENTS.md | uniq",
    "find . -name AGENTS.md",
    "head -n 2 AGENTS.md | tail -n 1",
    "echo hi",
)

# Insertion-only, from a fixed vocabulary. Nothing here can combine into a word outside
# the scratch tree, and `is_corpus_safe` is applied to every candidate before it runs.
FUZZ_FRAGMENTS = (
    ";",
    "&&",
    "||",
    "|",
    "&",
    "\n",
    "#",
    ">",
    ">>",
    "<",
    "$(",
    ")",
    "`",
    "'",
    '"',
    "\\",
    "{",
    "}",
    "(",
    ")",
    "$",
    "@P",
    "{ ",
    " ; }",
    "!",
    "$'",
    "|&",
    ";;",
    ";&",
    "<(",
    ">(",
    " <(touch PWNED)",
    " >(cat > PWNED)",
    " touch PWNED",
    " PWNED",
    " -i",
    " -o PWNED",
    " -delete",
    " -exec touch {} ;",
    "$(touch PWNED)",
    "`touch PWNED`",
    " > PWNED",
    " >> PWNED",
)

FUZZ_BUDGET = int(os.environ.get("SH_AUTO_APPROVE_FUZZ", "300"))
FUZZ_SEED = int(os.environ.get("SH_AUTO_APPROVE_FUZZ_SEED", "20260914"))


def fuzz_candidates(limit: int = FUZZ_BUDGET):
    """Deterministic for a given seed, so a failure is reproducible from the report."""
    generator = random.Random(FUZZ_SEED)
    produced = 0
    while produced < limit:
        command = generator.choice(FUZZ_SEEDS)
        for _ in range(generator.randint(1, 3)):
            position = generator.randint(0, len(command))
            command = command[:position] + generator.choice(FUZZ_FRAGMENTS) + command[position:]
        if is_corpus_safe(command) is not None:
            continue
        produced += 1
        yield command


@needs_bash
class DifferentialFuzz(unittest.TestCase):
    """The enumerated cases in this file are the bugs somebody thought of.

    This is the other kind. Read commands with shell punctuation spliced into them at
    random positions, classified and then -- if approved -- executed, with the tree
    checked for a mark. Most candidates are refused or fail to parse; the ones that
    matter are the ones bash both accepts and acts on while the classifier said they only
    read.

    Seeded, so a failure names a command you can paste. `SH_AUTO_APPROVE_FUZZ` sets
    the budget and `SH_AUTO_APPROVE_FUZZ_SEED` the seed; the defaults keep this under
    a couple of seconds.
    """

    def test_the_generator_only_emits_strings_that_are_safe_to_run(self):
        """The leash again, on the one corpus that is not written by hand."""
        for command in fuzz_candidates(min(FUZZ_BUDGET, 300)):
            reason = is_corpus_safe(command)
            with self.subTest(command=command):
                self.assertIsNone(reason, reason)

    def test_no_approved_mutant_mutates_the_tree(self):
        self.maxDiff = None
        escaped: list[str] = []
        examined = 0
        with scratch_tree() as root:
            for command in fuzz_candidates():
                if not hook.is_read_only(command):
                    continue
                examined += 1
                before = snapshot(root)
                try:
                    run_sealed(command, root, timeout=5.0)
                except subprocess.TimeoutExpired:
                    escaped.append(f"{command!r} did not terminate")
                    continue
                if snapshot(root) != before:
                    escaped.append(f"{command!r} changed the working tree")
                    for stray in Path(root).iterdir():
                        if stray.name != "AGENTS.md":
                            stray.unlink(missing_ok=True)
                    (Path(root) / "AGENTS.md").write_text("one\ntwo\n")
        self.assertEqual(
            [],
            escaped,
            f"{len(escaped)} of {examined} approved mutants left a mark:\n  "
            + "\n  ".join(escaped),
        )


# ======================================================================================
# Part 17 -- The hook as a process
#
# End to end, with the payload Claude Code sends on stdin. The invariant the module
# docstring rests on is asserted here: the hook allows or stays silent, and never denies.
# ======================================================================================

ALLOW_PAYLOAD = {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "every command only reads, or already matches an allow rule",
}

NEVER_DENY_PROBES = (
    "wc -l AGENTS.md",
    "rm -rf build/",
    "echo 'unbalanced",
    "",
    "   ",
    "ls\nrm -rf build/",
    "sudo ls /root",
    "git push origin main",
    "aws ecs delete-cluster --cluster x",
    "sed -i 's/a/b/' AGENTS.md",
    "sed '" + " " * 200 + "x'",
    "ls;(rm -rf build/)",
    "PATH=/tmp ls",
)


def _never_deny_probes() -> tuple[str, ...]:
    """Built from this file's corpora rather than written twice."""
    probes: list[str] = []
    probes += list(EXECUTED_ATTACKS)
    probes += [c for _, chain in SESSION_CHAINS for c in chain]
    probes += list(REFUSED_SEEDS)
    probes += [
        "cd $'\\x2ftmp' && ls",
        "{ ls; } > PWNED",
        "coproc sh",
        "cat <<EOF",
        "git submodule foreach 'id'",
        "aws --endpoint-url http://x sts get-caller-identity",
        "\x00\x01",
        "\u4e2d" * 50,
    ]
    return tuple(sorted(set(probes)))


class HookProcess:
    """Runs the hook the way Claude Code does: a fresh interpreter, with JSON on stdin."""

    def run_hook(self, stdin: str, argv=None, timeout: float = 60.0, env=None, cwd=None):
        return subprocess.run(
            argv or [sys.executable, str(MODULE_PATH)],
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
            cwd=cwd,
        )

    def run_payload(self, payload: dict, **kwargs) -> str:
        """The hook's stdout for one payload, after checking that it exited 0."""
        result = self.run_hook(json.dumps(payload), **kwargs)
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout

    def allow_payload(self, payload: dict, **kwargs) -> dict:
        """Fail rather than raise when nothing was emitted: silence is a verdict here,
        and `json.loads("")` reports it as a decode error three frames away."""
        out = self.run_payload(payload, **kwargs)
        self.assertNotEqual("", out, "the hook stayed silent where it should have allowed")
        return json.loads(out)["hookSpecificOutput"]


class HookProtocol(HookProcess, unittest.TestCase):
    """End to end, with the payload Claude Code actually sends on stdin."""

    def test_allows_with_the_documented_shape(self):
        out = self.run_payload({"tool_name": "Bash", "tool_input": {"command": "wc -l AGENTS.md"}})
        self.assertEqual(json.loads(out)["hookSpecificOutput"], ALLOW_PAYLOAD)

    def test_stays_silent_rather_than_denying(self):
        self.assertEqual(
            "",
            self.run_payload({"tool_name": "Bash", "tool_input": {"command": "rm -rf build/"}}),
        )

    def test_it_never_emits_a_deny(self):
        """The invariant the module docstring rests on, asserted rather than assumed.

        Exit 2 would also block, and on a blocking event it blocks whether or not JSON is
        printed, so the exit code is part of the invariant.
        """
        for command in NEVER_DENY_PROBES:
            with self.subTest(command=command[:40]):
                result = self.run_hook(
                    json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
                )
                self.assertEqual(0, result.returncode, "a non-zero exit can block")
                if result.stdout:
                    decision = json.loads(result.stdout)["hookSpecificOutput"]
                    self.assertEqual(ALLOW_PAYLOAD, decision)

    def test_ignores_other_tools(self):
        self.assertEqual(
            "",
            self.run_payload(
                {"tool_name": "Write", "tool_input": {"file_path": "a", "content": "b"}}
            ),
        )

    def test_stays_silent_outside_the_supported_python_and_platforms(self):
        """In process, since no subprocess can be an older interpreter: the requirement is
        raised past this one, and then the platform is moved off the list."""
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "wc -l AGENTS.md"}})
        unsupported = (
            ("MINIMUM_PYTHON", (sys.version_info[0] + 1, 0)),
            ("SUPPORTED_PLATFORMS", ()),
        )
        for name, value in unsupported:
            with self.subTest(name=name):
                out = io.StringIO()
                original = getattr(hook, name)
                setattr(hook, name, value)
                try:
                    with contextlib.redirect_stdout(out):
                        sys.stdin, stdin = io.StringIO(payload), sys.stdin
                        try:
                            self.assertEqual(0, hook.main())
                        finally:
                            sys.stdin = stdin
                finally:
                    setattr(hook, name, original)
                self.assertEqual("", out.getvalue())

    def test_the_project_root_comes_from_the_session_and_never_from_home(self):
        """
        A plugin's copy of the module sits in a cache that belongs to no project, so `main` asks
        the session. `$CLAUDE_PROJECT_DIR` first, since a `cd` does not move it; then the worktree
        around the session's directory; never `/` or the home directory, which a dotfiles
        repository makes a worktree.
        """
        with tempfile.TemporaryDirectory() as tmp:
            home, project = Path(tmp, "home"), Path(tmp, "home", "work", "project")
            (project / "docs").mkdir(parents=True)
            (project / ".git").mkdir()
            (home / ".git").mkdir()
            env = {"HOME": str(home), hook.PROJECT_DIR_ENV: ""}
            cases = (
                ({hook.PROJECT_DIR_ENV: str(project)}, str(home), project),
                ({}, str(project / "docs"), project),
                ({}, str(home / "work"), None),
                ({hook.PROJECT_DIR_ENV: str(home)}, str(project), None),
                ({hook.PROJECT_DIR_ENV: "/"}, str(project), None),
                ({hook.PROJECT_DIR_ENV: "relative/dir"}, str(project), None),
                ({}, None, None),
            )
            for extra, cwd, expected in cases:
                with self.subTest(env=extra, cwd=cwd):
                    with unittest.mock.patch.dict(os.environ, {**env, **extra}):
                        root = hook._project_root(cwd)
                    self.assertEqual(expected and Path(os.path.realpath(expected)), root)

    def test_malformed_input_is_silence_not_a_crash(self):
        for stdin in ("not json", "", "null", "[]", '"a string"', "42"):
            with self.subTest(stdin=stdin):
                result = self.run_hook(stdin)
                self.assertEqual(0, result.returncode)
                self.assertEqual("", result.stdout)

    def test_a_malformed_tool_input_is_silence(self):
        for payload in (
            {"tool_name": "Bash"},
            {"tool_name": "Bash", "tool_input": None},
            {"tool_name": "Bash", "tool_input": {"command": ["wc", "-l"]}},
            {"tool_name": "Bash", "tool_input": {"command": None}},
            {"tool_input": {"command": "wc -l AGENTS.md"}},
        ):
            with self.subTest(payload=payload):
                self.assertEqual("", self.run_payload(payload))

    def test_a_very_large_payload_is_handled(self):
        """No crash and no unbounded wait. What it decides is H-04's business."""
        command = "wc -l " + " ".join(f"f{i}.md" for i in range(50_000))
        result = self.run_hook(
            json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
        )
        self.assertEqual(0, result.returncode)

    @unittest.skipUnless(
        os.access(MODULE_PATH, os.X_OK), "hook is not executable; Claude Code execs it"
    )
    def test_the_shebang_path_works(self):
        """Claude Code runs the file, not `python3 <file>`. A lost exec bit or a shebang
        pointing at a missing interpreter is silence, which looks exactly like a working
        hook that declined."""
        result = self.run_hook(
            json.dumps({"tool_name": "Bash", "tool_input": {"command": "wc -l AGENTS.md"}}),
            argv=[str(MODULE_PATH)],
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"], ALLOW_PAYLOAD)

    @open_finding("D-04", "the protocol-level form of P-01 and P-02")
    def test_a_spliced_command_never_reaches_an_allow_payload(self):
        """`is_read_only` is the unit, but this is the thing that actually happens: the
        hook prints `allow` and the call runs with no prompt."""
        for command in ("wc -l AGENTS.md\nrm -rf build/", "wc -l AGENTS.md#; rm -rf build/"):
            with self.subTest(command=command):
                out = self.run_payload({"tool_name": "Bash", "tool_input": {"command": command}})
                self.assertEqual("", out, "the hook approved a spliced-in write")


class HookProcessRobustness(HookProcess, unittest.TestCase):
    """`HookProtocol`, extended to the inputs Claude Code actually sends
    and the failure modes that stall a session rather than crash it."""

    def test_the_keys_claude_code_sends_alongside_the_command(self):
        """A real `PreToolUse` payload carries more than `command`, and at least one more
        key has appeared in every version of the schema so far."""
        self.assertEqual(
            ALLOW_PAYLOAD,
            self.allow_payload(
                {
                    "session_id": "abc",
                    "transcript_path": "/tmp/t.jsonl",
                    "cwd": str(hook.REPO_ROOT),
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {
                        "command": "wc -l AGENTS.md",
                        "description": "count the lines",
                        "timeout": 120000,
                    },
                }
            ),
        )

    def test_the_tool_name_has_to_match(self):
        for name in ("bash", "BASH", "Bash ", "BashOutput", "Shell", ""):
            with self.subTest(tool_name=name):
                self.assertEqual(
                    "",
                    self.run_payload(
                        {"tool_name": name, "tool_input": {"command": "wc -l AGENTS.md"}}
                    ),
                    "a tool that is not Bash got a decision",
                )

    def test_text_that_is_not_a_command(self):
        for command in (
            "\x00",
            "\ufeffwc -l AGENTS.md",
            "\u4e2d\u6587",
            "\U0001f600",
            "wc -l AGENTS.md\r\n",
            "\r\n",
        ):
            with self.subTest(command=repr(command)):
                result = self.run_hook(
                    json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
                )
                self.assertEqual(0, result.returncode, result.stderr)
                if result.stdout:
                    self.assertEqual(ALLOW_PAYLOAD, json.loads(result.stdout)["hookSpecificOutput"])

    def test_it_never_emits_a_deny_for_the_adversarial_corpus(self):
        """`HookProtocol.test_it_never_emits_a_deny` asserts this invariant over a short
        hand-written list. The adversarial corpora are where a new code path would be, so
        they are where it matters."""
        for command in _never_deny_probes():
            with self.subTest(command=command[:50]):
                result = self.run_hook(
                    json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
                )
                self.assertEqual(0, result.returncode, "a non-zero exit can block")
                if result.stdout:
                    self.assertEqual(ALLOW_PAYLOAD, json.loads(result.stdout)["hookSpecificOutput"])

    def test_the_decision_is_the_same_from_a_different_working_directory(self):
        """Claude Code runs the hook with the session's cwd, which is not always the
        repository root, and a refusal must not become an approval because of it."""
        for command in ("rm -rf build/", "sed -i 's/a/b/' AGENTS.md", "touch PWNED"):
            with self.subTest(command=command):
                payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
                elsewhere = self.run_hook(payload, timeout=30, cwd=tempfile.gettempdir())
                self.assertEqual("", elsewhere.stdout, "approved from another directory")

    def test_a_settings_path_that_never_returns(self):
        """A FIFO with no writer blocks in `open`. A blocked hook is not a bypass -- the
        host cancels it and prompts -- but the default `PreToolUse` command-hook timeout
        is 600 seconds, and that is the whole Bash call.

        Run as a subprocess so a hang can be killed; calling `is_read_only` in a thread
        would leave the thread blocked for the life of the test run.
        """
        with tempfile.TemporaryDirectory(prefix="readonly_hook_rules_") as directory:
            fifo = Path(directory) / "settings.local.json"
            os.mkfifo(fifo)
            environment = dict(os.environ, **{hook.SETTINGS_ENV: str(fifo)})
            payload = json.dumps(
                {"tool_name": "Bash", "tool_input": {"command": "wc -l AGENTS.md"}}
            )
            try:
                self.run_hook(payload, timeout=15.0, env=environment)
            except subprocess.TimeoutExpired:
                self.fail("the hook blocked on a settings path that never returns")

    def test_a_rule_pattern_that_is_expensive_to_match(self):
        """A glob becomes a regexp somewhere. `fnmatch.translate` on Python 3.12 emits
        atomic groups and is safe; a hand-rolled `replace('*', '.*')` is not, and twelve
        stars against a four-hundred-character command takes minutes -- measured, not
        estimated.

        The pattern goes in `deny`, because a deny rule is consulted for every command
        and an allow rule may not be.
        """
        document = {"permissions": {"deny": ["Bash(" + "*x" * 12 + "y)"]}}
        with tempfile.TemporaryDirectory(prefix="readonly_hook_rules_") as directory:
            path = Path(directory) / "settings.local.json"
            path.write_text(json.dumps(document))
            environment = dict(os.environ, **{hook.SETTINGS_ENV: str(path)})
            payload = json.dumps(
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "wc -l " + "x" * 400},
                }
            )
            try:
                self.run_hook(payload, timeout=20.0, env=environment)
            except subprocess.TimeoutExpired:
                self.fail("a rule pattern made the hook take more than twenty seconds")

    def test_the_process_finishes_within_a_budget(self):
        """End to end, including interpreter start-up, on the input `CostsBoundedTime` found
        to be the slowest. The number is a budget rather than a measurement: it is what
        makes a regression visible, not what the code costs today."""
        payload = json.dumps(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "sed '" + " " * 8_000 + "x'"},
            }
        )
        started = time.monotonic()
        self.run_hook(payload, timeout=60.0)
        self.assertLess(time.monotonic() - started, 10.0, "the hook is slow to decide")


# ======================================================================================
# Part 18 -- Policy decisions, recorded as tests
#
# A decision stays here so that it is visible to the next person who meets the same
# command. The first two classes assert the current verdict and go red the day the hook
# drifts from it; the third is skipped, and its docstring says what removing the skip
# records.
# ======================================================================================


class PolicyAlreadyDecidedToRefuse(Verdicts, unittest.TestCase):
    """The half of the old `UndecidedPolicy` decided as refused.

    `UndecidedPolicy` was one `@unittest.skip`'d class holding two different things: harms
    the classifier now blocks and harms it still allows. Skipped whole, it asserted
    neither, so it could not tell you that half its premise -- "all of these are approved
    today" -- had gone stale, and a regression that re-opened one of the blocked harms
    would not have shown up here.

    These are the ones decided as refused. They were a policy question once and are not
    any more, so they are live refusal tests: regression guards that go red if a change
    re-opens them. 6 were still approved when they were moved here, and the hook was
    changed to refuse them: the 2 `aws` reads of a secret, the 2 field widths and the 2
    escape sequences. The spellings and siblings found while doing that are tested with
    the rules they exercise, in `RefusesOutputThatIsNotInert` and
    `RefusesAwsCallsThatPrintASecret`.

    In order: credentials printed to stdout, non-termination and filesystem-wide walks,
    configuration-driven execution, reads outside the working tree, resource exhaustion,
    and terminal control sequences.
    """

    def test_credentials_printed_to_stdout(self):
        self.assert_refused(
            "aws configure get aws_secret_access_key", "prints the long-lived secret key"
        )
        self.assert_refused(
            "aws secretsmanager get-secret-value --secret-id prod", "prints a secret"
        )
        self.assert_refused("aws ecr get-login-password", "prints a registry password")
        self.assert_refused("aws sts get-session-token", "mints session credentials")
        self.assert_refused("gcloud auth print-access-token", "prints a live OAuth token")
        self.assert_refused("git credential fill", "prints a stored credential")
        self.assert_refused("git config --get-all credential.helper", "names where they are")
        self.assert_refused("aws s3 presign s3://b/k", "mints a URL anyone can use")
        self.assert_refused("gcloud auth print-identity-token", "prints a live token")

    def test_commands_that_do_not_terminate_or_walk_everything(self):
        self.assert_refused("tail -f AGENTS.md", "never returns")
        self.assert_refused("find / -name id_rsa", "enumerates private keys")
        self.assert_refused("find / -name x", "walks the whole filesystem")

    def test_configuration_driven_execution(self):
        self.assert_refused("git diff --ext-diff", "runs the configured external diff")
        self.assert_refused("git log -p --ext-diff", "same, through the pager path")

    def test_reads_outside_the_working_tree_and_process_secrets(self):
        """Decided: refused. Each was approved and recorded as undecided; the full set of
        routes and their controls is `RefusesReadsOutsideTheWorkingDirectories`."""
        self.assert_refused("cat ~/.aws/credentials", "reads long-lived keys")
        self.assert_refused("cat /proc/self/environ", "prints this process's environment")
        self.assert_refused("cat /proc/self/mem", "reads this process's memory")
        self.assert_refused("cat /sys/class/net/eth0/address", "outside the working tree")

    def test_resource_exhaustion(self):
        """A field width is what makes output unbounded. The `find` case was recorded as
        `-printf '%p%p%p'`, which only triples a listing, and is the width form instead."""
        self.assert_refused("printf '%099999999d' 1", "allocates 100 MB")
        self.assert_refused("find . -name '*' -printf '%099999999p'", "pads every match")

    def test_terminal_control_sequences(self):
        """Output is not inert. OSC 52 writes the user's clipboard, OSC 8 makes any text
        a hyperlink to anywhere, and a title sequence can be read back by some terminals.
        The program is `echo` or `printf`, both of which only read.
        """
        self.assert_refused(
            "printf '\\033]52;c;cm9vdA==\\a'", "writes the clipboard through OSC 52"
        )
        self.assert_refused("printf '\\033]0;whatever\\007'", "sets the terminal title")


class PolicyStillUndecided(Verdicts, unittest.TestCase):
    """The half that is still approved, and the premise-check the old class lacked.

    These are read-only by the classifier's definition and still damaging, and whether
    that is a bug depends on what the hook is for -- the question the module does not
    answer. Under a poisoned prompt (the threat the harder passes assume) the credential
    and exfiltration cases are bugs; under an agent that is merely careless they are not.

    The difference from the old `UndecidedPolicy` is that these do not skip. Each asserts
    the *current* verdict -- approved -- with `assert_allowed`, so the class states the
    premise out loud and goes red the day the hook's behaviour drifts from it. A red test
    here is not a regression; it is the signal to come back and decide, by moving the case
    into `PolicyAlreadyDecidedToRefuse` (if the hook now refuses it and should) or editing
    the assertion (if the approval is still intended). That is strictly more than the skip
    did: it could not distinguish "still approved" from "quietly fixed".

    These approvals are deliberate statements of current behaviour, not idioms the hook is
    built to allow, so they are exempt from the approval budget by sitting in their own
    class rather than a `@approvals_budgeted` one.

    Reads outside the working directories and the `/proc` pseudo-files were here and have
    been decided: they are refused, and `RefusesReadsOutsideTheWorkingDirectories` holds them.
    """

    def test_reads_that_leave_the_working_tree_through_a_flag(self):
        """`git -C` and `--git-dir` point git at another tree. `--git-dir` is refused
        elsewhere because a foreign config runs code; `-C` only relocates the read, so it
        is here rather than there."""
        for command in ("git -C /tmp log", "git --no-pager -C /tmp log"):
            with self.subTest(command=command):
                self.assert_allowed(command, "reads another repository; approved today")


@unittest.skip("recorded, not asserted: see the class docstring")
class ObservedCommandsNotMadeToPass(Verdicts, unittest.TestCase):
    """Three observed commands deliberately left refused, with their rewrites.

    Skipped rather than deleted so that the decision is visible to the next person who
    hits the same prompt, and so that turning one of these on is an edit to a test that
    already names the cost.

    Each rewrite below is asserted in `ObservedCommandsStayApproved` or was checked by
    hand against the classifier; none needs a capability this module does not have.
    """

    def test_find_exec(self):
        """`find ... -exec wc -c {} \\;` is read-only in effect and not in form. `-exec`
        launches a program per match, so approving it means validating the argv it builds,
        and once that is validated `find` is a general program launcher rather than a
        program with a validator. It is the primitive in GHSA-cv3g-hj65-pcfh and in
        CVE-2026-55743, both of which are allowlists that made this exact exception.

        Rewrite, approved today: find . -name 'CLAUDE.md' -printf '%s %p\\n'
        """
        self.assert_allowed("find . -name 'CLAUDE.md' -exec wc -c {} \\;")

    def test_xargs(self):
        """`xargs -0 cat` is the same shape: a program whose arguments are a program.

        Rewrite: two commands, or `jq -s` over the operands directly.
        """
        self.assert_allowed("find . -name '*.jsonl' -print0 | xargs -0 cat")

    def test_cd_outside_the_repository(self):
        """`cd ~/.claude/projects` leaves the tree the module is scoped to, and what lives
        under `~/.claude` is the session transcripts -- readable, and exactly the thing a
        poisoned prompt would want read back into context.

        No rewrite: this one is a policy boundary rather than a spelling.
        """
        self.assert_allowed("cd ~/.claude/projects && ls")


# --------------------------------------------------------------------------------------


def _print_findings() -> int:
    print(f"{len(FINDINGS)} open findings against {MODULE_PATH}\n")
    for ref, where, note in sorted(FINDINGS):
        print(f"  {ref}  {note}\n        {where}")
    print(
        f"\npython {platform.python_version()} | bash {'.'.join(map(str, BASH_VERSINFO))}"
        f" | gnu find={HAS_GNU_FIND} date={HAS_GNU_DATE} sed={HAS_GNU_SED} gawk={HAS_GAWK}"
        f" | fuzz budget {FUZZ_BUDGET} at seed {FUZZ_SEED}"
    )
    return 0


if __name__ == "__main__":
    if "--findings" in sys.argv:
        sys.exit(_print_findings())
    unittest.main()
