"""Check the canonical grammar against a real shell, with every program replaced by a shim.

Usage: python3 -I tools/canonical/equiv.py <report.json> <workdir> [fuzz count] [bash|zsh]

`report.json` is `coverage.py`'s output. `workdir` is wiped and rebuilt.

Nothing real runs. The shell starts with an empty environment and PATH holding only shims: one
Python script, symlinked under every program name, that appends its argv to a log. Under bash every
builtin is disabled except `eval`, `command`, `builtin` and `KEEP_BUILTIN`, so a program name can
only reach a shim. Commands whose parse has a `/` in a program name are never run, and a DEBUG trap
under `extdebug` also skips any simple command whose first word holds a `/`, in case bash reads a
command word the parser didn't.

Three checks:

- fidelity: bash running the ORIGINAL text logs the argv `parse` read (usability)
- exactness: the shell running the CANONICAL text logs the same argv (the safety property)
- fuzz: random argv with every shell metacharacter, serialized, logs back exactly, and the
  canonical text parses back to the same argv

With `zsh`, only the canonical text runs (exactness and fuzz), under `zsh -f` the way Claude Code
wraps a command (`setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL; eval ...`), once per option set in
`ZSH_OPTION_SETS`. Canonical text only calls `command '<name>'`, which zsh sends to the external
program (a shim), or `builtin` for `KEEP_BUILTIN`, so no builtin needs disabling there.
"""

from __future__ import annotations

import collections
import json
import random
import shutil
import subprocess
import sys
from pathlib import Path

# `-I` keeps the script's own directory off `sys.path`
sys.path.insert(0, str(Path(__file__).resolve().parent))
from canon import (
    KEEP_BUILTIN,
    CommandList,
    Pipeline,
    Reject,
    Simple,
    parse,
    serialize,
)

BASH = shutil.which("bash") or "/bin/bash"
ZSH = shutil.which("zsh")
ZSH_OPTION_SETS = (
    "",
    "RC_QUOTES",
    "RC_QUOTES SH_WORD_SPLIT GLOB_SUBST MAGIC_EQUAL_SUBST EXTENDED_GLOB KSH_GLOB",
)

SHIM = """#!{python} -I
import json, os, sys
with open(os.environ["SHIM_LOG"], "a", encoding="utf-8", errors="surrogateescape") as log:
    log.write(json.dumps([os.path.basename(sys.argv[0]), *sys.argv[1:]]) + "\\n")
"""

# Kept enabled under bash: the harness needs eval; the canonical form needs command and builtin,
# and builtin needs the KEEP_BUILTIN ones themselves (shimmed instead for the original text).
# shopt, set and trap run before the `enable -n` line disables them; `enable` goes last on it.
KEEP_ENABLED = {"eval", "command", "builtin", *KEEP_BUILTIN}

BASH_PREAMBLE = r"""
shopt -s extdebug
set -o functrace
trap 'case ${BASH_COMMAND%%[[:space:]]*} in */*) ((0));; *) ((1));; esac' DEBUG
enable -n {disabled}
eval "$1"
"""

SEED = 20261108
EDGE_RATE = 0.15
ALPHABET = [
    *"abcXYZ019 \t\n'\"\\$`!*?[]{}~#=^%&|;<>()-_.,:@+/",
    *["é", "日本", "\x01", "\x1b", "\x7f"],
    *["''", "'\\''", "\\'", "$(id)", "${x}", "`id`", "*.md"],
]
EDGE_WORDS = [
    *["", "'", "''", "'''", "\\", "-", "--", "~", "~/x", "=x", "#", "!", "!!", "[", "]", "{a,b}"],
]


def bash_builtins() -> list[str]:
    """Return the names of bash's builtins."""
    out = subprocess.run(
        [BASH, "--norc", "--noprofile", "-c", "enable -a"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line.split()[-1] for line in out.splitlines() if line.startswith("enable")]


class Harness:
    """A shim directory, a run directory and a log, and the shell to run text in."""

    def __init__(self, workdir: Path, shell: str = "bash", zsh_options: str = "") -> None:
        """Wipe and rebuild `workdir`."""
        workdir = workdir.resolve()
        if workdir.exists():
            shutil.rmtree(workdir)
        self.shell = shell
        self.zsh_options = zsh_options
        self.shims = workdir / "shims"
        self.run_dir = workdir / "run"
        self.shims.mkdir(parents=True)
        self.run_dir.mkdir()
        self.shim = workdir / "argv_shim.py"
        self.shim.write_text(SHIM.format(python=sys.executable))
        self.shim.chmod(0o755)
        self.log = workdir / "log.jsonl"
        available = bash_builtins()
        disabled = [b for b in available if b not in KEEP_ENABLED and b != "enable"]
        kept = sorted(KEEP_BUILTIN & set(available))
        self.keep_builtins = BASH_PREAMBLE.replace("{disabled}", " ".join([*disabled, "enable"]))
        self.shim_builtins = BASH_PREAMBLE.replace(
            "{disabled}",
            " ".join([*disabled, *kept, "enable"]),
        )

    def add_shim(self, name: str) -> None:
        """Make `name` on PATH reach the shim."""
        if "/" in name or name in ("", ".", ".."):
            raise ValueError(f"not a program name: {name!r}")
        link = self.shims / name
        if not link.exists():
            link.symlink_to(self.shim)

    def run(self, text: str, *, shim_builtins: bool) -> list[list[str]]:
        """Run `text` and return the argv each shim logged, in order."""
        self.log.write_text("")
        env = {
            "PATH": str(self.shims),
            "SHIM_LOG": str(self.log),
            "HOME": str(self.run_dir),
            "LC_ALL": "C.UTF-8",
        }
        if self.shell == "zsh":
            if shim_builtins or ZSH is None:
                raise ValueError("under zsh only canonical text runs, and zsh has to be on PATH")
            setopt = f"setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL {self.zsh_options}".strip()
            argv = [ZSH, "-f", "-c", f'{setopt}; eval "$1"', "harness", text]
        else:
            preamble = self.shim_builtins if shim_builtins else self.keep_builtins
            argv = [BASH, "--norc", "--noprofile", "-c", preamble, "harness", text]
        subprocess.run(
            argv, cwd=self.run_dir, env=env, capture_output=True, timeout=20, check=False
        )
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]


def expected_runs(parsed: CommandList) -> list[list[str]]:
    """Return the argv that run: every shim exits 0, so `||` skips its right side."""
    runs = []
    for connector, pipeline in parsed.items:
        if connector != "||":
            runs += [s.argv for s in pipeline.commands]
    return runs


def comparable(runs: list[list[str]]) -> collections.Counter:
    """Return `runs` as a multiset, without the builtins kept in the shell.

    Pipeline members run concurrently, so order doesn't count; `cd`, `pwd` and `type` never reach
    a shim in the canonical run.
    """
    return collections.Counter(tuple(r) for r in runs if r[0] not in KEEP_BUILTIN)


def prepare(harness: Harness, parsed: CommandList) -> str | None:
    """Give the run what it needs, or return why it can't run here."""
    names = {s.argv[0] for _, p in parsed.items for s in p.commands}
    if any("/" in n or n in ("", ".", "..") for n in names):
        return "skipped: path as program name"
    simples = [s for _, p in parsed.items for s in p.commands]
    if any(
        not (harness.run_dir / r.target).exists()
        for s in simples
        for r in s.redirects
        if r.op == "<"
    ):
        return "skipped: input file absent"
    for name in names:
        harness.add_shim(name)
    # The canonical run's `builtin cd` is the real one: give it the directory the original run's
    # shimmed `cd` pretended to enter, so that `&&` after it behaves the same
    for s in simples:
        if s.argv[0] == "cd" and len(s.argv) == 2:
            target = s.argv[1]
            if ".." not in target.split("/") and not target.startswith(("/", "-", "~")):
                (harness.run_dir / target).mkdir(parents=True, exist_ok=True)
    return None


def corpus_checks(harness: Harness, rows: list[dict]) -> dict:
    """Run every accepted command of the report, original and canonical."""
    results: collections.Counter = collections.Counter()
    mismatches = []
    for row in rows:
        if row["strict"] != "accept":
            continue
        parsed = parse(row["command"])
        skipped = prepare(harness, parsed)
        if skipped:
            results[skipped] += 1
            continue
        expected = comparable(expected_runs(parsed))
        original = expected
        if harness.shell == "bash":
            original = comparable(harness.run(row["command"], shim_builtins=True))
            results["fidelity ok" if original == expected else "fidelity MISMATCH"] += 1
        canonical = comparable(harness.run(row["canonical"], shim_builtins=False))
        results["run"] += 1
        results["exactness ok" if canonical == expected else "exactness MISMATCH"] += 1
        if original != expected or canonical != expected:
            mismatches.append(
                {
                    "command": row["command"],
                    "expected": sorted(expected.elements()),
                    "original": sorted(original.elements()),
                    "canonical": sorted(canonical.elements()),
                },
            )
    return {"counts": dict(results), "mismatches": mismatches}


def fuzz(harness: Harness, count: int) -> dict:
    """Serialize random argv and check the shell hands each back exactly."""
    rng = random.Random(SEED)
    harness.add_shim("fz")
    failures = []
    for _ in range(count):
        words = []
        for _ in range(rng.randint(0, 5)):
            if rng.random() < EDGE_RATE:
                words.append(rng.choice(EDGE_WORDS))
            else:
                words.append("".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 10))))
        argv = ["fz", *words]
        text = serialize(CommandList([(None, Pipeline([Simple(argv)]))]))
        got = harness.run(text, shim_builtins=False)
        if got != [argv]:
            failures.append({"argv": argv, "text": text, "got": got})
        # The canonical text is inside the grammar too, and parses back to the same argv
        try:
            again = parse(text.removeprefix("command "))
            if again.items[0][1].commands[0].argv != argv:
                failures.append({"argv": argv, "text": text, "reparse": "differs"})
        except Reject as reason:
            failures.append({"argv": argv, "text": text, "reparse": str(reason)})
    return {"cases": count, "failures": failures}


def main() -> int:
    """Run the checks and write `equiv-<shell>.json` into the workdir."""
    report = json.loads(Path(sys.argv[1]).read_text())
    workdir = Path(sys.argv[2])
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 300
    shell = sys.argv[4] if len(sys.argv) > 4 else "bash"
    if shell == "zsh" and ZSH is None:
        print("zsh is not on PATH", file=sys.stderr)
        return 2
    runs = {}
    for options in ZSH_OPTION_SETS if shell == "zsh" else ("",):
        harness = Harness(workdir, shell, options)
        out = {"corpus": corpus_checks(harness, report["rows"]), "fuzz": fuzz(harness, count)}
        label = f"{shell} {options}".strip()
        runs[label] = out
        failures = len(out["fuzz"]["failures"])
        print(label, json.dumps({"corpus": out["corpus"]["counts"], "fuzz_failures": failures}))
    (workdir / f"equiv-{shell}.json").write_text(json.dumps(runs, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
