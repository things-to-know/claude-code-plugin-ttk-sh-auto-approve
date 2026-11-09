r"""Run real session traffic through the canonical grammar, joined with the hook's own verdicts.

Usage, from the repository root, for one transcript or several:

    make -s explain PROJECT=<dir> TRANSCRIPT=<session>.jsonl \
      | python3 -I tools/canonical/measure_explain.py

Reads `tools/explain.py --transcript` lines (decision, reason, directory, command; fields
escaped) from stdin. Prints, per decision, how many commands the grammar keeps as they are, how
many it would keep if the hook expanded globs, a leading `~` and `{a,b}` itself, and what the
rest fall to, with a few examples each.
"""

from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

# `-I` keeps the script's own directory off `sys.path`
sys.path.insert(0, str(Path(__file__).resolve().parent))
from canon import Reject, parse

# The reverse of `tools/explain.py`'s `escaped`
ESCAPE = re.compile(r"\\(\\|n|t|r|x[0-9a-f]{2}|u[0-9a-f]{4}|U[0-9a-f]{8})")
NAMED = {"\\": "\\", "n": "\n", "t": "\t", "r": "\r"}
FIELDS = 4
EXAMPLES = 3


def unescape(field: str) -> str:
    """Return the text a `--transcript` field was escaped from."""

    def one(match: re.Match[str]) -> str:
        code = match.group(1)
        return NAMED[code] if code in NAMED else chr(int(code[1:], 16))

    return ESCAPE.sub(one, field)


def outcome(command: str) -> str:
    """Return what the grammar does with `command`."""
    try:
        parse(command)
    except Reject as reason:
        try:
            parse(command, lenient=True)
        except Reject:
            return f"rejected: {reason.category}"
        return "kept if the hook expands globs, a leading ~ and {a,b}"
    return "kept"


def main() -> int:
    """Read explain lines from stdin and print the counts."""
    by_decision: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    examples: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    for line in sys.stdin:
        fields = line.rstrip("\n").split("\t")
        if len(fields) < FIELDS:
            continue
        decision, command = fields[0], unescape(fields[-1])
        result = outcome(command)
        by_decision[decision][result] += 1
        if result != "kept" and len(examples[(decision, result)]) < EXAMPLES:
            examples[(decision, result)].append(command)
    for decision, counts in sorted(by_decision.items()):
        total = sum(counts.values())
        print(f"{decision}: {total}")
        for result, n in counts.most_common():
            print(f"  {n:6}  {100 * n / total:5.1f}%  {result}")
            for command in examples.get((decision, result), []):
                print(f"            e.g. {command[:100]!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
