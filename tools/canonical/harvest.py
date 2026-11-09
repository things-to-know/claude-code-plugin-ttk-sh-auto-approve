"""Harvest the approval suite's asserted verdicts statically, without importing or running it.

Usage: python3 -I tools/canonical/harvest.py <out.jsonl> [tests/test_sh_auto_approve.py]

Same rule as the suite's own `_harvest`: a string literal passed as the first argument to one of
the assertion helpers. The helper names the verdict `main` gives that command under the test's
setup, since the suite passes on `main`. Each record also says which test class asserted it, and
whether that class depends on operator rules or a configured remote (the suite's own
`RULE_DEPENDENT` test: the class source mentions `operator_rules` or `remotes_configured`).
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

HELPERS = {
    "assert_allowed": "allow",
    "assert_refused": "refused",
    "assert_refused_outright": "refused",
    "assert_no_opinion": "no-opinion",
}
RULE_DEPENDENT = ("operator_rules", "remotes_configured")
DEFAULT_SUITE = Path(__file__).resolve().parents[2] / "tests" / "test_sh_auto_approve.py"


def harvest(suite: Path) -> list[dict]:
    """Return one record per literal command passed to an assertion helper in `suite`."""
    tree = ast.parse(suite.read_text(encoding="utf-8"))
    records = []
    for outer in tree.body:
        if not isinstance(outer, ast.ClassDef):
            continue
        dependent = any(marker in ast.unparse(outer) for marker in RULE_DEPENDENT)
        for node in ast.walk(outer):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = node.func
            if not isinstance(function, ast.Attribute) or function.attr not in HELPERS:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                records.append(
                    {
                        "verdict": HELPERS[function.attr],
                        "helper": function.attr,
                        "class": outer.name,
                        "rule_dependent": dependent,
                        "line": node.lineno,
                        "command": first.value,
                    },
                )
    return records


def main() -> int:
    """Write the harvested records as JSON lines."""
    out = Path(sys.argv[1])
    suite = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_SUITE
    records = harvest(suite)
    with out.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")
    print(f"{len(records)} assertions harvested from {suite}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
