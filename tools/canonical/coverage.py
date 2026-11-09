"""How much of the suite's asserted traffic the canonical grammar keeps, and what it rejects.

Usage: python3 -I tools/canonical/coverage.py <asserted.jsonl> <report.json>

Reads `harvest.py`'s output. Writes every command with its verdict, the grammar's outcome, and
its canonical text when accepted, and prints a summary per verdict: how many the grammar keeps,
how many hook-side expansion of globs, a leading `~` and `{a,b}` would add, and the categories of
the rest.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

# `-I` keeps the script's own directory off `sys.path`
sys.path.insert(0, str(Path(__file__).resolve().parent))
from canon import Reject, parse, serialize


def classify(command: str) -> dict:
    """Return the grammar's outcome for `command`: accepted with its canonical text, or why not."""
    out: dict = {}
    try:
        parsed = parse(command)
    except Reject as reason:
        out["strict"] = reason.category
        out["detail"] = reason.detail
        try:
            parse(command, lenient=True)
            out["lenient"] = "accept"
        except Reject as again:
            out["lenient"] = again.category
        return out
    out["strict"] = "accept"
    out["canonical"] = serialize(parsed)
    out["names"] = sorted({s.argv[0] for _, p in parsed.items for s in p.commands})
    return out


def summarize(rows: list[dict]) -> dict:
    """Count, per verdict, with and without the rule-dependent classes, what the grammar keeps."""
    summary = {}
    for verdict in ("allow", "refused", "no-opinion"):
        for scope in ("all", "rule-free"):
            subset = [
                x
                for x in rows
                if x["verdict"] == verdict and (scope == "all" or not x["rule_dependent"])
            ]
            strict = collections.Counter(x["strict"] for x in subset)
            rescued = sum(
                1 for x in subset if x["strict"] != "accept" and x.get("lenient") == "accept"
            )
            rejected = sorted(
                ((k, v) for k, v in strict.items() if k != "accept"),
                key=lambda kv: -kv[1],
            )
            summary[f"{verdict}/{scope}"] = {
                "n": len(subset),
                "accepted": strict.get("accept", 0),
                "rescued_by_hook_side_expansion": rescued,
                "rejected_by_category": dict(rejected),
            }
    return summary


def main() -> int:
    """Classify every harvested command and write the report."""
    records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
    # One row per command and verdict: a command asserted under several setups keeps each verdict
    rows: dict[tuple[str, str], dict] = {}
    for r in records:
        row = rows.setdefault((r["command"], r["verdict"]), {**r, "classes": set()})
        row["classes"].add(r["class"])
        row["rule_dependent"] = row["rule_dependent"] and r["rule_dependent"]
    report: dict = {
        "rows": [
            {
                "command": command,
                "verdict": verdict,
                "rule_dependent": row["rule_dependent"],
                "classes": sorted(row["classes"]),
                **classify(command),
            }
            for (command, verdict), row in rows.items()
        ],
    }
    report["summary"] = summarize(report["rows"])
    kept_names = collections.Counter(
        name
        for x in report["rows"]
        if x["verdict"] == "allow" and x["strict"] == "accept"
        for name in x["names"]
    )
    report["command_names_in_kept_allows"] = dict(kept_names.most_common())
    Path(sys.argv[2]).write_text(json.dumps(report, indent=1))
    print(json.dumps(report["summary"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
