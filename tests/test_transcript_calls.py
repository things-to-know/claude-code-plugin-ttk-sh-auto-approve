"""`tools/transcript_calls.py` counts each session's matching Bash calls by who allowed them."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "transcript_calls.py"

SESSION = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
OTHER = "9b2c6d1e-0000-4000-8000-000000000000"


def call(call_id: str, command: str, name: str = "Bash") -> dict:
    """An assistant entry with one tool call."""
    tool_input = {"command": command} if name == "Bash" else {"file_path": "/x"}
    block = {"type": "tool_use", "id": call_id, "name": name, "input": tool_input}
    return {"type": "assistant", "message": {"role": "assistant", "content": [block]}}


def result(call_id: str, source: str | None) -> dict:
    """The user entry with a call's result, and how it was allowed unless ``source`` is None."""
    block = {"type": "tool_result", "tool_use_id": call_id, "content": "ok"}
    entry: dict = {"type": "user", "message": {"role": "user", "content": [block]}}
    if source is not None:
        entry["permissionDecision"] = {"source": source}
    return entry


def write(path: Path, *entries: dict, junk: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(entry) for entry in entries]
    path.write_text("\n".join([*lines, junk]) + "\n", encoding="utf-8")


def run(*args: str) -> list[str]:
    completed = subprocess.run(
        [sys.executable, "-I", str(TOOL), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.splitlines()


class CountsBySource(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="transcript_calls_")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        write(
            self.root / "-proj" / f"{SESSION}.jsonl",
            call("a", "make -s -C sub check"),
            result("a", "user_temporary"),
            call("b", "make -s check"),
            result("b", "hook"),
            call("c", "make -C sub lint"),
            call("d", "git status"),
            result("d", "config"),
            call("e", "make -C ignored", name="Read"),
            junk="{not json",
        )
        write(
            self.root / "-proj" / SESSION / "subagents" / "agent-1.jsonl",
            call("f", "make -C sub test"),
            result("f", "user_temporary"),
        )
        write(
            self.root / "-other" / f"{OTHER}.jsonl",
            call("g", "make -C x"),
            result("g", "config"),
        )

    def test_each_session_and_the_totals(self):
        self.assertEqual(
            run("^make( -s)? -C ", str(self.root)),
            [
                "3f2504e0 unrecorded=1 user_temporary=2",
                "9b2c6d1e config=1",
                "sessions 2 config=1 unrecorded=1 user_temporary=2",
            ],
        )

    def test_a_transcript_given_as_a_file(self):
        self.assertEqual(
            run("^make", str(self.root / "-proj" / f"{SESSION}.jsonl")),
            [
                "3f2504e0 hook=1 unrecorded=1 user_temporary=1",
                "sessions 1 hook=1 unrecorded=1 user_temporary=1",
            ],
        )

    def test_no_match(self):
        self.assertEqual(run("^cd ", str(self.root)), ["sessions 0"])


if __name__ == "__main__":
    unittest.main()
