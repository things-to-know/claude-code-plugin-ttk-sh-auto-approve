"""Tests for `tests/test_verdict_diff.py` to run through `tools/verdict_diff.py`.

They load the hook as `tests/test_sh_auto_approve.py` does, and ask it commands: spelled out, one
twice; built; across lines; in a context of the test's own, a scratchpad and a rule file, where
each is approved, beside the same command without the rule; and 2 refusals in a row.
"""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

HOOK = os.environ["SH_AUTO_APPROVE_HOOK"]
spec = importlib.util.spec_from_file_location("sh_auto_approve", HOOK)
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)
os.environ[hook.SETTINGS_ENV] = ""
NAME = "AGENTS.md"
SCRATCH = "/tmp/claude-1000/-home-dir1-dir2/00000000-0000-4000-8000-000000000000/scratchpad"


class Cases(unittest.TestCase):
    def test_built(self):
        hook.is_read_only("wc -c " + NAME)
        hook.is_read_only("wc -l AGENTS.md\nwc -w AGENTS.md")

    def test_in_a_context(self):
        hook._SCRATCHPAD_DIR = SCRATCH
        hook.is_read_only(f"ls {SCRATCH}")
        hook._SCRATCHPAD_DIR = None
        hook.is_read_only("touch PWNED")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(json.dumps({"permissions": {"allow": ["Bash(touch *)"]}}))
            os.environ[hook.SETTINGS_ENV] = str(path)
            hook.is_read_only("touch PWNED")
            os.environ[hook.SETTINGS_ENV] = ""

    def test_refused_in_a_row(self):
        """A hook that approves the first stops the test there."""
        self.assertFalse(hook.is_read_only("sed -i 's/a/b/' AGENTS.md"))
        self.assertFalse(hook.is_read_only("sed -n '1e touch PWNED' AGENTS.md"))

    def test_spelled_out(self):
        for command in ("wc -l AGENTS.md", "cat /dev/tcp/example.com/80", "wc -l AGENTS.md"):
            hook.is_read_only(command)
