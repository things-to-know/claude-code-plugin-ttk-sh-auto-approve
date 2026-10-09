"""Contract tests: run the hook exactly as Claude Code would, via hooks/hooks.json.

These hold for the placeholder and must keep holding for the real
implementation. Add the implementation's own suites next to this file.
Run with `python3 -m unittest discover -s tests` (pytest also collects them).
"""

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent / "plugin"
HOOKS_JSON = PLUGIN_ROOT / "hooks" / "hooks.json"
DECISIONS = {"allow", "deny", "ask", "defer"}


def bash_hook_handlers():
    config = json.loads(HOOKS_JSON.read_text())
    return [
        handler
        for group in config["hooks"]["PreToolUse"]
        if group.get("matcher") == "Bash"
        for handler in group["hooks"]
    ]


def run_hook(stdin_text):
    """Spawn the Bash PreToolUse handler the way Claude Code's exec form does."""
    (handler,) = bash_hook_handlers()
    root = str(PLUGIN_ROOT)
    argv = [shutil.which(handler["command"])] + [
        arg.replace("${CLAUDE_PLUGIN_ROOT}", root) for arg in handler["args"]
    ]
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=root, CLAUDE_PROJECT_DIR=os.getcwd())
    return subprocess.run(
        argv, input=stdin_text, capture_output=True, text=True, env=env, timeout=30
    )


def payload(command, tool_name="Bash"):
    return json.dumps(
        {
            "session_id": "test",
            "cwd": os.getcwd(),
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command, "description": "test"},
            "tool_use_id": "toolu_test",
        }
    )


def decision_of(result):
    """Return the permissionDecision printed by the hook, or None if silent."""
    if not result.stdout.strip():
        return None
    output = json.loads(result.stdout)
    specific = output["hookSpecificOutput"]
    assert specific["hookEventName"] == "PreToolUse", specific
    assert specific["permissionDecision"] in DECISIONS, specific
    return specific["permissionDecision"]


class WiringTest(unittest.TestCase):
    def test_single_exec_form_handler_pointing_inside_plugin(self):
        (handler,) = bash_hook_handlers()
        self.assertEqual(handler["type"], "command")
        self.assertIn("args", handler, "use exec form so the path needs no quoting")
        self.assertIn("-I", handler["args"], "run Python in isolated mode")
        script = handler["args"][-1].replace("${CLAUDE_PLUGIN_ROOT}", str(PLUGIN_ROOT))
        self.assertTrue(Path(script).is_file(), script)

    def test_no_version_field_in_manifest(self):
        # Versions are derived from the sha pinned in the catalog (see CLAUDE.md).
        manifest = json.loads((PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text())
        self.assertNotIn("version", manifest)


class FailClosedTest(unittest.TestCase):
    def assert_not_allowed(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)  # never exit 2: that blocks
        self.assertNotEqual(decision_of(result), "allow")

    def test_malformed_json(self):
        self.assert_not_allowed(run_hook("{not json"))

    def test_empty_stdin(self):
        self.assert_not_allowed(run_hook(""))

    def test_other_tool(self):
        self.assert_not_allowed(run_hook(payload("ls", tool_name="Write")))

    def test_missing_command(self):
        self.assert_not_allowed(run_hook(json.dumps({"tool_name": "Bash", "tool_input": {}})))

    def test_mutating_commands(self):
        for command in [
            "rm -rf ./build",
            "git push --force",
            "ls > listing.txt",
            "cat notes.txt | tee copy.txt",
            "find . -delete",
            "ls; rm -f x",
            "echo $(touch pwned)",
        ]:
            with self.subTest(command=command):
                self.assert_not_allowed(run_hook(payload(command)))


class OutputShapeTest(unittest.TestCase):
    def test_output_is_empty_or_a_valid_decision(self):
        for command in ["ls", "git status", "cat README.md"]:
            with self.subTest(command=command):
                result = run_hook(payload(command))
                self.assertEqual(result.returncode, 0, result.stderr)
                decision_of(result)


if __name__ == "__main__":
    unittest.main()
