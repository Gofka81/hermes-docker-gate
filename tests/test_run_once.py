"""Unit tests for docker_run_once — validator + hook gate. No Docker required."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import validator as v  # noqa: E402
import hook as h       # noqa: E402


class TestValidateSingleCommand(unittest.TestCase):
    def test_safe_command_returns_argv(self):
        self.assertEqual(v.validate_single_command("cat /app/config.yaml"),
                         ["cat", "/app/config.yaml"])
        self.assertEqual(v.validate_single_command("grep -i error /var/log/app.log"),
                         ["grep", "-i", "error", "/var/log/app.log"])

    def test_chaining_rejected(self):
        for cmd in ("cat x; rm y", "cat x && rm y", "cat x || rm y", "cat x & rm y"):
            with self.assertRaises(v.ValidationError, msg=cmd):
                v.validate_single_command(cmd)

    def test_pipe_and_redirection_rejected(self):
        for cmd in ("cat x | grep y", "cat x > out", "cat < in", "echo hi > /etc/x"):
            with self.assertRaises(v.ValidationError, msg=cmd):
                v.validate_single_command(cmd)

    def test_substitution_rejected(self):
        for cmd in ("cat $(whoami)", "cat `whoami`", "kill $(pidof x)"):
            with self.assertRaises(v.ValidationError, msg=cmd):
                v.validate_single_command(cmd)

    def test_host_reaching_binaries_rejected(self):
        for cmd in ("docker ps", "systemctl restart nginx", "nsenter -t 1 -m sh",
                    "mount /dev/sda1 /mnt", "reboot", "chroot /host"):
            with self.assertRaises(v.ValidationError, msg=cmd):
                v.validate_single_command(cmd)

    def test_empty_and_unparseable_rejected(self):
        for cmd in ("", "   ", 'cat "unterminated'):
            with self.assertRaises(v.ValidationError):
                v.validate_single_command(cmd)

    def test_argv_execution_is_the_real_guard(self):
        # Even a semicolon that somehow reached shlex would be an inert token,
        # not a chain — proving no-shell arg-array execution. (It's rejected
        # earlier by the metachar check, but this documents the guarantee.)
        import shlex
        self.assertEqual(shlex.split("cat x; rm y"), ["cat", "x;", "rm", "y"])
        # mutating command is allowed to VALIDATE (approval handles the gate)
        self.assertEqual(v.validate_single_command("rm /tmp/scratch"), ["rm", "/tmp/scratch"])


class TestClassification(unittest.TestCase):
    def test_read_only(self):
        for c in (["cat", "x"], ["ls", "-la"], ["grep", "e", "f"], ["ps", "aux"]):
            self.assertTrue(v.is_read_only_command(c), c)

    def test_mutating(self):
        for c in (["rm", "x"], ["apt", "install", "y"], ["chmod", "777", "z"],
                  ["find", ".", "-delete"], ["curl", "http://x"]):
            self.assertFalse(v.is_read_only_command(c), c)


class TestHookGate(unittest.TestCase):
    def test_valid_run_once_requests_approval_and_says_exec(self):
        r = h.on_pre_tool_call(tool_name="docker_run_once",
                               args={"container": "job-radar-server", "command": "cat /app/x"})
        self.assertEqual(r["action"], "approve")
        self.assertIn("exec", r["message"].lower())
        self.assertTrue(r["rule_key"].startswith("docker_run_once:"))

    def test_prompt_labels_read_vs_mutating(self):
        ro = h.on_pre_tool_call(tool_name="docker_run_once",
                                args={"container": "c", "command": "cat x"})
        mut = h.on_pre_tool_call(tool_name="docker_run_once",
                                 args={"container": "c", "command": "rm x"})
        self.assertIn("read-only", ro["message"])
        self.assertIn("MUTATING", mut["message"])

    def test_name_validated_before_command(self):
        # Garbage container name → blocked at name stage even with a fine command.
        r = h.on_pre_tool_call(tool_name="docker_run_once",
                               args={"container": "job-radar; rm -rf /", "command": "cat x"})
        self.assertEqual(r["action"], "block")

    def test_bad_command_blocked_before_approval(self):
        r = h.on_pre_tool_call(tool_name="docker_run_once",
                               args={"container": "c", "command": "cat x | sh"})
        self.assertEqual(r["action"], "block")

    def test_no_persisted_trust_unique_rule_key_per_call(self):
        # Policy (a): every exec is per-use. Two identical calls must produce
        # DIFFERENT rule_keys so an [a]lways answer can never match a later call.
        a = h.on_pre_tool_call(tool_name="docker_run_once",
                               args={"container": "c", "command": "cat x"})
        b = h.on_pre_tool_call(tool_name="docker_run_once",
                               args={"container": "c", "command": "cat x"})
        self.assertNotEqual(a["rule_key"], b["rule_key"])


if __name__ == "__main__":
    unittest.main()
