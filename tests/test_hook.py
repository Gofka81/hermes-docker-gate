"""Unit tests for hook.py — the pre_tool_call gate. No Docker/hermes required
(tools.py falls back to stubs off-Pi)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hook as h  # noqa: E402


class TestTerminalBlock(unittest.TestCase):
    def test_raw_docker_blocked(self):
        for cmd in ("docker ps", "sudo docker run -it x",
                    "curl --unix-socket /var/run/docker.sock http://x/containers/json",
                    "podman ps", "docker-compose up -d",
                    "curl http://docker-proxy:2375/containers/json"):
            r = h.on_pre_tool_call(tool_name="terminal", args={"command": cmd})
            self.assertIsInstance(r, dict, f"should block: {cmd}")
            self.assertEqual(r["action"], "block")

    def test_non_docker_terminal_allowed(self):
        for cmd in ("ls -la", "cat /etc/hostname", "echo dockeresque",
                    "python3 script.py"):
            r = h.on_pre_tool_call(tool_name="terminal", args={"command": cmd})
            self.assertIsNone(r, f"should allow: {cmd}")


class TestReadTools(unittest.TestCase):
    def test_reads_pass_through(self):
        for t in ("docker_ps", "docker_logs", "docker_inspect", "docker_stats"):
            self.assertIsNone(h.on_pre_tool_call(tool_name=t, args={"container": "x"}))


class TestWriteApproval(unittest.TestCase):
    def test_valid_deploy_requests_approval(self):
        r = h.on_pre_tool_call(
            tool_name="docker_deploy",
            args={"name": "canary", "image": "hello-world", "network": "webnet"},
        )
        self.assertEqual(r["action"], "approve")
        self.assertEqual(r["rule_key"], "docker-gate:deploy")
        self.assertIn("canary", r["message"])

    def test_invalid_deploy_blocked_before_approval(self):
        # host network → block, never prompt
        r = h.on_pre_tool_call(
            tool_name="docker_deploy",
            args={"name": "x", "image": "nginx", "network": "host"},
        )
        self.assertEqual(r["action"], "block")
        # sensitive mount → block
        r2 = h.on_pre_tool_call(
            tool_name="docker_deploy",
            args={"name": "x", "image": "nginx", "volumes": ["/:/host"]},
        )
        self.assertEqual(r2["action"], "block")

    def test_valid_network_connect_requests_approval(self):
        r = h.on_pre_tool_call(
            tool_name="docker_network_connect",
            args={"network": "webnet", "container": "job-radar-server"},
        )
        self.assertEqual(r["action"], "approve")
        self.assertEqual(r["rule_key"], "docker-gate:network_connect")

    def test_invalid_network_connect_blocked(self):
        r = h.on_pre_tool_call(
            tool_name="docker_network_connect",
            args={"network": "host", "container": "x"},
        )
        self.assertEqual(r["action"], "block")


class TestArgExtraction(unittest.TestCase):
    def test_alternate_arg_keys(self):
        # hermes may pass args under different keys — hook must find them.
        r = h.on_pre_tool_call(
            tool_name="docker_deploy",
            tool_args={"name": "c", "image": "nginx"},
        )
        self.assertEqual(r["action"], "approve")

    def test_unknown_tool_allowed(self):
        self.assertIsNone(h.on_pre_tool_call(tool_name="web_search", args={"q": "x"}))


if __name__ == "__main__":
    unittest.main()
