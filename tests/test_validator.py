"""Unit tests for validator.py — pure logic, no Docker required."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import validator as v  # noqa: E402


class TestNames(unittest.TestCase):
    def test_valid_names(self):
        for n in ("web", "job-radar-server", "my_app.1", "A1"):
            self.assertEqual(v.validate_name(n), n)

    def test_injection_names_rejected(self):
        for n in ("", "foo; rm -rf /", "a b", "$(whoami)", "foo|bar",
                  "foo/bar", "-startsdash", "back`tick`", "quote'x"):
            with self.assertRaises(v.ValidationError):
                v.validate_name(n)


class TestImage(unittest.TestCase):
    def test_valid_images(self):
        for img in ("nginx", "nginx:1.27", "ghcr.io/org/app:tag",
                    "repo@sha256:" + "a" * 64):
            self.assertEqual(v.validate_image(img), img)

    def test_bad_images_rejected(self):
        for img in ("", "nginx; rm", "img $(x)", "a b"):
            with self.assertRaises(v.ValidationError):
                v.validate_image(img)


class TestNetworkName(unittest.TestCase):
    def test_valid(self):
        for net in ("webnet", "app_net", "proj-net"):
            self.assertEqual(v.validate_network_name(net), net)

    def test_reserved_rejected(self):
        for net in ("host", "none", "bridge", "container:abc"):
            with self.assertRaises(v.ValidationError):
                v.validate_network_name(net)


class TestVolumes(unittest.TestCase):
    def test_safe_allowed(self):
        # named volume + non-sensitive host paths
        v.validate_volumes(["mydata:/data", "/opt/appdata:/data", "/srv/x:/y:ro"])

    def test_sensitive_rejected(self):
        for spec in ("/:/host", "/etc:/x", "/root:/r", "/home/lantonyk:/h",
                     "/var/run/docker.sock:/sock", "/run/docker.sock:/s",
                     "/proc:/p", "/sys:/s", "/var/lib/docker:/d"):
            with self.assertRaises(v.ValidationError):
                v.validate_volumes([spec])


class TestPorts(unittest.TestCase):
    def test_valid(self):
        v.validate_ports(["8080:80", "80", "53:53/udp"])

    def test_invalid(self):
        for spec in ("abc:80", "8080:xyz", "99999:80", "0:80", ""):
            with self.assertRaises(v.ValidationError):
                v.validate_ports([spec])


class TestEscapeFlagScanner(unittest.TestCase):
    def test_safe_args_pass(self):
        v.scan_for_escape_flags(
            ["-d", "--name", "foo", "-p", "8080:80", "-v", "mydata:/data",
             "--restart", "unless-stopped", "--network", "webnet"]
        )

    def test_dangerous_flags_rejected(self):
        cases = [
            ["--privileged"],
            ["--cap-add", "SYS_ADMIN"],
            ["--cap-add=NET_ADMIN"],
            ["--device", "/dev/kmsg"],
            ["--security-opt", "seccomp=unconfined"],
            ["--pid=host"],
            ["--pid", "host"],
            ["--ipc=host"],
            ["--userns=host"],
            ["--network=host"],
            ["--net", "host"],
            ["-v", "/:/host"],
            ["--volume=/etc:/x"],
            ["--mount", "type=bind,source=/,target=/x"],
            ["--mount", "type=bind,src=/var/run/docker.sock,target=/s"],
        ]
        for args in cases:
            with self.assertRaises(v.ValidationError, msg=f"should reject {args}"):
                v.scan_for_escape_flags(args)


class TestDeploy(unittest.TestCase):
    def test_happy_path(self):
        v.validate_deploy(
            name="canary", image="hello-world",
            ports=["8080:80"], volumes=["mydata:/data"], network="webnet",
        )

    def test_rejects_bad_pieces(self):
        with self.assertRaises(v.ValidationError):
            v.validate_deploy(name="bad name", image="nginx")
        with self.assertRaises(v.ValidationError):
            v.validate_deploy(name="ok", image="nginx", volumes=["/:/host"])
        with self.assertRaises(v.ValidationError):
            v.validate_deploy(name="ok", image="nginx", network="host")
        with self.assertRaises(v.ValidationError):
            v.validate_deploy(name="ok", image="nginx", extra_args=["--privileged"])


class TestNetworkConnect(unittest.TestCase):
    def test_happy(self):
        v.validate_network_connect(network="webnet", container="job-radar-server")

    def test_host_network_rejected(self):
        with self.assertRaises(v.ValidationError):
            v.validate_network_connect(network="host", container="x")

    def test_bad_container_rejected(self):
        with self.assertRaises(v.ValidationError):
            v.validate_network_connect(network="webnet", container="foo; rm")


if __name__ == "__main__":
    unittest.main()
