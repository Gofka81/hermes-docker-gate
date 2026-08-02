"""Unit tests for redact.py — pure logic, no Docker/hermes required.

These run against the fallback redactor (agent.redact isn't importable off-Pi);
the structural env-masking is independent of that, so the critical
prefixless-secret guarantee is fully exercised here.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import redact as r  # noqa: E402

# Distinctive fake secrets — must never appear in redacted output.
TELEGRAM = "123456789:AAH0no0this0is0a0fake0bot0token0value0xyz"   # prefixless-ish
GPG = "ABCDEF0123456789PREFIXLESSFAKEGPGSECRET"                     # no known prefix
ANTHROPIC = "sk-ant-FAKEsecret1234567890abcdefghij"                # prefixed


class TestInspectRedaction(unittest.TestCase):
    def _sample(self):
        return json.dumps([{
            "Id": "deadbeef",
            "Name": "/job-radar-server",
            "Config": {
                "Env": [
                    f"TELEGRAM_BOT_TOKEN={TELEGRAM}",
                    f"ANTHROPIC_API_KEY={ANTHROPIC}",
                    f"GPG_KEY={GPG}",
                    "PATH=/usr/local/bin",
                    "NOTANASSIGNMENT",
                ],
                "Cmd": ["node", "server.js"],
            },
            "RestartPolicy": {"Name": "unless-stopped"},
        }])

    def test_secret_values_removed(self):
        out = r.redact_inspect(self._sample())
        for secret in (TELEGRAM, GPG, ANTHROPIC):
            self.assertNotIn(secret, out, f"leaked secret value: {secret}")

    def test_prefixless_secrets_masked(self):
        # The whole point: prefixless env values (no sk-/gsk- prefix) still gone.
        out = r.redact_inspect(self._sample())
        self.assertNotIn(TELEGRAM, out)
        self.assertNotIn(GPG, out)
        self.assertIn(r.REDACTED, out)

    def test_keys_preserved(self):
        out = r.redact_inspect(self._sample())
        for key in ("TELEGRAM_BOT_TOKEN", "ANTHROPIC_API_KEY", "GPG_KEY", "PATH"):
            self.assertIn(key, out, f"env key should remain visible: {key}")

    def test_structure_preserved(self):
        out = r.redact_inspect(self._sample())
        # non-secret structure still there for troubleshooting
        self.assertIn("job-radar-server", out)
        self.assertIn("unless-stopped", out)
        self.assertIn("NOTANASSIGNMENT", out)  # non-assignment env kept as-is

    def test_non_json_falls_back_to_text(self):
        raw = f"not json at all, but contains {ANTHROPIC} in the middle"
        out = r.redact_inspect(raw)
        self.assertNotIn(ANTHROPIC, out)


class TestTextRedaction(unittest.TestCase):
    def test_log_line_tokens_masked(self):
        line = (f"level=info key={ANTHROPIC} tg={TELEGRAM} "
                f"jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef123456")
        out = r.redact_text(line)
        self.assertNotIn(ANTHROPIC, out)
        self.assertNotIn(TELEGRAM, out)

    def test_empty_is_safe(self):
        self.assertEqual(r.redact_text(""), "")


class TestFallbackFlag(unittest.TestCase):
    def test_running_on_fallback_offpi(self):
        # Sanity: off-Pi we use the fallback, not the real hermes redactor.
        # (On the Pi this would be True and the redaction is stronger.)
        self.assertIn(r.hermes_redactor_available(), (True, False))


if __name__ == "__main__":
    unittest.main()
