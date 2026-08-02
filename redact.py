"""Secret redaction for hermes-docker-gate read tools.

Two layers:
  1. A docker-specific structural pass that masks EVERY env-var *value* in
     ``docker inspect`` output while keeping the keys — this covers *prefixless*
     secrets (e.g. ``TELEGRAM_BOT_TOKEN=123:AAH...``, ``GPG_KEY=...``) that
     pattern-based redaction misses.
  2. Hermes' own ``agent.redact.redact_sensitive_text`` as a catch-all for
     tokens hiding anywhere else (Cmd, Labels, mount specs, log lines).

Layer 2 is imported lazily with a safe fallback so this module (and its tests)
run off-Pi where the ``agent`` package isn't importable. On the real hermes
runtime the genuine redactor is used; in tests/fallback a conservative local
regex stands in so output is never returned raw.
"""
from __future__ import annotations

import json
import re
from typing import Callable

__all__ = ["redact_inspect", "redact_text", "REDACTED", "hermes_redactor_available"]

REDACTED = "[REDACTED]"  # ASCII marker — survives JSON encoding + any terminal/font


def _load_hermes_redactor() -> tuple[Callable[..., str], bool]:
    """Return (redactor, is_real). Falls back to a local regex off-Pi."""
    try:
        from agent.redact import redact_sensitive_text  # type: ignore

        def _real(text: str) -> str:
            return redact_sensitive_text(text, force=True)

        return _real, True
    except Exception:
        return _fallback_redact, False


# --- Fallback redactor (only used when hermes' agent.redact is unavailable) ---
# Conservative: masks common secret-shaped tokens so a test/off-Pi run never
# emits a raw credential. The REAL redactor is far more thorough.
_FALLBACK_PATTERNS = [
    re.compile(r"\b(sk-[A-Za-z0-9_-]{12,})"),          # OpenAI/DeepSeek/Anthropic keys
    re.compile(r"\b(gsk_[A-Za-z0-9]{20,})"),           # Groq
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})"),     # GitHub tokens
    re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})"),   # Slack
    re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,})"),  # JWT
    re.compile(r"\b(\d{6,}:AA[A-Za-z0-9_-]{30,})"),    # Telegram bot token
]


def _fallback_redact(text: str) -> str:
    if not text:
        return text
    out = text
    for pat in _FALLBACK_PATTERNS:
        out = pat.sub(REDACTED, out)
    return out


_HERMES_REDACTOR, _HERMES_REAL = _load_hermes_redactor()


def hermes_redactor_available() -> bool:
    """True when running against the genuine hermes redactor (not the fallback)."""
    return _HERMES_REAL


def redact_text(text: str) -> str:
    """Redact free-form output (logs / ps / stats) via hermes' redactor (or fallback)."""
    if not text:
        return text
    return _HERMES_REDACTOR(text)


def _mask_env_list(env):
    """Replace each ``KEY=VALUE`` with ``KEY=‹redacted›``; keep non-assignments."""
    masked = []
    for item in env:
        if isinstance(item, str) and "=" in item:
            key = item.split("=", 1)[0]
            masked.append(f"{key}={REDACTED}")
        else:
            masked.append(item)
    return masked


def redact_inspect(raw: str) -> str:
    """Redact ``docker inspect`` output: mask every env value, keep keys.

    Structural masking guarantees prefixless secrets are covered; the result is
    then passed through the general redactor to catch tokens elsewhere. If the
    input isn't valid JSON, falls back to text redaction so nothing leaks.
    """
    if not raw:
        return raw
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return redact_text(raw)

    containers = data if isinstance(data, list) else [data]
    for cont in containers:
        if not isinstance(cont, dict):
            continue
        cfg = cont.get("Config")
        if isinstance(cfg, dict) and isinstance(cfg.get("Env"), list):
            cfg["Env"] = _mask_env_list(cfg["Env"])

    dumped = json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False)
    return redact_text(dumped)  # catch-all over Cmd/Labels/mounts/etc.
