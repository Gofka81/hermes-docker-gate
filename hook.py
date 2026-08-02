"""pre_tool_call gate for hermes-docker-gate.

Two jobs, run before any tool executes:

1. **Force the plugin path.** Block the raw terminal/shell tool from touching
   Docker at all (``docker``/``podman``/``docker-compose``, the socket, or the
   docker-proxy address). This guarantees every Docker interaction goes through
   the plugin's tools — which redact reads and gate writes — with no side door.

2. **Gate writes with human approval.** For the plugin's write tools
   (deploy / network_connect), validate the request (fail fast on escape
   vectors) and return the native ``approve`` directive so hermes escalates to
   the same Telegram approval flow that guards ``rm -rf``. Read tools pass
   straight through.

Returned dicts use the Hermes-canonical shape:
    {"action": "block",   "message": "..."}                     → hard block
    {"action": "approve", "message": "...", "rule_key": "..."}  → human approval
Returning ``None`` allows the call unchanged.
"""
from __future__ import annotations

import re
from typing import Any, Optional

try:  # package or standalone
    from . import validator as V
    from . import tools as T
except ImportError:  # pragma: no cover
    import validator as V  # type: ignore
    import tools as T  # type: ignore

# Tool names whose command string must never reach Docker directly.
_TERMINAL_TOOLS = {"terminal", "bash", "shell", "process", "run_command"}

# Any of these in a terminal command means "you're trying to reach Docker" →
# block and redirect to the docker_* tools. Deliberately broad (catches
# curl --unix-socket, the proxy host, podman, compose).
_DOCKER_REACH = re.compile(
    r"(?:^|[\s;|&/`$(])(?:docker|podman|docker-compose)\b"
    r"|docker\.sock"
    r"|/var/run/docker|/run/docker"
    r"|docker-proxy[:\s]"
    r"|unix://",
    re.IGNORECASE,
)

_REDIRECT_MSG = (
    "Direct Docker access from the terminal is disabled by hermes-docker-gate. "
    "Use the dedicated tools instead: docker_ps, docker_logs, docker_inspect, "
    "docker_stats (read, instant) or docker_deploy / docker_network_connect "
    "(write, require the user's Telegram approval). Reads are redacted; writes "
    "are gated — that protection only applies through these tools."
)


def _extract_tool_name(kwargs: dict) -> str:
    for k in ("tool_name", "name", "tool", "function_name"):
        v = kwargs.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _extract_args(kwargs: dict) -> dict:
    for k in ("args", "tool_args", "function_args", "input", "arguments", "params"):
        v = kwargs.get(k)
        if isinstance(v, dict):
            return v
    return {}


def _command_text(args: dict) -> str:
    for k in ("command", "cmd", "script", "input", "code"):
        v = args.get(k)
        if isinstance(v, str):
            return v
        if isinstance(v, (list, tuple)):
            return " ".join(str(x) for x in v)
    return ""


def _approve(message: str, rule_key: str) -> dict:
    return {"action": "approve", "message": message, "rule_key": rule_key}


def _block(message: str) -> dict:
    return {"action": "block", "message": message}


def _describe_deploy(a: dict) -> str:
    bits = [f"image '{a.get('image')}'"]
    if a.get("network"):
        bits.append(f"network '{a['network']}'")
    if a.get("ports"):
        bits.append(f"ports {list(a['ports'])}")
    if a.get("volumes"):
        bits.append(f"volumes {list(a['volumes'])}")
    return (f"🚀 Deploy container '{a.get('name')}' — " + ", ".join(bits) + ". Approve?")


def on_pre_tool_call(**kwargs: Any) -> Optional[dict]:
    tool = _extract_tool_name(kwargs)
    args = _extract_args(kwargs)

    # 1) Block raw Docker access via the terminal → force the plugin path.
    if tool in _TERMINAL_TOOLS:
        if _DOCKER_REACH.search(_command_text(args)):
            return _block(_REDIRECT_MSG)
        return None

    # 2) Read tools: always allowed (output is redacted in the handler).
    if tool in T.READ_TOOLS:
        return None

    # 3) Write tools: validate first (no point prompting for a doomed command),
    #    then require human approval via the native gate.
    if tool == "docker_deploy":
        try:
            V.validate_deploy(
                name=args.get("name"), image=args.get("image"),
                ports=args.get("ports") or [], volumes=args.get("volumes") or [],
                network=args.get("network"),
            )
        except V.ValidationError as exc:
            return _block(f"docker_deploy blocked by safety validator: {exc}")
        return _approve(_describe_deploy(args), rule_key="docker-gate:deploy")

    if tool == "docker_network_connect":
        try:
            V.validate_network_connect(
                network=args.get("network"), container=args.get("container"),
            )
        except V.ValidationError as exc:
            return _block(f"docker_network_connect blocked by safety validator: {exc}")
        msg = (f"🔌 Connect container '{args.get('container')}' to network "
               f"'{args.get('network')}'. Approve?")
        return _approve(msg, rule_key="docker-gate:network_connect")

    # 4) Everything else: not ours — allow unchanged.
    return None
