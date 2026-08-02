"""Docker tools for hermes-docker-gate.

Read tools (ps/logs/inspect/stats) run instantly and their output is redacted.
Write tools (deploy/network_connect) are validated here (defense-in-depth) and
execute only after the pre_tool_call hook has secured Telegram approval — by the
time a write handler runs, approval was already granted (or the tool was blocked).

All Docker calls go through the `docker` CLI as an ARGUMENT ARRAY (never a shell
string), so container names/args can't inject. The CLI talks to whatever
`DOCKER_HOST` points at (read-only proxy for reads; a write-capable socket once
writes are enabled) — this module is agnostic to that.
"""
from __future__ import annotations

import subprocess
from typing import Iterable

# --- hermes runtime helpers (graceful fallback so the module imports off-Pi) ---
try:  # pragma: no cover - exercised on the hermes runtime
    from tools.registry import tool_error, tool_result  # type: ignore
except Exception:  # pragma: no cover
    def tool_result(text: str, **_kw) -> str:  # type: ignore
        return text

    def tool_error(msg: str, **_kw) -> str:  # type: ignore
        return f"ERROR: {msg}"

# --- sibling modules: work both as a package (.x) and standalone (x) ---
try:  # pragma: no cover
    from . import validator as V
    from . import redact as R
except ImportError:  # pragma: no cover
    import validator as V  # type: ignore
    import redact as R  # type: ignore

_DOCKER = "docker"
_READ_TIMEOUT = 30
_WRITE_TIMEOUT = 120


def _check_docker_available() -> bool:
    """Gate: only expose the tools if the docker CLI + endpoint are reachable."""
    try:
        p = subprocess.run(
            [_DOCKER, "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=8,
        )
        return p.returncode == 0
    except Exception:
        return False


def _docker(args: list[str], timeout: int = _READ_TIMEOUT) -> tuple[int, str, str]:
    """Run `docker <args>` as an arg array (no shell). Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            [_DOCKER, *args], capture_output=True, text=True, timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"docker {args[0] if args else ''} timed out after {timeout}s"
    except FileNotFoundError:
        return 127, "", "docker CLI not found in this container"
    except Exception as exc:  # pragma: no cover
        return 1, "", f"failed to run docker: {type(exc).__name__}: {exc}"


# ============================ READ TOOLS ============================

DOCKER_PS_SCHEMA = {
    "type": "object",
    "properties": {
        "all": {"type": "boolean", "description": "Include stopped containers.", "default": True},
    },
    "additionalProperties": False,
}


def _handle_docker_ps(args: dict, **_kw) -> str:
    cmd = ["ps", "--format",
           "table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}"]
    if args.get("all", True):
        cmd.insert(1, "-a")
    rc, out, err = _docker(cmd)
    if rc != 0:
        return tool_error(err.strip() or "docker ps failed")
    return tool_result(R.redact_text(out))


DOCKER_LOGS_SCHEMA = {
    "type": "object",
    "properties": {
        "container": {"type": "string", "description": "Container name or id."},
        "tail": {"type": "integer", "description": "Lines from the end.", "default": 200},
    },
    "required": ["container"],
    "additionalProperties": False,
}


def _handle_docker_logs(args: dict, **_kw) -> str:
    try:
        name = V.validate_name(args["container"])
    except (KeyError, V.ValidationError) as exc:
        return tool_error(str(exc) if not isinstance(exc, KeyError) else "container is required")
    tail = args.get("tail", 200)
    tail = 200 if not isinstance(tail, int) or tail <= 0 else min(tail, 2000)
    rc, out, err = _docker(["logs", "--tail", str(tail), name])
    if rc != 0:
        return tool_error(R.redact_text(err.strip()) or "docker logs failed")
    combined = out if out else err  # docker sends some logs to stderr
    return tool_result(R.redact_text(combined))


DOCKER_INSPECT_SCHEMA = {
    "type": "object",
    "properties": {
        "container": {"type": "string", "description": "Container name or id."},
    },
    "required": ["container"],
    "additionalProperties": False,
}


def _handle_docker_inspect(args: dict, **_kw) -> str:
    try:
        name = V.validate_name(args["container"])
    except (KeyError, V.ValidationError) as exc:
        return tool_error(str(exc) if not isinstance(exc, KeyError) else "container is required")
    rc, out, err = _docker(["inspect", name])
    if rc != 0:
        return tool_error(R.redact_text(err.strip()) or "docker inspect failed")
    # Secret-masking (keys kept, values redacted) — the critical read redaction.
    return tool_result(R.redact_inspect(out))


DOCKER_STATS_SCHEMA = {
    "type": "object",
    "properties": {
        "container": {"type": "string", "description": "Optional: one container; omit for all."},
    },
    "additionalProperties": False,
}


def _handle_docker_stats(args: dict, **_kw) -> str:
    cmd = ["stats", "--no-stream", "--format",
           "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"]
    name = args.get("container")
    if name:
        try:
            cmd.append(V.validate_name(name))
        except V.ValidationError as exc:
            return tool_error(str(exc))
    rc, out, err = _docker(cmd)
    if rc != 0:
        return tool_error(err.strip() or "docker stats failed")
    return tool_result(R.redact_text(out))


# ============================ WRITE TOOLS ============================
# These execute only after the pre_tool_call hook secured approval. They still
# re-validate (defense-in-depth) before touching Docker.

DOCKER_DEPLOY_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Container name."},
        "image": {"type": "string", "description": "Image reference, e.g. nginx:1.27."},
        "ports": {"type": "array", "items": {"type": "string"},
                  "description": "Port maps like '8080:80' (numeric)."},
        "volumes": {"type": "array", "items": {"type": "string"},
                    "description": "Bind/volume specs like 'name:/data' (no host system paths)."},
        "network": {"type": "string", "description": "User-defined network to attach (not 'host')."},
    },
    "required": ["name", "image"],
    "additionalProperties": False,
}


def _handle_docker_deploy(args: dict, **_kw) -> str:
    name = args.get("name")
    image = args.get("image")
    ports = args.get("ports") or []
    volumes = args.get("volumes") or []
    network = args.get("network")
    try:
        V.validate_deploy(name=name, image=image, ports=ports,
                          volumes=volumes, network=network)
    except V.ValidationError as exc:
        return tool_error(f"blocked by safety validator: {exc}")

    cmd = ["run", "-d", "--name", name, "--restart", "unless-stopped"]
    if network:
        cmd += ["--network", network]
    for p in ports:
        cmd += ["-p", p]
    for v in volumes:
        cmd += ["-v", v]
    cmd.append(image)

    rc, out, err = _docker(cmd, timeout=_WRITE_TIMEOUT)
    if rc != 0:
        return tool_error(R.redact_text(err.strip()) or "docker run failed")
    cid = out.strip()[:12]
    return tool_result(f"Deployed '{name}' from {image} (id {cid}).")


DOCKER_NETWORK_CONNECT_SCHEMA = {
    "type": "object",
    "properties": {
        "network": {"type": "string", "description": "User-defined network name."},
        "container": {"type": "string", "description": "Container to attach."},
    },
    "required": ["network", "container"],
    "additionalProperties": False,
}


def _handle_docker_network_connect(args: dict, **_kw) -> str:
    network = args.get("network")
    container = args.get("container")
    try:
        V.validate_network_connect(network=network, container=container)
    except V.ValidationError as exc:
        return tool_error(f"blocked by safety validator: {exc}")
    rc, out, err = _docker(["network", "connect", network, container], timeout=_WRITE_TIMEOUT)
    if rc != 0:
        return tool_error(R.redact_text(err.strip()) or "docker network connect failed")
    return tool_result(f"Connected '{container}' to network '{network}'.")


# Sets used by the hook to classify tool calls.
READ_TOOLS = {"docker_ps", "docker_logs", "docker_inspect", "docker_stats"}
WRITE_TOOLS = {"docker_deploy", "docker_network_connect"}

# (name, schema, handler, emoji) — consumed by register() in __init__.py
TOOLS = (
    ("docker_ps", DOCKER_PS_SCHEMA, _handle_docker_ps, "📋"),
    ("docker_logs", DOCKER_LOGS_SCHEMA, _handle_docker_logs, "📜"),
    ("docker_inspect", DOCKER_INSPECT_SCHEMA, _handle_docker_inspect, "🔍"),
    ("docker_stats", DOCKER_STATS_SCHEMA, _handle_docker_stats, "📊"),
    ("docker_deploy", DOCKER_DEPLOY_SCHEMA, _handle_docker_deploy, "🚀"),
    ("docker_network_connect", DOCKER_NETWORK_CONNECT_SCHEMA, _handle_docker_network_connect, "🔌"),
)
