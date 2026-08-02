"""Escape-flag / dangerous-argument validation for hermes-docker-gate.

Defense-in-depth for the write tools. v1 write tools take *structured* params
(name, image, ports, env, volumes, network) and build the docker invocation as
an argument array from templates — so raw flags like ``--privileged`` can't be
injected in the first place. This module validates the few structured fields
that *can* still be dangerous (volume host paths, a ``host`` network, shell
metacharacters in names) and additionally scans any free-form token list for
host-escape flags, so a future tool that forwards raw args is still covered.

Pure logic — no Docker, no I/O — so it unit-tests in isolation, off-Pi.
"""
from __future__ import annotations

import re
from typing import Iterable, Sequence

__all__ = [
    "ValidationError",
    "validate_name",
    "validate_image",
    "validate_network_name",
    "validate_volumes",
    "validate_ports",
    "scan_for_escape_flags",
    "validate_deploy",
    "validate_network_connect",
]


class ValidationError(ValueError):
    """Raised when a proposed docker write fails a safety check."""


# Container / network names: must start alphanumeric, then a conservative set.
# Blocks whitespace, quotes, ``;`` ``|`` ``&`` ``$`` ``/`` etc. → no shell/arg
# injection even if a caller ever interpolates the value.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

# Image references legitimately carry ``registry/repo:tag@sha256:...`` so allow
# ``/`` ``:`` ``@`` — but still no whitespace or shell metacharacters.
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:@-]{0,255}$")

# Host path prefixes that must never be bind-mounted into a container: mounting
# any of these hands over host root / the docker daemon / kernel interfaces.
_SENSITIVE_MOUNT_PREFIXES = (
    "/",              # bare root — the classic escape (matched exactly below)
    "/etc",
    "/root",
    "/home",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/var/run",       # covers /var/run/docker.sock
    "/run",           # covers /run/docker.sock
    "/var/lib/docker",
)

# Escape-granting flags (or their ``=host`` namespace forms) for the raw-token
# scanner. Compared case-insensitively; both ``--flag value`` and ``--flag=value``
# spellings are handled by scan_for_escape_flags.
_DANGEROUS_FLAGS = {
    "--privileged",
    "--cap-add",
    "--device",
    "--device-cgroup-rule",
    "--security-opt",
    "--sysctl",
}
_HOST_NAMESPACE_FLAGS = {"--pid", "--ipc", "--uts", "--userns", "--network", "--net"}
_MOUNT_FLAGS = {"-v", "--volume", "--mount"}


def _norm(path: str) -> str:
    """Collapse a host path for prefix comparison (no filesystem access)."""
    p = (path or "").strip()
    # strip trailing slash except for the root itself
    if len(p) > 1:
        p = p.rstrip("/")
    return p


def _is_sensitive_host_path(host_path: str) -> bool:
    p = _norm(host_path)
    if not p.startswith("/"):
        return False  # named volume or relative — not a host bind of a system dir
    if p == "/":
        return True
    for pref in _SENSITIVE_MOUNT_PREFIXES:
        if pref == "/":
            continue
        if p == pref or p.startswith(pref + "/"):
            return True
    return False


def validate_name(name: str, *, kind: str = "container") -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ValidationError(
            f"invalid {kind} name {name!r}: must match [A-Za-z0-9][A-Za-z0-9_.-]* "
            f"(no spaces or shell characters)"
        )
    return name


def validate_image(image: str) -> str:
    if not isinstance(image, str) or not _IMAGE_RE.match(image):
        raise ValidationError(
            f"invalid image reference {image!r}: unexpected characters"
        )
    return image


def validate_network_name(network: str) -> str:
    validate_name(network, kind="network")
    if network in {"host", "none", "bridge", "container"} or network.startswith("container:"):
        raise ValidationError(
            f"network {network!r} is not allowed: 'host'/'container:' networking "
            f"breaks isolation; connect only to user-defined networks"
        )
    return network


def validate_volumes(volumes: Iterable[str]) -> None:
    """Reject any bind mount whose host source is a sensitive system path.

    Accepts short ``host:container[:ro]`` specs and named volumes (``name:/path``).
    """
    for spec in volumes or ():
        if not isinstance(spec, str) or not spec.strip():
            raise ValidationError(f"invalid volume spec {spec!r}")
        parts = spec.split(":")
        source = parts[0].strip()
        if _is_sensitive_host_path(source):
            raise ValidationError(
                f"refusing volume {spec!r}: host path {source!r} is a protected "
                f"system location (would expose host root / docker / kernel)"
            )


def validate_ports(ports: Iterable[str]) -> None:
    """Only allow ``[host:]container[/proto]`` with numeric ports."""
    for spec in ports or ():
        if not isinstance(spec, str) or not spec.strip():
            raise ValidationError(f"invalid port spec {spec!r}")
        mapping = spec.split("/", 1)[0]  # drop optional /tcp|/udp
        nums = mapping.split(":")
        if not (1 <= len(nums) <= 2) or not all(n.isdigit() and 0 < int(n) < 65536 for n in nums):
            raise ValidationError(
                f"invalid port mapping {spec!r}: expected numeric [host:]container"
            )


def scan_for_escape_flags(tokens: Sequence[str]) -> None:
    """Reject a raw docker-run token list carrying any host-escape vector.

    Handles ``--flag value``, ``--flag=value``, and volume mounts of sensitive
    host paths. Belt-and-suspenders for any path that forwards free-form args.
    """
    toks = list(tokens or ())
    i = 0
    while i < len(toks):
        raw = toks[i]
        tok = raw.lower()
        flag, _, inline = tok.partition("=")

        if flag in _DANGEROUS_FLAGS:
            raise ValidationError(f"refusing escape flag {raw!r}")

        if flag in _HOST_NAMESPACE_FLAGS:
            value = inline if "=" in tok else (toks[i + 1].lower() if i + 1 < len(toks) else "")
            if value == "host" or value.startswith("host"):
                raise ValidationError(f"refusing host namespace: {raw} {value}".strip())

        if flag in _MOUNT_FLAGS:
            value = raw.split("=", 1)[1] if "=" in raw else (toks[i + 1] if i + 1 < len(toks) else "")
            if flag == "--mount":
                # type=bind,source=/,target=/x  → pull source= / src=
                for kv in value.split(","):
                    k, _, v = kv.partition("=")
                    if k.strip() in {"source", "src"} and _is_sensitive_host_path(v):
                        raise ValidationError(f"refusing mount of sensitive host path in {value!r}")
            else:
                if _is_sensitive_host_path(value.split(":", 1)[0]):
                    raise ValidationError(f"refusing volume mount {value!r}")
        i += 1


def validate_deploy(
    *,
    name: str,
    image: str,
    ports: Iterable[str] = (),
    volumes: Iterable[str] = (),
    network: str | None = None,
    extra_args: Sequence[str] = (),
) -> None:
    """Validate a structured deploy request. Raises ValidationError on any issue."""
    validate_name(name)
    validate_image(image)
    validate_ports(ports)
    validate_volumes(volumes)
    if network is not None:
        validate_network_name(network)
    if extra_args:
        scan_for_escape_flags(extra_args)


def validate_network_connect(*, network: str, container: str) -> None:
    validate_network_name(network)
    validate_name(container)
