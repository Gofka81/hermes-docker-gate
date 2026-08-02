"""hermes-docker-gate — safe Docker read/manage for Hermes, from Telegram.

Reads (ps/logs/inspect/stats) run instantly with secrets redacted; writes
(deploy/network_connect) require the user's Telegram approval via Hermes' native
approval gate; the terminal tool is blocked from touching Docker directly.

Loaded by the Hermes plugin loader, which calls ``register(ctx)`` once.
"""
from __future__ import annotations

try:  # package (installed under plugins/) or standalone (tests/dev)
    from .tools import TOOLS, _check_docker_available
    from .hook import on_pre_tool_call
except ImportError:  # pragma: no cover
    from tools import TOOLS, _check_docker_available  # type: ignore
    from hook import on_pre_tool_call  # type: ignore

__all__ = ["register"]


def register(ctx) -> None:
    """Register the docker tools + the pre_tool_call gate."""
    for name, schema, handler, emoji in TOOLS:
        ctx.register_tool(
            name=name,
            toolset="docker",
            schema=schema,
            handler=handler,
            check_fn=_check_docker_available,
            emoji=emoji,
        )
    # The gate: blocks raw terminal Docker + routes writes to native approval.
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
