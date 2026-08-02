# hermes-docker-gate

Safe Docker **read + manage** for a [Hermes](https://github.com/NousResearch/hermes-agent)
agent — driven from Telegram (or any Hermes platform), with secrets redacted and
every change gated behind your explicit approval.

- 🔍 **Reads run instantly, redacted** — `docker_ps`, `docker_logs`, `docker_inspect`, `docker_stats`. Secret env values are masked (keys kept) so `inspect` can't leak API keys/tokens into the chat, the model, or your LLM provider.
- 🔐 **Writes need your approval** — `docker_deploy`, `docker_network_connect` are validated, then escalated to Hermes' **native approval gate** (the same one that guards `rm -rf`). Nothing changes until you approve in Telegram.
- 🚫 **No side door** — the agent's terminal tool is blocked from touching Docker directly, so the redaction and approval can't be bypassed.

## Security model

Three layers, in order:

1. **The terminal can't reach Docker.** A `pre_tool_call` hook blocks any raw
   `docker` / `podman` / `docker-compose`, socket, or docker-proxy access from
   the shell tool, forcing everything through this plugin's tools.
2. **Writes require human approval.** Write tools return the native `approve`
   directive → Hermes prompts you in Telegram and blocks until you answer
   (supports once / session / always / deny, fails closed on timeout). The
   agent cannot self-approve — approval is dispatched by the gateway.
3. **Blast-radius limits (defense-in-depth).** `validator.py` rejects
   host-escape vectors (`--privileged`, `--cap-add`, `--device`, host
   namespaces, bind-mounts of `/`, `/etc`, `/var/run/docker.sock`, …) and
   shell-injection names — so even an approved write can't break out to the
   host or shell out.

Reads are redacted by `redact.py`, which masks **every** env value structurally
(covering prefixless secrets that pattern-matching misses) and reuses Hermes'
own `redact_sensitive_text` as a catch-all.

## Tools

| Tool | Kind | Approval |
|---|---|---|
| `docker_ps` | read | none |
| `docker_logs` | read | none |
| `docker_inspect` | read (redacted) | none |
| `docker_stats` | read | none |
| `docker_deploy` | write | **Telegram** |
| `docker_network_connect` | write | **Telegram** |

## Requirements

- Hermes agent with the plugin loader (this is a `kind: backend` plugin).
- A reachable Docker endpoint via `DOCKER_HOST`. **Do not** point the agent at
  the raw root socket without understanding the trade-off — a read-only
  [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) for
  reads is the safer default; writes need a write-capable endpoint. The plugin
  is agnostic to how `DOCKER_HOST` is provisioned.

## Install (generic)

Drop this directory into your Hermes plugins path (e.g. `~/.hermes/plugins/`),
ensure `DOCKER_HOST` is set for the agent, and restart the gateway. The plugin
auto-loads and its tools appear once Docker is reachable.

## Tests

Pure-logic core, no Docker required:

```
python3 tests/test_validator.py
python3 tests/test_redact.py
python3 tests/test_hook.py
```

## Status

v0.1 — read tools + approval-gated writes. The hardening variant (dedicated
`docker-gate` OS user + sudoers + one-shot token, for adversarial/multi-user
threat models) is a planned v2.

MIT licensed.
