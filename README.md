# Docker MCP Guardian

A security-hardened Model Context Protocol (MCP) server written in Python with FastMCP that connects local LLM agents (Claude Desktop, Claude Code) to the Docker daemon with strict zero-trust boundaries.

[![CI](https://github.com/SivaSaiKrishnaSuryadevara/docker-mcp-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/SivaSaiKrishnaSuryadevara/docker-mcp-guardian/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Core Capabilities & Safeguards

- **Read-Only by Default:** Mutation tools (`safe_restart_container`) reject calls before touching the Docker socket unless `GUARDIAN_ALLOW_WRITE=true` is explicitly set.
- **Canonical ID Resolution:** Resolves container IDs to Docker's internal canonical name before evaluating regex denylists, preventing evasion via hex IDs.
- **Credential & Secret Redaction:** `inspect_container` strips all environment variable values, returning only variable keys to prevent LLM prompt leakage.
- **Isolated Stdio JSON-RPC:** Strict logging separation ensures zero unstructured stdout writes, preventing JSON-RPC stream corruption in MCP clients.
- **Bounded Daemon Timeouts:** Every Docker API call is capped by `GUARDIAN_DOCKER_TIMEOUT` (default 5s), so a wedged or missing daemon returns a structured `daemon_unavailable` error instead of hanging the session.

## Quickstart

### Prerequisites
- Python 3.10+
- Docker Engine / Docker Desktop
- `mcp>=1.0.0,<2` (pinned to FastMCP API)

### Local Installation
```bash
git clone https://github.com/SivaSaiKrishnaSuryadevara/docker-mcp-guardian.git
cd docker-mcp-guardian
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest tests/ -v
```

### Connect to Claude Code
```bash
claude mcp add docker-guardian -- "$PWD/.venv/bin/python" "$PWD/server.py"
```

For Claude Desktop, add the same interpreter and script paths (absolute) under `mcpServers` in `claude_desktop_config.json`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GUARDIAN_ALLOW_WRITE` | `false` | Must be `true` for `safe_restart_container` to do anything |
| `GUARDIAN_RESTART_DENY_REGEX` | `^(prod\|db\|kube\|vault)-.*` | Containers that can never be restarted (always wins) |
| `GUARDIAN_RESTART_ALLOW_REGEX` | *(unset)* | If set, only matching containers can be restarted |
| `GUARDIAN_ANOMALY_REGEX` | error/exception/fatal/... | Pattern the log scanner flags |
| `GUARDIAN_REGEX_TIMEOUT` | `1` | Total seconds one log scan may spend matching; slower scans return `regex_timeout` |
| `GUARDIAN_DOCKER_TIMEOUT` | `5` | Seconds per Docker API call |
| `GUARDIAN_LOG_LEVEL` | `INFO` | Log level (logs go to stderr only) |
| `DOCKER_HOST` | *(unset)* | Docker endpoint to use; always wins when set |
| `GUARDIAN_ALLOW_ROOTFUL` | `false` | Allow falling back to the rootful `/var/run/docker.sock` |

### Docker endpoint resolution

Guardian picks its Docker endpoint in this order, and logs the choice to stderr:

1. `DOCKER_HOST`, if set.
2. A rootless Docker socket: `$XDG_RUNTIME_DIR/docker.sock`, then `/run/user/<uid>/docker.sock`. The second path covers MCP clients that start servers without `XDG_RUNTIME_DIR`.
3. The rootful `/var/run/docker.sock`, only when `GUARDIAN_ALLOW_ROOTFUL=true`. Guardian logs a warning, because rootful API access is root-equivalent.

If none applies, tools return a `docker_socket_unresolved` error instead of connecting. The system socket is never used while a rootless socket exists.

> **Upgrading:** earlier versions fell back to `/var/run/docker.sock` silently. If you rely on the rootful daemon, set `DOCKER_HOST=unix:///var/run/docker.sock` (or `GUARDIAN_ALLOW_ROOTFUL=true`) in your MCP server definition. Docker Desktop and Colima users should set `DOCKER_HOST` to their socket, for example `unix://$HOME/.docker/run/docker.sock` or `unix://$HOME/.colima/default/docker.sock`.

### Rootless Docker

MCP clients (Claude Desktop, Claude Code, Cursor, Cline) start Guardian as a child process, often with a reduced environment that has no `XDG_RUNTIME_DIR` or `DOCKER_HOST`. Guardian still checks `/run/user/<uid>/docker.sock`, but if your rootless runtime directory is elsewhere, or you want the endpoint pinned, set `DOCKER_HOST` in the server definition:

```json
{
  "mcpServers": {
    "docker-guardian": {
      "command": "/path/to/docker-mcp-guardian/.venv/bin/python",
      "args": ["/path/to/docker-mcp-guardian/server.py"],
      "env": {
        "DOCKER_HOST": "unix:///run/user/1000/docker.sock"
      }
    }
  }
}
```

Write the path literally: most clients do not expand `$XDG_RUNTIME_DIR` or `$HOME` in `env`. To find the value for your user, run either of these in a shell where rootless Docker works:

```bash
echo "unix://$XDG_RUNTIME_DIR/docker.sock"
docker context inspect rootless --format '{{.Endpoints.docker.Host}}'
```

With Claude Code, the shell expands the variable when the server is added:

```bash
claude mcp add docker-guardian -e DOCKER_HOST="unix://$XDG_RUNTIME_DIR/docker.sock" -- "$PWD/.venv/bin/python" "$PWD/server.py"
```

To confirm the endpoint is the rootless daemon, check that this lists `name=rootless`:

```bash
DOCKER_HOST=unix:///run/user/1000/docker.sock docker info --format '{{.SecurityOptions}}'
```

On the first tool call, Guardian logs the endpoint it chose to stderr, for example `Using Docker endpoint unix:///run/user/1000/docker.sock (DOCKER_HOST is set).`

## Verifying Release Images

Release images are published to `ghcr.io/sivasaikrishnasuryadevara/docker-mcp-guardian` for `linux/amd64` and `linux/arm64` by [`release-signed.yml`](.github/workflows/release-signed.yml) when a `v*.*.*` tag is pushed. Each image is:

- **signed** with keyless [Sigstore cosign](https://docs.sigstore.dev/): the signing certificate is bound to this repository's release workflow through GitHub OIDC, and the signature is recorded in the public Rekor transparency log. No signing key exists to leak.
- **attested** with a [GitHub build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations) (SLSA provenance) for the same image digest.

Verify both before running an image (requires cosign 3.x and the GitHub CLI):

```bash
IMAGE=ghcr.io/sivasaikrishnasuryadevara/docker-mcp-guardian:<version>   # e.g. 1.0.0

# 1. Sigstore signature: issued to this repository's release workflow, for a version tag.
cosign verify "$IMAGE" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/SivaSaiKrishnaSuryadevara/docker-mcp-guardian/\.github/workflows/release-signed\.yml@refs/tags/v'

# 2. Build provenance: built by this repository's GitHub Actions workflow.
gh attestation verify "oci://$IMAGE" --repo SivaSaiKrishnaSuryadevara/docker-mcp-guardian
```

Both commands exit non-zero if the image was not built and signed by this repository's release workflow. To run exactly what you verified, pull by digest: `docker pull ghcr.io/sivasaikrishnasuryadevara/docker-mcp-guardian@sha256:<digest>`, using the digest that `cosign verify` prints.

## Write-up

The security model, tool surface, and policy engine are documented in [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md).

## Deep Dive & Publications

- **[Don't Hand Claude Your Docker Socket — Build It a Guarded One](https://hackernoon.com/dont-hand-claude-your-docker-socket-build-it-a-guarded-one)** (HackerNoon, October 21, 2026): why handing an AI agent the raw Docker socket is root-equivalent, and how this server's read-only default, canonical-name restart deny-list, secret redaction and bounded Docker API timeouts contain it.
