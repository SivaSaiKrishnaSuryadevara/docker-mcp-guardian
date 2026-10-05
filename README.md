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
| `GUARDIAN_DOCKER_TIMEOUT` | `5` | Seconds per Docker API call |
| `GUARDIAN_LOG_LEVEL` | `INFO` | Log level (logs go to stderr only) |

## Write-up

The security model, tool surface, and policy engine are documented in [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md).

## Deep Dive & Publications

A hands-on implementation and security analysis guide is currently under editorial review for HackerNoon. The direct publication link will be posted here upon release.
