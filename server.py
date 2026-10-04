"""Docker MCP Guardian: a read-only-by-default Docker MCP server over stdio.

Every tool returns a JSON-serializable dict with an ``ok`` flag instead of
raising, so a missing daemon, a socket timeout, or a bad container name
never tears down the stdio JSON-RPC transport. Nothing is ever printed to
stdout — stdout is the protocol channel; diagnostics go to stderr logging.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from typing import Any

import docker
from docker.errors import APIError, DockerException, NotFound
from mcp.server.fastmcp import FastMCP
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout

logging.basicConfig(stream=sys.stderr, level=os.environ.get("GUARDIAN_LOG_LEVEL", "INFO"))
log = logging.getLogger("docker-mcp-guardian")

DEFAULT_DENY_PATTERN = r"^(prod|db|kube|vault)-.*"
DEFAULT_ANOMALY_PATTERN = (
    r"(?i)\b(error|exception|fatal|panic|traceback|critical|oomkilled|out of memory|segfault|refused|timed? ?out)\b"
)
CONTAINER_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MAX_TAIL = 5000
MAX_RETURNED_LINES = 500

mcp = FastMCP("docker-mcp-guardian")


# ---------------------------------------------------------------------------
# Configuration (read per call so tests and operators can change env safely)
# ---------------------------------------------------------------------------

def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _socket_timeout() -> int:
    try:
        return max(1, int(os.environ.get("GUARDIAN_DOCKER_TIMEOUT", "5")))
    except ValueError:
        return 5


def _deny_regex() -> re.Pattern[str]:
    return re.compile(os.environ.get("GUARDIAN_RESTART_DENY_REGEX", DEFAULT_DENY_PATTERN))


def _allow_regex() -> re.Pattern[str] | None:
    pattern = os.environ.get("GUARDIAN_RESTART_ALLOW_REGEX", "").strip()
    return re.compile(pattern) if pattern else None


def _error(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": {"code": code, "message": message, **extra}}


# ---------------------------------------------------------------------------
# Docker client handling
# ---------------------------------------------------------------------------

class DaemonUnavailable(Exception):
    """Raised internally when the Docker daemon cannot be reached."""


def get_client() -> docker.DockerClient:
    """Connect via DOCKER_HOST / the default socket, with a bounded timeout.

    ``ping()`` forces a round trip so a dead or missing socket surfaces here,
    not halfway through a tool call.
    """
    try:
        client = docker.from_env(timeout=_socket_timeout())
        client.ping()
        return client
    except (DockerException, RequestsConnectionError, ReadTimeout, OSError) as exc:
        raise DaemonUnavailable(str(exc)) from exc


def _validate_ref(ref: str) -> dict[str, Any] | None:
    if not isinstance(ref, str) or not CONTAINER_REF_RE.match(ref):
        return _error("invalid_container_ref", "Container reference must be a name or ID: [A-Za-z0-9_.-], max 128 chars.")
    return None


def _run(action):
    """Run ``action(client)``, translating every daemon failure into a structured error."""
    try:
        client = get_client()
    except DaemonUnavailable as exc:
        log.warning("Docker daemon unavailable: %s", exc)
        return _error("daemon_unavailable", "Docker daemon is unreachable or timed out.", detail=str(exc))
    try:
        return action(client)
    except NotFound as exc:
        return _error("not_found", "No such container.", detail=str(exc))
    except (ReadTimeout, RequestsConnectionError) as exc:
        return _error("daemon_unavailable", "Docker daemon timed out mid-request.", detail=str(exc))
    except APIError as exc:
        return _error("docker_api_error", "Docker API rejected the request.", detail=str(exc))
    except DockerException as exc:
        return _error("docker_error", "Docker client error.", detail=str(exc))


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested directly)
# ---------------------------------------------------------------------------

def restart_policy_decision(name: str) -> tuple[bool, str]:
    """Return (allowed, reason) for restarting a container with this resolved name."""
    if not _env_flag("GUARDIAN_ALLOW_WRITE"):
        return False, "Server is in read-only mode (set GUARDIAN_ALLOW_WRITE=true to enable restarts)."
    if _deny_regex().search(name):
        return False, f"Container '{name}' matches the protected denylist pattern."
    allow = _allow_regex()
    if allow is not None and not allow.search(name):
        return False, f"Container '{name}' is not on the restart allowlist."
    return True, "allowed"


def scan_log_anomalies(text: str, pattern: str | None = None) -> dict[str, Any]:
    regex = re.compile(pattern or os.environ.get("GUARDIAN_ANOMALY_REGEX", DEFAULT_ANOMALY_PATTERN))
    lines = text.splitlines()
    hits = [
        {"line_number": i, "match": m.group(0), "line": line[:1000]}
        for i, line in enumerate(lines, start=1)
        if (m := regex.search(line))
    ]
    counts: dict[str, int] = {}
    for hit in hits:
        key = hit["match"].lower()
        counts[key] = counts.get(key, 0) + 1
    return {
        "total_lines": len(lines),
        "anomaly_count": len(hits),
        "anomaly_ratio": round(len(hits) / len(lines), 4) if lines else 0.0,
        "counts_by_keyword": counts,
        "anomalies": hits[:MAX_RETURNED_LINES],
        "truncated": len(hits) > MAX_RETURNED_LINES,
    }


def _summarize(container) -> dict[str, Any]:
    attrs = container.attrs or {}
    state = attrs.get("State", {})
    return {
        "id": container.short_id,
        "name": container.name,
        "image": (container.image.tags[0] if container.image and container.image.tags else attrs.get("Config", {}).get("Image")),
        "status": container.status,
        "health": (state.get("Health") or {}).get("Status"),
        "restart_count": attrs.get("RestartCount"),
        "started_at": state.get("StartedAt"),
    }


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_containers(all: bool = False) -> dict[str, Any]:
    """List containers (running only unless all=true). Read-only."""
    return _run(lambda c: {"ok": True, "containers": [_summarize(x) for x in c.containers.list(all=all)]})


@mcp.tool()
def inspect_container(container: str) -> dict[str, Any]:
    """Inspect a container's state, config, and networking. Read-only; env values are redacted."""
    if bad := _validate_ref(container):
        return bad

    def action(c):
        obj = c.containers.get(container)
        attrs = obj.attrs or {}
        config = attrs.get("Config", {})
        env_keys = [e.split("=", 1)[0] for e in (config.get("Env") or [])]
        return {
            "ok": True,
            "container": {
                **_summarize(obj),
                "created": attrs.get("Created"),
                "exit_code": attrs.get("State", {}).get("ExitCode"),
                "oom_killed": attrs.get("State", {}).get("OOMKilled"),
                "env_keys": env_keys,  # values deliberately withheld — they routinely carry secrets
                "labels": config.get("Labels") or {},
                "ports": attrs.get("NetworkSettings", {}).get("Ports") or {},
                "mounts": [
                    {"source": m.get("Source"), "destination": m.get("Destination"), "rw": m.get("RW")}
                    for m in attrs.get("Mounts") or []
                ],
                "restart_policy": attrs.get("HostConfig", {}).get("RestartPolicy"),
            },
        }

    return _run(action)


@mcp.tool()
def get_container_logs(container: str, tail: int = 200, anomaly_regex: str | None = None) -> dict[str, Any]:
    """Fetch the last `tail` log lines and scan them for error anomalies. Read-only."""
    if bad := _validate_ref(container):
        return bad
    if not isinstance(tail, int) or not 1 <= tail <= MAX_TAIL:
        return _error("invalid_tail", f"tail must be between 1 and {MAX_TAIL}.")
    if anomaly_regex is not None:
        try:
            re.compile(anomaly_regex)
        except re.error as exc:
            return _error("invalid_regex", f"anomaly_regex does not compile: {exc}")

    def action(c):
        obj = c.containers.get(container)
        raw = obj.logs(tail=tail, stdout=True, stderr=True, timestamps=False)
        text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        lines = text.splitlines()
        return {
            "ok": True,
            "container": obj.name,
            "tail": tail,
            "lines": lines[-MAX_RETURNED_LINES:],
            "scan": scan_log_anomalies(text, anomaly_regex),
        }

    return _run(action)


@mcp.tool()
def safe_restart_container(container: str, timeout: int = 10) -> dict[str, Any]:
    """Restart a container only if write mode is enabled and its name passes the deny/allow guard."""
    if bad := _validate_ref(container):
        return bad
    if not isinstance(timeout, int) or not 0 <= timeout <= 120:
        return _error("invalid_timeout", "timeout must be between 0 and 120 seconds.")
    if not _env_flag("GUARDIAN_ALLOW_WRITE"):
        # Fail closed before touching the daemon at all.
        _, reason = restart_policy_decision(container)
        return _error("forbidden", reason)

    def action(c):
        obj = c.containers.get(container)
        # Decide on the daemon-resolved name, never the caller's input — otherwise
        # passing a container ID would bypass the name-based denylist.
        resolved = obj.name.lstrip("/")
        allowed, reason = restart_policy_decision(resolved)
        if not allowed:
            log.warning("Blocked restart of %s: %s", resolved, reason)
            return _error("forbidden", reason, container=resolved)
        obj.restart(timeout=timeout)
        obj.reload()
        log.info("Restarted container %s", resolved)
        return {"ok": True, "container": resolved, "status": obj.status}

    return _run(action)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
