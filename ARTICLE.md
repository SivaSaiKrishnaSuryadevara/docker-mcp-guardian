# How to Build a Secure Docker Management MCP Server for Claude Desktop and Claude Code

Here is a line I keep finding in Docker MCP server setups:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

The `:ro` reads like a safety guarantee. It isn't one. A read-only bind mount stops the container from replacing or deleting the socket *file*. It does nothing to the bytes you send through it. Once a process can `connect()` to that Unix socket, it is talking HTTP to the Docker Engine API, and the engine will happily accept `POST /containers/{id}/restart`, `POST /containers/create`, or `DELETE /containers/{id}` over a "read-only" mount.

Now hand that socket to an LLM agent through an MCP server, and the only thing standing between "summarize why my API container keeps crashing" and "restart the production database" is whatever checks you wrote in the tool layer.

I'm a platform engineer, and I wanted Claude to be able to look at my containers without being able to break them. This article walks through the server I built for that: a Python MCP server on FastMCP that exposes four Docker tools to Claude Desktop and Claude Code, is read-only by default, guards the one write operation with a regex denylist that can't be dodged with a container ID, strips secrets out of inspection results, and never crashes the stdio transport when the Docker daemon is down.

Every code block below comes from the working repository, and the test suite at the end runs green: 47 tests, exit code 0.

## What we're building

The server exposes four tools over stdio JSON-RPC:

| Tool | Writes? | What it does |
|---|---|---|
| `list_containers` | No | Lists containers with status, health, restart count |
| `inspect_container` | No | State, ports, mounts, labels, env var *names* only |
| `get_container_logs` | No | Tails logs and scans them for error anomalies |
| `safe_restart_container` | Yes | Restarts a container, only if write mode is on and the name passes the guard |

The repository is deliberately small:

```text
docker-mcp-guardian/
├── server.py              # FastMCP server, tools, guards
├── requirements.txt
├── Dockerfile             # multi-stage, non-root, socket GID mapping
├── docker-compose.yml     # test harness
├── .dockerignore
├── .gitignore
└── tests/
    └── test_server.py     # 47 tests, docker-py fully mocked
```

## Prerequisites

- Python 3.10 or newer. The `mcp` SDK won't install on older versions. On my Mac, the system `python3` was 3.9.6, so I built the virtualenv with Homebrew's 3.13.
- Docker, for actually pointing the server at containers. The test suite doesn't need it.
- Claude Desktop or Claude Code.

## The dependency trap: `mcp` 2.x removed FastMCP

My first `requirements.txt` looked like this:

```text
mcp>=1.0.0
docker>=7.0.0
pydantic>=2.0.0
pytest>=8.0.0
```

`pip` resolved `mcp>=1.0.0` to version 2.3.0, and the very first import failed:

```text
ModuleNotFoundError: No module named 'mcp.server.fastmcp'. This is mcp 2.x,
where FastMCP was renamed to MCPServer (from mcp.server.mcpserver import
MCPServer) and other APIs changed; see the migration guide at
https://py.sdk.modelcontextprotocol.io/v2/migration/#fastmcp-renamed-to-mcpserver
or pin 'mcp<2' to keep running v1 code.
```

To be precise about versions: the package is the official `mcp` Python SDK. FastMCP is the high-level server API that ships inside it in the 1.x line, at `mcp.server.fastmcp`. In 2.x it was renamed to `MCPServer`, and other APIs moved along with it.

A bare lower bound like `mcp>=1.0.0` is a time bomb in any project written against the 1.x API. It installs fine on the day you write it and breaks the first time someone builds after a major release. I capped it:

```text
mcp>=1.0.0,<2
docker>=7.0.0
pydantic>=2.0.0
pytest>=8.0.0
```

That resolved to `mcp` 1.30.0 and the import worked. Migrating to `MCPServer` is a reasonable future step, but it should be a deliberate change, not something a fresh `pip install` does to you.

## Rule zero for stdio servers: stdout belongs to the protocol

Claude Desktop and Claude Code launch a local MCP server as a subprocess and speak JSON-RPC over its stdin and stdout. Every line the client reads from stdout must be a valid JSON-RPC message. One stray `print("connected to docker")` and the client gets a line it can't parse, and the session breaks.

So the first thing in `server.py` is pinning all logging to stderr:

```python
logging.basicConfig(stream=sys.stderr, level=os.environ.get("GUARDIAN_LOG_LEVEL", "INFO"))
log = logging.getLogger("docker-mcp-guardian")
```

The rest of the code follows two rules:

1. Nothing in `server.py` calls `print()`. Diagnostics go through `log`, which writes to stderr, and both Claude clients surface server stderr in their MCP logs.
2. Tools never raise. Every failure comes back as a structured result instead of an exception escaping into the transport layer.

The second rule is enforced by one small helper that every tool returns through:

```python
def _error(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": {"code": code, "message": message, **extra}}
```

Every tool returns `{"ok": True, ...}` or `{"ok": False, "error": {...}}`. Claude gets a machine-readable error code it can reason about (`daemon_unavailable`, `forbidden`, `not_found`) instead of a stack trace.

## Connecting to Docker without hanging or crashing

`docker.from_env()` reads `DOCKER_HOST` and falls back to the default socket. Two failure modes matter for a long-lived stdio server: the daemon isn't there at all, or it's there but not answering. I handle both in one place:

```python
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
```

A few details:

- `timeout=_socket_timeout()` bounds every API call. It defaults to 5 seconds and can be overridden with `GUARDIAN_DOCKER_TIMEOUT`. Without a timeout, a wedged daemon can hang a tool call indefinitely, and the model sits waiting on a response that never comes.
- `client.ping()` makes a missing socket fail here with a clear error, instead of surfacing as a confusing exception halfway through a tool.
- The `except` list is wide on purpose. docker-py raises `DockerException` for most failures, but socket problems can also come through as `requests` connection errors, read timeouts, or a plain `FileNotFoundError` when the socket path doesn't exist. `OSError` covers that last one.

Every tool then runs its Docker work through one wrapper that turns failures into structured errors:

```python
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
```

The client is created per call rather than cached at import time. If Docker Desktop restarts while Claude is open, the next tool call just reconnects instead of reusing a dead client.

## Validating input before it reaches the daemon

Every tool that takes a container reference checks it first:

```python
CONTAINER_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _validate_ref(ref: str) -> dict[str, Any] | None:
    if not isinstance(ref, str) or not CONTAINER_REF_RE.match(ref):
        return _error("invalid_container_ref", "Container reference must be a name or ID: [A-Za-z0-9_.-], max 128 chars.")
    return None
```

docker-py would mostly cope with garbage input on its own. The point is to reject inputs like `../etc`, `web;rm -rf /`, or a 200-character string before any network call, with an error that tells the model exactly what went wrong.

## The read-only tools

### list_containers

```python
@mcp.tool()
def list_containers(all: bool = False) -> dict[str, Any]:
    """List containers (running only unless all=true). Read-only."""
    return _run(lambda c: {"ok": True, "containers": [_summarize(x) for x in c.containers.list(all=all)]})
```

FastMCP builds the tool's JSON schema from the type hints and uses the docstring as the description Claude sees. That docstring is effectively a prompt, so it should say plainly what the tool does and that it's read-only.

### inspect_container: keys yes, values never

`docker inspect` output is one of the easiest ways to leak secrets. `Config.Env` holds every environment variable in plaintext, and in practice that includes `DATABASE_URL=postgres://user:password@...`, API keys, and whatever else someone passed with `-e`.

If an agent calls inspect and gets that blob back, the secrets are now in the model's context. From there they can show up in a chat transcript, a summary, or a later tool call. So the inspection tool returns the env var names and drops the values:

```python
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
```

Keeping the keys is still useful for debugging. "Is `DATABASE_URL` even set in this container?" is a real question, and the model can answer it without ever seeing the value.

The other choice here is an allowlist of fields rather than a filtered copy of `attrs`. The response contains only fields I picked. When a future Docker version adds a new field to inspect output, it won't show up in the model's context unless I add it.

### get_container_logs with an anomaly scanner

Raw logs are noisy, and dumping 5,000 lines into a context window wastes tokens and buries the signal. The logs tool returns the tail plus a structured scan:

```python
DEFAULT_ANOMALY_PATTERN = (
    r"(?i)\b(error|exception|fatal|panic|traceback|critical|oomkilled|out of memory|segfault|refused|timed? ?out)\b"
)


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
```

The `\b` word boundaries matter. Without them, a line like `errorless shutdown` would count as an error. There's a test for exactly that case. Each hit includes its line number, so Claude can point to "line 412" instead of paraphrasing.

The tool itself bounds every input:

```python
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
```

- `tail` is capped at 5,000 (`MAX_TAIL`), and the returned lines and anomaly hits are capped at 500 each (`MAX_RETURNED_LINES`).
- A model-supplied `anomaly_regex` is compiled before anything touches Docker, so a malformed pattern returns `invalid_regex` instead of raising inside the transport.
- Container logs aren't guaranteed to be valid UTF-8. `errors="replace"` means a binary byte in a log line degrades to a replacement character instead of crashing the tool.

## The write path: safe_restart_container

This is the only tool that changes anything, and it has three layers.

### Layer 1: read-only unless explicitly enabled

```python
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
```

Write mode is off unless `GUARDIAN_ALLOW_WRITE` is `true`, `1`, `yes`, or `on`. Anything else, including the variable being unset or misspelled, means no restarts.

The checks run in a fixed order: write mode first, then the denylist, then the optional allowlist. Because the denylist is checked before the allowlist, it always wins. If someone sets `GUARDIAN_RESTART_ALLOW_REGEX=.*` thinking it means "allow everything", `vault-1` is still blocked, and a test covers that case.

### Layer 2: fail closed before touching the socket

In read-only mode, the restart tool refuses before it even connects to the daemon:

```python
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
```

The test suite asserts that `docker.from_env` is never called in this path. If write mode is off, the restart tool can't reach Docker through this server at all.

### Layer 3: decide on the canonical name, not the caller's input

This is the bug I'd most like other MCP server authors to avoid. The obvious way to write a name denylist is to regex-check whatever string the caller passed:

```python
# The naive version (don't do this)
if re.search(r"^(prod|db|kube|vault)-.*", container):
    return forbidden()
client.containers.get(container).restart()
```

Docker accepts many references for the same container: the full 64-character ID, the 12-character short ID, or any unique ID prefix. `prod-payments` might also be `3f9a1c2b7e4d`. If the model passes the ID, it doesn't match `^prod-`, the guard waves it through, and production restarts.

Nobody has to be malicious for this to happen. An agent that called `list_containers` a minute earlier has every ID in its context, and IDs are a natural thing for it to pass back.

The fix is to let Docker resolve the reference first, then run the guard on the name Docker reports:

```python
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
```

`containers.get()` resolves an ID, short ID, or name to one container object, and the regex runs against that object's canonical name. The `.lstrip("/")` matters too: Docker's API stores names with a leading slash (`/prod-payments`), and a `^prod-` pattern won't match `/prod-payments`. docker-py's `.name` already strips it, so this is a safety net in case the name ever arrives raw.

Here is the test that pins this behaviour:

```python
def test_denylist_applies_to_resolved_name_not_caller_input(self, client, monkeypatch):
    # Passing an ID must not bypass a name-based denylist.
    monkeypatch.setenv("GUARDIAN_ALLOW_WRITE", "true")
    container = make_container("prod-payments")
    client.containers.get.return_value = container

    result = server.safe_restart_container("abc123def456")

    assert result["error"]["code"] == "forbidden"
    assert result["error"]["container"] == "prod-payments"
    container.restart.assert_not_called()
```

The default denylist is `^(prod|db|kube|vault)-.*`, and you can override it with `GUARDIAN_RESTART_DENY_REGEX`. For a tighter setup, `GUARDIAN_RESTART_ALLOW_REGEX=^staging-` limits restarts to staging containers only, and the denylist still applies on top.

## What the software guard does and doesn't protect against

The guard controls what *Claude* can do through *this server's tools*. The model only sees four tools, and the only write tool is gated.

It is not a security boundary against anything else running in the same process or container. Anything that can open `/var/run/docker.sock` has root-equivalent access to the host, `:ro` or not. If this server had a remote code execution bug, the attacker would get the raw socket, not my regex.

For a hard boundary at the API level, put a filtering proxy between the server and the engine, such as `tecnativa/docker-socket-proxy` with only container endpoints enabled. Then point `DOCKER_HOST` at the proxy instead of mounting the socket. The software guard and the proxy solve different problems, and on a shared host I'd run both.

## Packaging: multi-stage image, non-root user, explicit socket GID

```dockerfile
# syntax=docker/dockerfile:1

# ---- builder: resolve and install dependencies into an isolated venv --------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
# pytest is a test-only pin; keep it out of the runtime image.
RUN grep -v '^pytest' requirements.txt > runtime-requirements.txt \
 && pip install -r runtime-requirements.txt

# ---- runtime: minimal image, non-root user ----------------------------------
FROM python:3.12-slim AS runtime

# UID/GID of the runtime user, and the GID that owns /var/run/docker.sock on
# the host (`stat -c %g /var/run/docker.sock` on Linux). The socket is only
# usable if this user is in a group with that exact GID.
ARG APP_UID=10001
ARG APP_GID=10001
ARG DOCKER_GID=999

RUN groupadd --gid "${APP_GID}" guardian \
 && (getent group "${DOCKER_GID}" >/dev/null || groupadd --gid "${DOCKER_GID}" docker-host) \
 && useradd --uid "${APP_UID}" --gid "${APP_GID}" --no-create-home --shell /usr/sbin/nologin guardian \
 && usermod -aG "$(getent group "${DOCKER_GID}" | cut -d: -f1)" guardian

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=root:root server.py .

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GUARDIAN_ALLOW_WRITE=false

USER ${APP_UID}:${APP_GID}

# stdio transport: the MCP client launches this with `docker run -i`.
ENTRYPOINT ["python", "/app/server.py"]
```

The parts that matter:

- **Two stages.** Dependencies are installed into a virtualenv in the builder stage, and only that venv is copied into the runtime stage. `pytest` is stripped out, so the test runner never ships.
- **Non-root with a fixed UID/GID.** The process runs as UID 10001 and can't modify its own code, because `server.py` is owned by root.
- **Socket GID mapping.** Running as non-root creates a new problem: the socket is owned by `root:docker` with mode `660`, so UID 10001 can't open it. The Dockerfile takes the host socket's group ID as a build argument (`DOCKER_GID`), creates a group with that ID if one doesn't exist, and adds the runtime user to it. On Linux, find the value with `stat -c %g /var/run/docker.sock`.
- **Write mode off in the image.** `GUARDIAN_ALLOW_WRITE=false` is baked into the image, so even if the caller forgets to pass it, restarts are blocked.

Docker Desktop on macOS is different. The socket is proxied from the Linux VM, and inside a container it usually shows up owned by `root:root`. In that case, pass `--group-add 0` (or the GID that `ls -ln /var/run/docker.sock` shows from inside a container) instead of relying on 999.

### The compose harness

```yaml
# Test harness for the Docker MCP Guardian.
#
#   DOCKER_GID=$(stat -c %g /var/run/docker.sock) docker compose run --rm guardian
#   docker compose run --rm tests
#
# Note on `:ro`: mounting the socket read-only stops the container from
# replacing or deleting the socket file, but it does NOT make the Docker API
# read-only — any process that can open the socket can issue write calls.
# The real write guard is GUARDIAN_ALLOW_WRITE plus the restart deny/allow
# regexes enforced inside server.py. For a hard API-level boundary, point
# DOCKER_HOST at a filtering proxy (e.g. tecnativa/docker-socket-proxy with
# only CONTAINERS=1) instead of the raw socket.

services:
  guardian:
    build:
      context: .
      args:
        APP_UID: "10001"
        APP_GID: "10001"
        DOCKER_GID: "${DOCKER_GID:-999}"
    image: docker-mcp-guardian:latest
    stdin_open: true   # MCP stdio transport
    tty: false         # a TTY would corrupt the JSON-RPC stream
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    group_add:
      - "${DOCKER_GID:-999}"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      GUARDIAN_ALLOW_WRITE: "${GUARDIAN_ALLOW_WRITE:-false}"
      GUARDIAN_RESTART_DENY_REGEX: "${GUARDIAN_RESTART_DENY_REGEX:-^(prod|db|kube|vault)-.*}"
      GUARDIAN_RESTART_ALLOW_REGEX: "${GUARDIAN_RESTART_ALLOW_REGEX:-}"
      GUARDIAN_DOCKER_TIMEOUT: "${GUARDIAN_DOCKER_TIMEOUT:-5}"
      GUARDIAN_LOG_LEVEL: "${GUARDIAN_LOG_LEVEL:-INFO}"

  tests:
    image: python:3.12-slim
    working_dir: /src
    volumes:
      - .:/src:ro
    environment:
      PYTHONDONTWRITEBYTECODE: "1"
    command: >
      sh -c "pip install -q -r requirements.txt && python -m pytest tests/ -v -p no:cacheprovider"
```

The socket is still mounted `:ro` because it does prevent one thing: the container can't swap the socket file for something else. The header comment says plainly what it doesn't do.

Two settings here exist specifically for stdio:

- `stdin_open: true` keeps stdin open so the client can send requests.
- `tty: false` is just as important. A TTY rewrites line endings and adds terminal control sequences, which corrupts the JSON-RPC stream.

The rest is standard hardening: a read-only root filesystem, no Linux capabilities, and no privilege escalation.

## Testing without a Docker daemon

The suite mocks docker-py completely, so it runs on any machine and in CI without a daemon. The key fixture swaps `docker.from_env` for a mock client:

```python
@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("GUARDIAN_ALLOW_WRITE", "GUARDIAN_RESTART_DENY_REGEX", "GUARDIAN_RESTART_ALLOW_REGEX", "GUARDIAN_ANOMALY_REGEX"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def client(monkeypatch):
    fake = MagicMock()
    monkeypatch.setattr(server.docker, "from_env", MagicMock(return_value=fake))
    return fake
```

The `clean_env` fixture runs automatically before every test. If a developer happens to have `GUARDIAN_ALLOW_WRITE=true` exported in their shell, it can't leak into a test and quietly make a "read-only by default" test pass for the wrong reason.

The daemon-failure tests run every read-only tool against every way the connection can fail:

```python
class TestDaemonFailures:
    @pytest.mark.parametrize(
        "exc",
        [
            DockerException("Error while fetching server API version: Connection refused"),
            RequestsConnectionError("connection refused"),
            ReadTimeout("socket read timed out"),
            FileNotFoundError("/var/run/docker.sock"),
        ],
    )
    @pytest.mark.parametrize(
        "call",
        [
            lambda: server.list_containers(),
            lambda: server.inspect_container("web-api"),
            lambda: server.get_container_logs("web-api"),
        ],
    )
    def test_daemon_unreachable_returns_structured_error(self, monkeypatch, exc, call):
        monkeypatch.setattr(server.docker, "from_env", MagicMock(side_effect=exc))
        result = call()
        assert result["ok"] is False
        assert result["error"]["code"] == "daemon_unavailable"
```

The secret-handling test checks the actual secret string, not just the field name:

```python
def test_inspect_redacts_env_values(self, client):
    client.containers.get.return_value = make_container()
    info = server.inspect_container("web-api")["container"]
    assert info["env_keys"] == ["DATABASE_URL", "PORT"]
    assert "secret" not in repr(info)
```

The mock container's `DATABASE_URL` is `postgres://u:secret@db/app`, so the second assertion fails if the password leaks into any field of the response.

Run it:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest tests/ -v
```

```text
collected 47 items
...
tests/test_server.py::TestRestartGuard::test_denylist_applies_to_resolved_name_not_caller_input PASSED
tests/test_server.py::TestRestartGuard::test_allowed_container_restarts PASSED
tests/test_server.py::TestRestartGuard::test_allowlist_restricts_further PASSED
tests/test_server.py::TestRestartGuard::test_denylist_wins_over_allowlist PASSED
...
tests/test_server.py::TestLogAnomalyScanner::test_non_utf8_logs_do_not_crash PASSED
tests/test_server.py::test_all_tools_registered PASSED

============================== 47 passed in 0.38s ==============================
```

## Smoke-testing the real stdio transport

Mocked unit tests don't prove the JSON-RPC layer behaves. I also drove the real server as a subprocess, pointed `DOCKER_HOST` at a socket path that doesn't exist, and made sure every stdout line parsed as JSON:

```python
import json, subprocess, sys

env = {"PATH": "/usr/bin:/bin", "DOCKER_HOST": "unix:///nonexistent/docker.sock", "GUARDIAN_DOCKER_TIMEOUT": "2"}
p = subprocess.Popen([sys.executable, "server.py"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, text=True, env=env)

def send(m): p.stdin.write(json.dumps(m) + "\n"); p.stdin.flush()
def recv(): return json.loads(p.stdout.readline())

send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "0"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

calls = [("list_containers", {}),
         ("safe_restart_container", {"container": "prod-api"}),
         ("inspect_container", {"container": "web;rm -rf /"})]
for i, (name, args) in enumerate(calls, start=2):
    send({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}})
    err = json.loads(recv()["result"]["content"][0]["text"])["error"]
    print(f"{name}: {err['code']} — {err['message']}")

p.stdin.close(); p.wait(timeout=10)
print("server still alive through all failures; clean exit code:", p.returncode)
```

Output:

```text
list_containers: daemon_unavailable — Docker daemon is unreachable or timed out.
safe_restart_container: forbidden — Server is in read-only mode (set GUARDIAN_ALLOW_WRITE=true to enable restarts).
inspect_container: invalid_container_ref — Container reference must be a name or ID: [A-Za-z0-9_.-], max 128 chars.
server still alive through all failures; clean exit code: 0
```

All three failure paths came back as structured errors, and the process stayed up through every one of them.

My first version of this script taught me something about the transport. I piped all the requests in at once and closed stdin immediately, and the response to the last call never arrived. The server's stderr showed it had *processed* that request; stdin hit EOF and the session shut down before the response was written.

Real MCP clients keep stdin open for the life of the session, so this isn't a server bug. But if you test with a shell heredoc (`docker run -i ... << EOF`), you'll get the same truncated output and might conclude the server is broken. Keep stdin open until you've read every response, as the script above does, or add a `sleep` at the end of the input. Also send `initialize` first: MCP servers reject `tools/call` before the handshake.

## Connecting it to Claude

**Claude Code**, running from the virtualenv:

```bash
claude mcp add docker-guardian -- \
  "$HOME/docker-mcp-guardian/.venv/bin/python" \
  "$HOME/docker-mcp-guardian/server.py"
```

**Claude Desktop**: edit `claude_desktop_config.json`. On macOS it lives in `~/Library/Application Support/Claude/`. Desktop doesn't expand `$HOME`, so use absolute paths:

```json
{
  "mcpServers": {
    "docker-guardian": {
      "command": "/Users/you/docker-mcp-guardian/.venv/bin/python",
      "args": ["/Users/you/docker-mcp-guardian/server.py"],
      "env": {
        "GUARDIAN_ALLOW_WRITE": "false"
      }
    }
  }
}
```

**From the container** instead, on Linux (on macOS Docker Desktop, swap the `--group-add` value for `0` as covered above):

```json
{
  "mcpServers": {
    "docker-guardian": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
        "--group-add", "999",
        "-e", "GUARDIAN_ALLOW_WRITE=false",
        "docker-mcp-guardian:latest"
      ]
    }
  }
}
```

Note `-i` without `-t`, for the same TTY reason as in the compose file.

Once it's connected, ask Claude something like "Why does my `checkout-api` container keep restarting?" It will typically call `list_containers`, then `inspect_container` (exit code, OOM flag, restart count), then `get_container_logs`, and work from the anomaly lines rather than raw log noise. If you ask it to restart `prod-checkout`, you get a `forbidden` error that names the reason, and Claude can pass that along instead of failing silently.

## What I'd add next

- **An audit log.** Restarts are logged to stderr today. In a shared environment I'd also write an append-only record of every write attempt, including blocked ones.
- **Per-tool scoping.** Right now write mode is one switch. A `GUARDIAN_WRITE_TOOLS=restart` style setting would make it easier to add more write tools later without opening all of them at once.
- **A socket proxy by default.** The compose file mentions `docker-socket-proxy`, but making it the default service would turn the guard into defense in depth rather than the only line.
- **The `mcp` 2.x migration.** It's a planned change now, not a surprise from `pip`.

## Takeaways

If you build an MCP server around Docker, these are the points I'd keep:

- **`:ro` on the socket is not access control.** Real limits have to live in the tool layer, a socket proxy, or both.
- **Check permissions against what Docker resolves, not what the caller typed.** Name-based guards that accept IDs are bypassable by default.
- **Treat inspect output as secret-bearing.** Return environment variable names, never values.
- **stdout belongs to JSON-RPC.** Log to stderr, return errors as data, and never let an exception reach the transport.
- **Pin major versions of fast-moving SDKs.** `mcp>=1.0.0` broke on the day it resolved to 2.x.
