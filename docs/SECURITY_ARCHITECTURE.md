# Docker MCP Guardian: Security Architecture & Specification

## 1. Threat Model & Docker Socket Exposure

Access to the Docker Engine API is equivalent to root on the host: any client that can open `/var/run/docker.sock` can create a privileged container with the host filesystem mounted. Mounting the socket read-only (`-v /var/run/docker.sock:/var/run/docker.sock:ro`) does not change this. `:ro` prevents the container from replacing or deleting the socket file; it does not restrict the HTTP API requests sent over it.

An LLM agent should therefore never receive raw socket or Docker CLI access. Guardian exposes a small, fixed set of MCP tools instead, so the agent can only perform the operations those tools implement.

Out of scope: Guardian is not a socket proxy. The Guardian process itself holds full API access, and its protections apply only to requests made through its MCP tools. For an API-level boundary on the Guardian process, point `DOCKER_HOST` at a filtering proxy (for example `tecnativa/docker-socket-proxy` with only `CONTAINERS=1` and `POST=1` for restarts) instead of the raw socket.

## 2. Guardian Intermediary Architecture

```
[ LLM client (Claude Desktop / Claude Code) ]
        │  stdio, MCP JSON-RPC (stdout reserved for protocol; logs on stderr)
        ▼
[ Docker MCP Guardian (FastMCP) ]
   ├── Input validation (container ref regex, numeric ranges, regex compile check)
   ├── Read-only gate (GUARDIAN_ALLOW_WRITE, checked before any daemon call)
   ├── Canonical-name resolution (daemon lookup → obj.name)
   ├── Restart policy (deny regex, optional allow regex)
   ├── Response shaping (env values withheld, line caps)
   └── Error translation (all failures returned as {"ok": false, "error": {...}})
        │  docker-py over DOCKER_HOST / default socket, bounded timeout
        ▼
[ Docker Engine ]
```

### Tool surface

| Tool | Effect | Guard |
|---|---|---|
| `list_containers(all=false)` | Read | Daemon timeout |
| `inspect_container(container)` | Read | Ref validation; env values withheld |
| `get_container_logs(container, tail=200, anomaly_regex=None)` | Read | Ref validation; `1 ≤ tail ≤ 5000`; regex must compile; ≤ 500 lines and ≤ 500 anomaly hits returned |
| `safe_restart_container(container, timeout=10)` | **Write** | Ref validation; `0 ≤ timeout ≤ 120`; write gate; canonical-name policy check |

No tool creates, executes in, stops, removes, or prunes containers, images, volumes, or networks.

## 3. Core Protection Mechanisms

- **Input validation.** Container references must match `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`. Numeric arguments are range-checked and a caller-supplied `anomaly_regex` must compile. Violations return `invalid_container_ref`, `invalid_tail`, `invalid_timeout`, or `invalid_regex` without contacting the daemon.

- **Fail-closed write gate.** `safe_restart_container` returns `forbidden` unless `GUARDIAN_ALLOW_WRITE=true`. In read-only mode the check runs before any Docker API call.

- **Canonical-name resolution.** With writes enabled, the container is looked up on the daemon and the policy is evaluated against the daemon-reported name (`obj.name`, leading `/` stripped), never the caller's input. Passing a container ID or ID prefix therefore cannot bypass a name-based denylist.

- **Restart policy.** Evaluated in order: write gate → deny regex (`GUARDIAN_RESTART_DENY_REGEX`, default `^(prod|db|kube|vault)-.*`; always wins) → optional allow regex (`GUARDIAN_RESTART_ALLOW_REGEX`; when set, names must match). Blocked attempts are logged to stderr and returned as `forbidden` with the resolved name.

- **Secret withholding in inspection.** `inspect_container` returns environment variable names only (`env_keys`); values are never read into the response. Labels, ports, mounts, and restart policy are returned as-is.

- **Bounded daemon calls.** Every client is created with `GUARDIAN_DOCKER_TIMEOUT` (default 5 s) and verified with `ping()`. Unreachable or slow daemons yield `daemon_unavailable` instead of a hung session.

- **Structured errors.** `NotFound`, API errors, client errors, and timeouts are translated into `{"ok": false, "error": {"code", "message", "detail"}}`; exceptions do not propagate to the client.

- **Protocol isolation.** Logging is configured to stderr only, so no diagnostic output can corrupt the stdio JSON-RPC stream.

### Known limitations

- **Log content is not redacted.** `get_container_logs` returns log lines verbatim (capped at 500). Secrets written to container logs will reach the LLM client.
- Labels and mount source paths in `inspect_container` are not filtered.
- The denylist is name-based; containers without a protective naming convention rely on the allowlist or on read-only mode.

### Configuration

| Variable | Default | Effect |
|---|---|---|
| `GUARDIAN_ALLOW_WRITE` | `false` | Enables `safe_restart_container` |
| `GUARDIAN_RESTART_DENY_REGEX` | `^(prod\|db\|kube\|vault)-.*` | Names that can never be restarted |
| `GUARDIAN_RESTART_ALLOW_REGEX` | unset | When set, only matching names can be restarted |
| `GUARDIAN_ANOMALY_REGEX` | error/exception/fatal/… | Default log anomaly pattern |
| `GUARDIAN_DOCKER_TIMEOUT` | `5` | Seconds per Docker API call |
| `GUARDIAN_LOG_LEVEL` | `INFO` | stderr log level |

### Container deployment

The provided `Dockerfile` runs as a non-root user (UID/GID 10001) with the socket's group added via `DOCKER_GID`. `docker-compose.yml` sets `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, and `tty: false` (a TTY would corrupt the JSON-RPC stream).

## 4. Verification & Testing

47 pytest tests, with docker-py fully mocked, covering:

- read-only inspection and env-value withholding;
- the restart guard: write gate, deny/allow precedence, and the container-ID bypass case;
- daemon failures: unreachable, ping timeout, timeout mid-request, not found, restart with daemon down;
- log retrieval limits and the anomaly scanner;
- tool registration.

CI runs the suite on Python 3.10, 3.12, and 3.13.
