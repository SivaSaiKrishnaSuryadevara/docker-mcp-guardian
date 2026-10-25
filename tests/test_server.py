from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from docker.errors import DockerException, NotFound
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server  # noqa: E402


def make_container(name="web-api", status="running", logs=b"", attrs=None):
    c = MagicMock()
    c.name = name
    c.short_id = "abc123def456"
    c.status = status
    c.image.tags = ["web-api:1.4.2"]
    c.attrs = attrs or {
        "Created": "2026-10-01T00:00:00Z",
        "RestartCount": 2,
        "State": {"StartedAt": "2026-10-01T00:00:01Z", "ExitCode": 0, "OOMKilled": False, "Health": {"Status": "healthy"}},
        "Config": {"Image": "web-api:1.4.2", "Env": ["DATABASE_URL=postgres://u:secret@db/app", "PORT=8080"], "Labels": {"team": "core"}},
        "NetworkSettings": {"Ports": {"8080/tcp": [{"HostPort": "8080"}]}},
        "Mounts": [{"Source": "/data", "Destination": "/var/data", "RW": False}],
        "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
    }
    c.logs.return_value = logs
    return c


TEST_DOCKER_HOST = "unix:///tmp/guardian-test-docker.sock"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in (
        "GUARDIAN_ALLOW_WRITE",
        "GUARDIAN_RESTART_DENY_REGEX",
        "GUARDIAN_RESTART_ALLOW_REGEX",
        "GUARDIAN_ANOMALY_REGEX",
        "GUARDIAN_ALLOW_ROOTFUL",
        "XDG_RUNTIME_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    # Tool tests mock docker.from_env; give them an explicit endpoint so socket
    # resolution never depends on the machine running the tests.
    monkeypatch.setenv("DOCKER_HOST", TEST_DOCKER_HOST)
    monkeypatch.setattr(server, "_last_resolution", None)


@pytest.fixture
def client(monkeypatch):
    fake = MagicMock()
    monkeypatch.setattr(server.docker, "from_env", MagicMock(return_value=fake))
    return fake


# ---------------------------------------------------------------- a) read-only inspection

class TestReadOnlyInspection:
    def test_inspect_returns_summary_without_mutating(self, client):
        container = make_container()
        client.containers.get.return_value = container

        result = server.inspect_container("web-api")

        assert result["ok"] is True
        info = result["container"]
        assert info["name"] == "web-api"
        assert info["status"] == "running"
        assert info["health"] == "healthy"
        assert info["mounts"] == [{"source": "/data", "destination": "/var/data", "rw": False}]
        container.restart.assert_not_called()
        container.stop.assert_not_called()
        container.remove.assert_not_called()
        container.kill.assert_not_called()

    def test_inspect_redacts_env_values(self, client):
        client.containers.get.return_value = make_container()
        info = server.inspect_container("web-api")["container"]
        assert info["env_keys"] == ["DATABASE_URL", "PORT"]
        assert "secret" not in repr(info)

    def test_list_containers(self, client):
        client.containers.list.return_value = [make_container("a"), make_container("b", status="exited")]
        result = server.list_containers(all=True)
        assert result["ok"] is True
        assert [c["name"] for c in result["containers"]] == ["a", "b"]
        client.containers.list.assert_called_once_with(all=True)

    def test_inspect_not_found(self, client):
        client.containers.get.side_effect = NotFound("No such container: ghost")
        result = server.inspect_container("ghost")
        assert result["ok"] is False
        assert result["error"]["code"] == "not_found"

    @pytest.mark.parametrize("ref", ["", "../etc", "web api", "a" * 200, "web;rm -rf /", None])
    def test_inspect_rejects_malformed_refs_before_touching_docker(self, client, ref):
        result = server.inspect_container(ref)
        assert result["error"]["code"] == "invalid_container_ref"
        client.containers.get.assert_not_called()


# ---------------------------------------------------------------- b) restart guard

class TestRestartGuard:
    def test_read_only_by_default_blocks_any_restart(self, client):
        result = server.safe_restart_container("web-api")
        assert result["ok"] is False
        assert result["error"]["code"] == "forbidden"
        assert "read-only" in result["error"]["message"]
        server.docker.from_env.assert_not_called()

    @pytest.mark.parametrize("name", ["prod-api", "db-primary", "kube-proxy", "vault-0"])
    def test_denylist_blocks_protected_containers(self, client, monkeypatch, name):
        monkeypatch.setenv("GUARDIAN_ALLOW_WRITE", "true")
        container = make_container(name)
        client.containers.get.return_value = container

        result = server.safe_restart_container(name)

        assert result["error"]["code"] == "forbidden"
        assert "denylist" in result["error"]["message"]
        container.restart.assert_not_called()

    def test_denylist_applies_to_resolved_name_not_caller_input(self, client, monkeypatch):
        # Passing an ID must not bypass a name-based denylist.
        monkeypatch.setenv("GUARDIAN_ALLOW_WRITE", "true")
        container = make_container("prod-payments")
        client.containers.get.return_value = container

        result = server.safe_restart_container("abc123def456")

        assert result["error"]["code"] == "forbidden"
        assert result["error"]["container"] == "prod-payments"
        container.restart.assert_not_called()

    def test_allowed_container_restarts(self, client, monkeypatch):
        monkeypatch.setenv("GUARDIAN_ALLOW_WRITE", "true")
        container = make_container("staging-worker")
        client.containers.get.return_value = container

        result = server.safe_restart_container("staging-worker", timeout=5)

        assert result == {"ok": True, "container": "staging-worker", "status": "running"}
        container.restart.assert_called_once_with(timeout=5)

    def test_allowlist_restricts_further(self, client, monkeypatch):
        monkeypatch.setenv("GUARDIAN_ALLOW_WRITE", "true")
        monkeypatch.setenv("GUARDIAN_RESTART_ALLOW_REGEX", r"^staging-")
        container = make_container("dev-sandbox")
        client.containers.get.return_value = container

        result = server.safe_restart_container("dev-sandbox")

        assert result["error"]["code"] == "forbidden"
        assert "allowlist" in result["error"]["message"]
        container.restart.assert_not_called()

    def test_denylist_wins_over_allowlist(self, monkeypatch):
        monkeypatch.setenv("GUARDIAN_ALLOW_WRITE", "true")
        monkeypatch.setenv("GUARDIAN_RESTART_ALLOW_REGEX", r".*")
        allowed, reason = server.restart_policy_decision("vault-1")
        assert allowed is False
        assert "denylist" in reason

    def test_invalid_timeout_rejected(self, client, monkeypatch):
        monkeypatch.setenv("GUARDIAN_ALLOW_WRITE", "true")
        assert server.safe_restart_container("web-api", timeout=999)["error"]["code"] == "invalid_timeout"


# ---------------------------------------------------------------- c) daemon down / timeouts

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

    def test_ping_timeout_is_handled(self, client):
        client.ping.side_effect = ReadTimeout("ping timed out")
        result = server.list_containers()
        assert result["error"]["code"] == "daemon_unavailable"

    def test_timeout_mid_request_is_handled(self, client):
        client.containers.list.side_effect = ReadTimeout("read timed out")
        result = server.list_containers()
        assert result["error"]["code"] == "daemon_unavailable"

    def test_client_uses_configured_timeout(self, client, monkeypatch):
        monkeypatch.setenv("GUARDIAN_DOCKER_TIMEOUT", "3")
        client.containers.list.return_value = []
        server.list_containers()
        server.docker.from_env.assert_called_once()
        assert server.docker.from_env.call_args.kwargs["timeout"] == 3

    def test_restart_with_daemon_down(self, monkeypatch):
        monkeypatch.setenv("GUARDIAN_ALLOW_WRITE", "true")
        monkeypatch.setattr(server.docker, "from_env", MagicMock(side_effect=DockerException("daemon down")))
        assert server.safe_restart_container("web-api")["error"]["code"] == "daemon_unavailable"


# ---------------------------------------------------------------- socket resolution

ROOTFUL = "/var/run/docker.sock"


@pytest.fixture
def sockets(monkeypatch):
    """Declare which paths exist as sockets; everything else is absent."""
    existing: set[str] = set()
    monkeypatch.setattr(server, "_is_socket", lambda path: path in existing)
    monkeypatch.setattr(server.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    return existing


class TestSocketResolution:
    def test_explicit_docker_host_wins_over_rootless(self, sockets, monkeypatch):
        sockets.add("/run/user/1000/docker.sock")
        monkeypatch.setenv("DOCKER_HOST", "tcp://10.0.0.5:2376")
        assert server.resolve_docker_host() == ("tcp://10.0.0.5:2376", "DOCKER_HOST is set")

    def test_blank_docker_host_is_treated_as_unset(self, sockets, monkeypatch):
        sockets.add("/run/user/1000/docker.sock")
        monkeypatch.setenv("DOCKER_HOST", "   ")
        assert server.resolve_docker_host()[0] == "unix:///run/user/1000/docker.sock"

    def test_rootless_socket_from_xdg_runtime_dir(self, sockets, monkeypatch):
        monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/2000")
        sockets.add("/run/user/2000/docker.sock")
        assert server.resolve_docker_host() == ("unix:///run/user/2000/docker.sock", "rootless Docker socket found")

    def test_rootless_socket_found_without_xdg_runtime_dir(self, sockets):
        # MCP clients often spawn servers without XDG_RUNTIME_DIR.
        sockets.add("/run/user/1000/docker.sock")
        assert server.resolve_docker_host()[0] == "unix:///run/user/1000/docker.sock"

    def test_xdg_path_that_is_not_a_socket_falls_through(self, sockets, monkeypatch):
        monkeypatch.setenv("XDG_RUNTIME_DIR", "/tmp/not-a-runtime-dir")
        sockets.add("/run/user/1000/docker.sock")
        assert server.resolve_docker_host()[0] == "unix:///run/user/1000/docker.sock"

    def test_rootless_preferred_even_when_rootful_is_allowed(self, sockets, monkeypatch):
        monkeypatch.setenv("GUARDIAN_ALLOW_ROOTFUL", "true")
        sockets.update({ROOTFUL, "/run/user/1000/docker.sock"})
        assert server.resolve_docker_host()[0] == "unix:///run/user/1000/docker.sock"

    def test_rootful_socket_refused_without_opt_in(self, sockets):
        sockets.add(ROOTFUL)
        with pytest.raises(server.SocketResolutionError, match="GUARDIAN_ALLOW_ROOTFUL=true"):
            server.resolve_docker_host()

    def test_rootful_socket_used_with_opt_in_and_warns(self, sockets, monkeypatch, caplog):
        monkeypatch.setenv("GUARDIAN_ALLOW_ROOTFUL", "true")
        sockets.add(ROOTFUL)
        fake = MagicMock()
        monkeypatch.setattr(server.docker, "from_env", MagicMock(return_value=fake))
        fake.containers.list.return_value = []
        with caplog.at_level("WARNING", logger="docker-mcp-guardian"):
            assert server.list_containers()["ok"] is True
        assert "root-equivalent" in caplog.text
        assert server.docker.from_env.call_args.kwargs["environment"]["DOCKER_HOST"] == f"unix://{ROOTFUL}"

    def test_no_socket_fails_closed(self, sockets):
        with pytest.raises(server.SocketResolutionError, match="No Docker socket found"):
            server.resolve_docker_host()

    def test_tools_return_structured_error_and_never_connect(self, sockets, monkeypatch):
        sockets.add(ROOTFUL)  # present but not opted in
        monkeypatch.setattr(server.docker, "from_env", MagicMock())
        result = server.list_containers()
        assert result["ok"] is False
        assert result["error"]["code"] == "docker_socket_unresolved"
        server.docker.from_env.assert_not_called()

    def test_client_receives_resolved_host_and_keeps_tls_settings(self, sockets, monkeypatch):
        sockets.add("/run/user/1000/docker.sock")
        monkeypatch.setenv("DOCKER_TLS_VERIFY", "1")
        fake = MagicMock()
        monkeypatch.setattr(server.docker, "from_env", MagicMock(return_value=fake))
        fake.containers.list.return_value = []
        server.list_containers()
        env = server.docker.from_env.call_args.kwargs["environment"]
        assert env["DOCKER_HOST"] == "unix:///run/user/1000/docker.sock"
        assert env["DOCKER_TLS_VERIFY"] == "1"

    def test_resolution_is_logged_once_per_change(self, sockets, monkeypatch, caplog):
        sockets.add("/run/user/1000/docker.sock")
        fake = MagicMock()
        monkeypatch.setattr(server.docker, "from_env", MagicMock(return_value=fake))
        fake.containers.list.return_value = []
        with caplog.at_level("INFO", logger="docker-mcp-guardian"):
            server.list_containers()
            server.list_containers()
        assert caplog.text.count("Using Docker endpoint unix:///run/user/1000/docker.sock") == 1

    @pytest.mark.skipif(not hasattr(__import__("socket"), "AF_UNIX"), reason="needs Unix domain sockets")
    def test_real_socket_detection(self):
        import shutil
        import socket
        import tempfile

        # Short directory: Unix socket paths are limited to ~104 bytes on macOS.
        workdir = Path(tempfile.mkdtemp(dir="/tmp"))
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(str(workdir / "d.sock"))
            assert server._is_socket(str(workdir / "d.sock")) is True
            (workdir / "file").write_text("x")
            assert server._is_socket(str(workdir / "file")) is False
            assert server._is_socket(str(workdir / "missing")) is False
        finally:
            sock.close()
            shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------- d) log anomaly scanner

LOG_SAMPLE = b"""2026-10-04 INFO server started on :8080
2026-10-04 INFO GET /health 200
2026-10-04 ERROR failed to connect to postgres
2026-10-04 WARN retrying
Traceback (most recent call last):
2026-10-04 FATAL out of memory
2026-10-04 INFO request completed
"""


class TestLogAnomalyScanner:
    def test_scanner_finds_anomalies_with_line_numbers(self):
        scan = server.scan_log_anomalies(LOG_SAMPLE.decode())
        assert scan["total_lines"] == 7
        assert scan["anomaly_count"] == 3
        assert [a["line_number"] for a in scan["anomalies"]] == [3, 5, 6]
        assert scan["counts_by_keyword"] == {"error": 1, "traceback": 1, "fatal": 1}
        assert scan["anomaly_ratio"] == round(3 / 7, 4)

    def test_scanner_clean_logs(self):
        scan = server.scan_log_anomalies("INFO ok\nINFO still ok\n")
        assert scan["anomaly_count"] == 0
        assert scan["anomalies"] == []

    def test_scanner_does_not_match_inside_words(self):
        assert server.scan_log_anomalies("INFO errorless shutdown")["anomaly_count"] == 0

    def test_get_logs_returns_lines_and_scan(self, client):
        container = make_container(logs=LOG_SAMPLE)
        client.containers.get.return_value = container

        result = server.get_container_logs("web-api", tail=50)

        assert result["ok"] is True
        assert len(result["lines"]) == 7
        assert result["scan"]["anomaly_count"] == 3
        container.logs.assert_called_once_with(tail=50, stdout=True, stderr=True, timestamps=False)

    def test_custom_anomaly_regex(self, client):
        client.containers.get.return_value = make_container(logs=LOG_SAMPLE)
        result = server.get_container_logs("web-api", anomaly_regex=r"WARN")
        assert result["scan"]["anomaly_count"] == 1
        assert result["scan"]["anomalies"][0]["line_number"] == 4

    def test_invalid_anomaly_regex_rejected(self, client):
        result = server.get_container_logs("web-api", anomaly_regex="(unclosed")
        assert result["error"]["code"] == "invalid_regex"
        client.containers.get.assert_not_called()

    @pytest.mark.parametrize("tail", [0, -1, 5001])
    def test_tail_bounds(self, client, tail):
        assert server.get_container_logs("web-api", tail=tail)["error"]["code"] == "invalid_tail"

    def test_non_utf8_logs_do_not_crash(self, client):
        client.containers.get.return_value = make_container(logs=b"\xff\xfe ERROR bad bytes\n")
        result = server.get_container_logs("web-api")
        assert result["ok"] is True
        assert result["scan"]["anomaly_count"] == 1


# ---------------------------------------------------------------- MCP registration

def test_all_tools_registered():
    import asyncio

    tools = asyncio.run(server.mcp.list_tools())
    assert {t.name for t in tools} == {"list_containers", "inspect_container", "get_container_logs", "safe_restart_container"}
