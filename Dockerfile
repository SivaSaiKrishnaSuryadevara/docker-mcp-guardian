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
