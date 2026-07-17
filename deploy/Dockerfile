# syntax=docker/dockerfile:1.7

# Override with an approved digest-pinned image in release builds, for example:
# --build-arg PYTHON_IMAGE=python:3.12.10-slim-bookworm@sha256:<approved-digest>
ARG PYTHON_IMAGE=python:3.12.10-slim-bookworm

FROM ${PYTHON_IMAGE} AS builder

WORKDIR /src
COPY agent_tree_rl ./agent_tree_rl
RUN chmod 0555 /src/agent_tree_rl/workers/evidence_probe.py
RUN python -m compileall -q /src

FROM ${PYTHON_IMAGE} AS runtime

ARG APP_UID=10001
ARG APP_GID=10001

LABEL org.opencontainers.image.title="agent-tree-rl" \
      org.opencontainers.image.description="Governed tree-search controller for agent decisions" \
      org.opencontainers.image.vendor="kalibraring" \
      org.opencontainers.image.source="https://github.com/kalibraring/agent-tree-rl" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    AGENT_TREE_RL_HOST=0.0.0.0 \
    AGENT_TREE_RL_PORT=8081 \
    AGENT_TREE_RL_DATA_DIR=/data \
    AGENT_TREE_RL_LOG_FORMAT=json \
    AGENT_TREE_RL_LOG_LEVEL=INFO \
    AGENT_TREE_RL_REQUIRE_AUTH=true \
    PYTHONFAULTHANDLER=1

RUN groupadd --gid "${APP_GID}" --system agenttree \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --system \
       --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin agenttree \
    && install -d -o "${APP_UID}" -g "${APP_GID}" -m 0750 /data

COPY --from=builder --chown=root:root /src/agent_tree_rl /app/agent_tree_rl
COPY --chown=root:root LICENSE /app/LICENSE

WORKDIR /app
USER ${APP_UID}:${APP_GID}
EXPOSE 8081

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/readyz', timeout=2).read()"]

ENTRYPOINT ["python", "-m", "agent_tree_rl.cli"]
CMD ["serve"]
