#!/usr/bin/env bash
# aegis-tick.sh — catch-up wrapper for the Aegis attestation cron tick.
#
# Why:
#   v0.2.0 of aegis-attestation runs INSTANTLY via the post_tool_call hook
#   when a worker calls kanban_block(reason='review-required:'). The hook
#   covers ~99% of handoffs but cannot catch tasks where kanban_block was
#   invoked outside the agent process — e.g. via the kanban Web UI, the
#   `hermes kanban block` CLI, or the dispatcher's automatic block on
#   timeout. This wrapper provides the catch-up safety net.
#
# What:
#   Runs `hermes aegis tick --json` and appends both stdout and stderr to
#   ~/.hermes/logs/aegis.log. Designed for invocation from a systemd-user
#   timer (preferred) or host cron (legacy).
#
#   When Hermes runs in Docker, this wrapper auto-detects the container
#   and uses `docker exec hermes hermes aegis tick --json`. Override with
#   AEGIS_TICK_MODE=host|docker if detection picks the wrong path.
#
# Test:
#   AEGIS_TICK_MODE=host /path/to/aegis-tick.sh
#   tail -n 5 ~/.hermes/logs/aegis.log
#
set -euo pipefail

LOG_FILE="${AEGIS_LOG_FILE:-$HOME/.hermes/logs/aegis.log}"
MODE="${AEGIS_TICK_MODE:-auto}"

# Path to the hermes CLI INSIDE the docker container. Hermes ships in a
# uv-managed virtualenv at /opt/hermes/.venv/; the global PATH inside the
# container does NOT include venv/bin, so `docker exec hermes hermes ...`
# would fail with status 127. Override via env if your container layout
# differs.
HERMES_BIN_DOCKER="${HERMES_BIN_DOCKER:-/opt/hermes/.venv/bin/hermes}"
DOCKER_CONTAINER="${AEGIS_DOCKER_CONTAINER:-hermes}"

mkdir -p "$(dirname "$LOG_FILE")"

# --- Detect mode -----------------------------------------------------------
if [[ "$MODE" == "auto" ]]; then
  # Prefer docker exec if the configured container exists and is running.
  # Otherwise fall back to host CLI.
  if command -v docker >/dev/null 2>&1 && \
     docker ps --filter "name=^${DOCKER_CONTAINER}$" --format '{{.Names}}' \
       2>/dev/null | grep -q "^${DOCKER_CONTAINER}$"; then
    MODE="docker"
  else
    MODE="host"
  fi
fi

# --- Run -------------------------------------------------------------------
ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "[$ts] aegis-tick mode=$MODE start" >> "$LOG_FILE"

case "$MODE" in
  host)
    # Host invocation — hermes CLI must be on PATH.
    if ! command -v hermes >/dev/null 2>&1; then
      echo "[$ts] aegis-tick FAIL: 'hermes' CLI not on PATH (mode=host)" \
        >> "$LOG_FILE"
      exit 127
    fi
    hermes aegis tick --json >> "$LOG_FILE" 2>&1
    ;;
  docker)
    # docker exec invocation. Hermes CLI lives inside a uv venv whose
    # bin/ is NOT on the container's $PATH — use the absolute venv path
    # (overridable via HERMES_BIN_DOCKER env var).
    docker exec "$DOCKER_CONTAINER" "$HERMES_BIN_DOCKER" aegis tick --json \
      >> "$LOG_FILE" 2>&1
    ;;
  *)
    echo "[$ts] aegis-tick FAIL: unknown AEGIS_TICK_MODE=$MODE" >> "$LOG_FILE"
    exit 2
    ;;
esac

rc=$?
echo "[$ts] aegis-tick mode=$MODE exit=$rc" >> "$LOG_FILE"
exit $rc
