#!/bin/bash
set -uo pipefail

TOKEN_DIR="${GARMINTOKENS:-/root/.garminconnect}"
mkdir -p "$TOKEN_DIR"
chmod 700 "$TOKEN_DIR"

# Restore tokens only if the directory is empty. This keeps a Render disk
# (if you attach one) authoritative, so refreshed tokens survive restarts.
if [ -n "${GARMIN_TOKENS_B64:-}" ] && [ -z "$(ls -A "$TOKEN_DIR" 2>/dev/null)" ]; then
  echo "Restoring Garmin tokens into $TOKEN_DIR" >&2
  echo "$GARMIN_TOKENS_B64" | base64 -d | tar -xz -C "$TOKEN_DIR"
  chmod 600 "$TOKEN_DIR"/* 2>/dev/null || true
fi

if [ -z "$(ls -A "$TOKEN_DIR" 2>/dev/null)" ]; then
  echo "WARNING: no tokens in $TOKEN_DIR. Tool calls will fail until you set GARMIN_TOKENS_B64." >&2
fi

# --- Unguarded mode: MCP served directly on Render's port -------------------
if [ -z "${MCP_SECRET_PATH:-}" ]; then
  echo "WARNING: MCP_SECRET_PATH unset - endpoint is publicly reachable with no auth." >&2
  export GARMIN_MCP_TRANSPORT=streamable-http
  export GARMIN_MCP_HOST=0.0.0.0
  export GARMIN_MCP_PORT="${PORT:-10000}"
  exec garmin-mcp
fi

# --- Guarded mode: MCP on loopback, proxy on Render's port ------------------
export GARMIN_MCP_TRANSPORT=streamable-http
export GARMIN_MCP_HOST=127.0.0.1
export GARMIN_MCP_PORT=8000
garmin-mcp &
MCP_PID=$!

uvicorn guard:app --host 0.0.0.0 --port "${PORT:-10000}" --app-dir /app &
PROXY_PID=$!

trap 'kill -TERM "$MCP_PID" "$PROXY_PID" 2>/dev/null' TERM INT

# If either process dies, exit so Render restarts the container.
wait -n
echo "A child process exited; shutting down." >&2
kill -TERM "$MCP_PID" "$PROXY_PID" 2>/dev/null
exit 1
