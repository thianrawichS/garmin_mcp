#!/bin/sh
set -e

TOKEN_DIR=/root/.garminconnect
mkdir -p "$TOKEN_DIR"

if [ -n "$GARMIN_TOKENS_B64" ] && [ ! -f "$TOKEN_DIR/oauth1_token.json" ]; then
  echo "$GARMIN_TOKENS_B64" | base64 -d | tar -xz -C "$TOKEN_DIR"
  chmod 700 "$TOKEN_DIR"
fi

exec garmin-mcp
