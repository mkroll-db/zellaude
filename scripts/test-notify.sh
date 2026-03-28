#!/usr/bin/env bash
# test-notify.sh — end-to-end test for notify-server.py
#
# Tests serve, connect, forward, and TLS modes.
# Usage: bash scripts/test-notify.sh [port]
set -euo pipefail

PORT="${1:-2399}"
REMOTE_PORT=$((PORT + 1))
TLS_PORT=$((PORT + 2))
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER="$SCRIPT_DIR/notify-server.py"
TMPDIR=$(mktemp -d)
SERVER_LOG="$TMPDIR/server.log"
CLIENT_LOG="$TMPDIR/client.log"
REMOTE_LOG="$TMPDIR/remote.log"
TLS_SERVER_LOG="$TMPDIR/tls-server.log"
TLS_CLIENT_LOG="$TMPDIR/tls-client.log"
TLS_DIR="$TMPDIR/certs"
PID_FILE="$TMPDIR/server.pid"
REMOTE_PID_FILE="$TMPDIR/remote.pid"
TLS_PID_FILE="$TMPDIR/tls-server.pid"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

pass() { printf "  \033[32m✓\033[0m %s\n" "$1"; }
fail() { printf "  \033[31m✗\033[0m %s\n" "$1"; FAILED=1; }
FAILED=0

echo "Testing notify-server.py (ports $PORT, $REMOTE_PORT, $TLS_PORT)"
echo "=== Plain TCP tests ==="

# --- Start server ---
python3 "$SERVER" serve --port "$PORT" --pid "$PID_FILE" --log "$SERVER_LOG" --backend none &
PIDS+=($!)
sleep 0.5

if kill -0 "${PIDS[0]}" 2>/dev/null; then
  pass "Server started (pid ${PIDS[0]})"
else
  fail "Server failed to start"
  cat "$SERVER_LOG" 2>/dev/null || true
  exit 1
fi

# --- Test: duplicate server exits ---
python3 "$SERVER" serve --port "$PORT" --pid "$PID_FILE" 2>/dev/null && \
  pass "Duplicate server exited cleanly" || \
  fail "Duplicate server did not exit cleanly"

# --- Test: one-shot notification ---
echo '{"title":"Test","message":"hello","pane_id":"1"}' | nc -w 1 127.0.0.1 "$PORT" 2>/dev/null || true
sleep 0.5

if grep -q "hello" "$SERVER_LOG"; then
  pass "One-shot notification received by server"
else
  fail "One-shot notification not found in server log"
fi

# --- Start client subscriber ---
python3 "$SERVER" connect --host localhost --port "$PORT" --log "$CLIENT_LOG" --backend none &
PIDS+=($!)
sleep 1

if kill -0 "${PIDS[1]}" 2>/dev/null; then
  pass "Client connected (pid ${PIDS[1]})"
else
  fail "Client failed to connect"
fi

# --- Test: notification reaches subscriber ---
echo '{"title":"Pushed","message":"to-client","pane_id":"2"}' | nc -w 1 127.0.0.1 "$PORT" 2>/dev/null || true
sleep 1

if grep -q "to-client" "$CLIENT_LOG"; then
  pass "Notification pushed to subscriber"
else
  fail "Notification not received by subscriber"
fi

# --- Test: rate limiting ---
echo '{"title":"Rate","message":"first","pane_id":"99"}' | nc -w 1 127.0.0.1 "$PORT" 2>/dev/null || true
sleep 0.3
echo '{"title":"Rate","message":"second","pane_id":"99"}' | nc -w 1 127.0.0.1 "$PORT" 2>/dev/null || true
sleep 0.5

if grep -q "rate-limited (pane 99)" "$SERVER_LOG"; then
  pass "Rate limiting works"
else
  fail "Rate limiting not triggered"
fi

# --- Test: bad payload ---
echo 'not json' | nc -w 1 127.0.0.1 "$PORT" 2>/dev/null || true
sleep 0.3

if grep -q "bad payload" "$SERVER_LOG"; then
  pass "Bad payload rejected"
else
  fail "Bad payload not detected"
fi

# --- Start remote server ---
python3 "$SERVER" serve --port "$REMOTE_PORT" --pid "$REMOTE_PID_FILE" --log "$REMOTE_LOG" --backend none &
PIDS+=($!)
sleep 0.5

if kill -0 "${PIDS[2]}" 2>/dev/null; then
  pass "Remote server started (pid ${PIDS[2]})"
else
  fail "Remote server failed to start"
fi

# --- Test: forward command ---
OUTPUT=$(python3 "$SERVER" forward --host "localhost:$REMOTE_PORT" --server-port "$PORT" 2>&1)

if echo "$OUTPUT" | grep -q "forward"; then
  pass "Forward command accepted"
else
  fail "Forward command failed: $OUTPUT"
fi

if grep -q "Forward target added: localhost:$REMOTE_PORT" "$SERVER_LOG"; then
  pass "Forward target registered in server"
else
  fail "Forward target not registered"
fi

# --- Test: notification forwarded to remote ---
echo '{"title":"Fwd","message":"to-remote","pane_id":"50"}' | nc -w 1 127.0.0.1 "$PORT" 2>/dev/null || true
sleep 2

if grep -q "forwarded to localhost:$REMOTE_PORT" "$SERVER_LOG"; then
  pass "Server forwarded notification"
else
  fail "Server did not forward notification"
fi

if grep -q "to-remote" "$REMOTE_LOG"; then
  pass "Remote server received forwarded notification"
else
  fail "Remote server did not receive notification"
fi

# === TLS tests ===
echo "=== TLS tests ==="

# Check if cryptography is available
if python3 -c "import cryptography" 2>/dev/null; then
  # --- Generate certs ---
  python3 "$SERVER" gen-cert --ca --tls-dir "$TLS_DIR" >/dev/null
  python3 "$SERVER" gen-cert --name client --tls-dir "$TLS_DIR" >/dev/null

  if [ -f "$TLS_DIR/ca.pem" ] && [ -f "$TLS_DIR/server.pem" ] && [ -f "$TLS_DIR/client.pem" ]; then
    pass "Certificates generated"
  else
    fail "Certificate generation incomplete"
  fi

  # --- Start TLS server ---
  python3 "$SERVER" serve --host 127.0.0.1 --port "$TLS_PORT" --pid "$TLS_PID_FILE" \
    --log "$TLS_SERVER_LOG" --backend none --tls-dir "$TLS_DIR" &
  PIDS+=($!)
  sleep 0.5

  if kill -0 "${PIDS[-1]}" 2>/dev/null; then
    pass "TLS server started"
  else
    fail "TLS server failed to start"
    cat "$TLS_SERVER_LOG" 2>/dev/null || true
  fi

  # --- Test: plain TCP still works on TLS server ---
  echo '{"title":"Plain","message":"still-works","pane_id":"70"}' | nc -w 1 127.0.0.1 "$TLS_PORT" 2>/dev/null || true
  sleep 0.5

  if grep -q "still-works" "$TLS_SERVER_LOG"; then
    pass "Plain TCP works on TLS-enabled server"
  else
    fail "Plain TCP broken on TLS-enabled server"
  fi

  # --- Test: TLS client can subscribe ---
  python3 "$SERVER" connect --host localhost --port "$TLS_PORT" --log "$TLS_CLIENT_LOG" \
    --backend none --tls-dir "$TLS_DIR" --cert-name client &
  PIDS+=($!)
  sleep 1

  if kill -0 "${PIDS[-1]}" 2>/dev/null; then
    pass "TLS client connected"
  else
    fail "TLS client failed to connect"
  fi

  # --- Test: notification reaches TLS subscriber ---
  echo '{"title":"TLS","message":"tls-push","pane_id":"80"}' | nc -w 1 127.0.0.1 "$TLS_PORT" 2>/dev/null || true
  sleep 1

  if grep -q "tls-push" "$TLS_CLIENT_LOG"; then
    pass "Notification pushed to TLS subscriber"
  else
    fail "Notification not received by TLS subscriber"
  fi
else
  echo "  (skipping TLS tests — 'cryptography' package not installed)"
fi

# --- Summary ---
echo "==="
if [ "$FAILED" -eq 0 ]; then
  printf "\033[32mAll tests passed\033[0m\n"
else
  printf "\033[31mSome tests failed\033[0m\n"
  echo "Server log:     $SERVER_LOG"
  echo "Client log:     $CLIENT_LOG"
  echo "Remote log:     $REMOTE_LOG"
  echo "TLS server log: $TLS_SERVER_LOG"
  echo "TLS client log: $TLS_CLIENT_LOG"
  trap - EXIT
  exit 1
fi
