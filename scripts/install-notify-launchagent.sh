#!/bin/zsh
set -euo pipefail

# Parse --host flag, rest is positional
LISTEN_HOST=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) LISTEN_HOST="$2"; shift 2 ;;
    --host=*) LISTEN_HOST="${1#--host=}"; shift ;;
    *) break ;;
  esac
done

NOTIFY_SERVER="${1:-$HOME/bin/notify-server}"
TLS_DIR="$HOME/.local/state/notify-server/certs"
STATE_DIR="$HOME/.local/state/notify-server"
LOG_DIR="$HOME/Library/Logs"
PYTHON="$(command -v python3 || echo /opt/homebrew/bin/python3)"

# Ask user for listen address if not provided via --host
if [ -z "$LISTEN_HOST" ]; then
  echo ""
  echo "Listen address:"
  echo "  1) 127.0.0.1 — localhost only (default, no TLS needed)"
  echo "  2) 0.0.0.0   — all interfaces (requires TLS certs)"
  echo ""
  printf "Choice [1]: "
  read -r choice
  case "$choice" in
    2) LISTEN_HOST="0.0.0.0" ;;
    *) LISTEN_HOST="127.0.0.1" ;;
  esac
fi

# Build --tls-dir flag only if certs exist and listening on non-localhost
TLS_FLAG=""
if [ "$LISTEN_HOST" != "127.0.0.1" ] && [ -d "$TLS_DIR" ] && [ -f "$TLS_DIR/server.pem" ]; then
  TLS_FLAG="--tls-dir \"\$TLS_DIR\""
elif [ "$LISTEN_HOST" != "127.0.0.1" ]; then
  echo ""
  echo "⚠  Listening on $LISTEN_HOST without TLS certs."
  echo "   Generate certs first:  $PYTHON $NOTIFY_SERVER gen-cert --ca"
  echo "   Or press Enter to continue anyway."
  read -r
fi

echo ""
echo "[1/6] Creating ~/.notify-server-autostart.sh ..."
mkdir -p "$STATE_DIR"
cat > ~/.notify-server-autostart.sh <<SCRIPT
#!/bin/zsh
set -euo pipefail

PYTHON="$PYTHON"
NOTIFY_SERVER="$NOTIFY_SERVER"
TLS_DIR="$TLS_DIR"
STATE_DIR="$STATE_DIR"
LISTEN_HOST="$LISTEN_HOST"

BACKOFF=5
MAX_BACKOFF=60

# Build TLS flag dynamically (certs may be added later)
TLS_FLAG=""
if [ "\$LISTEN_HOST" != "127.0.0.1" ] && [ -d "\$TLS_DIR" ] && [ -f "\$TLS_DIR/server.pem" ]; then
  TLS_FLAG="--tls-dir \$TLS_DIR"
fi

while true; do
  echo "[notify-server] \$(date) starting on \$LISTEN_HOST..." >&2
  eval "\$PYTHON" "\$NOTIFY_SERVER" serve \\
    --host "\$LISTEN_HOST" \\
    --pid "\$STATE_DIR/notify-server.pid" \\
    --log "\$STATE_DIR/notify-server.log" \\
    \$TLS_FLAG
  rc=\$?
  echo "[notify-server] \$(date) exited with rc=\$rc; retrying in \${BACKOFF}s" >&2
  sleep "\$BACKOFF"
  BACKOFF=\$(( BACKOFF < MAX_BACKOFF ? BACKOFF * 2 : MAX_BACKOFF ))
done
SCRIPT
chmod +x ~/.notify-server-autostart.sh


echo "[2/6] Ensuring LaunchAgents directory exists ..."
mkdir -p ~/Library/LaunchAgents


echo "[3/6] Creating LaunchAgent plist ..."
cat > ~/Library/LaunchAgents/com.user.notify-server.plist <<EOS
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key><string>com.user.notify-server</string>

    <key>ProgramArguments</key>
    <array>
      <string>/bin/zsh</string>
      <string>-lc</string>
      <string>$HOME/.notify-server-autostart.sh</string>
    </array>

    <key>RunAtLoad</key><true/>

    <key>KeepAlive</key>
    <dict>
      <key>NetworkState</key><true/>
      <key>SuccessfulExit</key><false/>
    </dict>

    <key>StandardOutPath</key><string>$LOG_DIR/notify-server.out.log</string>
    <key>StandardErrorPath</key><string>$LOG_DIR/notify-server.err.log</string>
  </dict>
</plist>
EOS


echo "[4/6] Validating plist ..."
plutil -lint ~/Library/LaunchAgents/com.user.notify-server.plist


echo "[5/6] Bootstrapping LaunchAgent ..."
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.user.notify-server.plist 2>/dev/null || true
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.user.notify-server.plist
launchctl enable gui/$(id -u)/com.user.notify-server
launchctl kickstart -k gui/$(id -u)/com.user.notify-server


echo "[6/6] Setting up log rotation via newsyslog ..."
sudo tee /etc/newsyslog.d/notify-server.conf >/dev/null <<EOF
$STATE_DIR/notify-server.log               $USER:staff    644   5    1024      *     Z
$LOG_DIR/notify-server.out.log             $USER:staff    644   5    1024      *     Z
$LOG_DIR/notify-server.err.log             $USER:staff    644   5    1024      *     Z
EOF

echo ""
echo "✅ Setup complete! (listening on $LISTEN_HOST)"
echo ""
echo "Verify with:  launchctl list | grep com.user.notify-server"
echo "Server log:   tail -f $STATE_DIR/notify-server.log"
echo "Wrapper log:  tail -f ~/Library/Logs/notify-server.err.log"
echo "Test rotate:  sudo newsyslog -f /etc/newsyslog.d/notify-server.conf -v"
echo ""

exit 0

# --- UNINSTALL ---
# launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.user.notify-server.plist
# rm ~/Library/LaunchAgents/com.user.notify-server.plist ~/.notify-server-autostart.sh
# sudo rm /etc/newsyslog.d/notify-server.conf
