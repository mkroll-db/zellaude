#!/usr/bin/env bash
# zellaude-hook.sh — Claude Code hook → zellij pipe bridge
# Forwards hook events to the zellaude Zellij plugin via pipe.
#
# Usage in ~/.claude/settings.json hooks:
#   "command": "/path/to/zellaude-hook.sh"

# Exit silently if not running inside Zellij
[ -z "$ZELLIJ_SESSION_NAME" ] && exit 0
[ -z "$ZELLIJ_PANE_ID" ] && exit 0

# Read hook JSON from stdin
INPUT=$(cat)

# Extract fields with jq (required dependency)
HOOK_EVENT=$(echo "$INPUT" | jq -r '.hook_event_name // empty')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // empty')
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')
CWD=$(echo "$INPUT" | jq -r '.cwd // empty')

[ -z "$HOOK_EVENT" ] && exit 0

# Build compact JSON payload
PAYLOAD=$(jq -nc \
  --arg pane_id "$ZELLIJ_PANE_ID" \
  --arg session_id "$SESSION_ID" \
  --arg hook_event "$HOOK_EVENT" \
  --arg tool_name "$TOOL_NAME" \
  --arg cwd "$CWD" \
  --arg zellij_session "$ZELLIJ_SESSION_NAME" \
  --arg term_program "${TERM_PROGRAM:-}" \
  '{
    pane_id: ($pane_id | tonumber),
    session_id: $session_id,
    hook_event: $hook_event,
    tool_name: (if $tool_name == "" then null else $tool_name end),
    cwd: (if $cwd == "" then null else $cwd end),
    zellij_session: $zellij_session,
    term_program: (if $term_program == "" then null else $term_program end)
  }')

# Permission request: bell + desktop notification
if [ "$HOOK_EVENT" = "PermissionRequest" ]; then
  printf '\a' > /dev/tty 2>/dev/null || true

  # Read notification setting (default: Always)
  SETTINGS_FILE="$HOME/.config/zellij/plugins/zellaude.json"
  NOTIFY_MODE="Always"
  if [ -f "$SETTINGS_FILE" ]; then
    NOTIFY_MODE=$(jq -r '.notifications // "Always"' "$SETTINGS_FILE" 2>/dev/null)
  fi

  # For "Unfocused" mode, check if the terminal app is frontmost
  SHOULD_NOTIFY=false
  case "$NOTIFY_MODE" in
    Always) SHOULD_NOTIFY=true ;;
    Unfocused)
      TERM_FOCUSED=false
      case "$(uname)" in
        Darwin)
          # Map TERM_PROGRAM to macOS process name
          EXPECTED="${TERM_PROGRAM:-}"
          case "$EXPECTED" in
            Apple_Terminal) EXPECTED="Terminal" ;;
            iTerm.app)     EXPECTED="iTerm2" ;;
          esac
          FRONT_APP=$(osascript -e 'tell application "System Events" to get name of first application process whose frontmost is true' 2>/dev/null)
          [ "$FRONT_APP" = "$EXPECTED" ] && TERM_FOCUSED=true
          ;;
        Linux)
          # X11: check if focused window belongs to our terminal
          if command -v xdotool >/dev/null 2>&1; then
            ACTIVE_PID=$(xdotool getactivewindow getwindowpid 2>/dev/null)
            if [ -n "$ACTIVE_PID" ]; then
              # Walk up the process tree from our shell to see if the
              # focused window's process is an ancestor (i.e. our terminal)
              PID=$$
              while [ "$PID" -gt 1 ] 2>/dev/null; do
                [ "$PID" = "$ACTIVE_PID" ] && { TERM_FOCUSED=true; break; }
                PID=$(ps -o ppid= -p "$PID" 2>/dev/null | tr -d ' ')
              done
            fi
          fi
          # Wayland: no standard way to check; fall through to not-focused
          ;;
      esac
      [ "$TERM_FOCUSED" = false ] && SHOULD_NOTIFY=true
      ;;
  esac

  if [ "$SHOULD_NOTIFY" = true ]; then
    TOOL_SUFFIX=""
    [ -n "$TOOL_NAME" ] && TOOL_SUFFIX=" — $TOOL_NAME"
    TITLE="⚠ Claude Code"
    MESSAGE="Permission requested${TOOL_SUFFIX}"

    # Rate-limit: one notification per pane per 10 seconds
    LOCK="${XDG_RUNTIME_DIR:-/tmp}/zellaude-notify-${ZELLIJ_PANE_ID}"
    NOW=$(date +%s)
    LAST=0
    [ -f "$LOCK" ] && LAST=$(cat "$LOCK" 2>/dev/null)
    if [ $((NOW - LAST)) -ge 10 ]; then
      echo "$NOW" > "$LOCK"

      # Click callback: activate terminal + focus the pane
      # Escape single quotes in variables to prevent shell injection
      escape_sq() { printf '%s' "$1" | sed "s/'/'\\\\''/g"; }
      ZELLIJ_BIN=$(command -v zellij)
      FOCUS_CMD="${ZELLIJ_BIN} -s '$(escape_sq "$ZELLIJ_SESSION_NAME")' pipe --name zellaude:focus -- ${ZELLIJ_PANE_ID}"

      # Try notify server first (for SSH remote → laptop notifications)
      NOTIFY_PORT="${ZELLAUDE_NOTIFY_PORT:-2365}"
      NOTIFY_JSON=$(jq -nc --arg t "$TITLE" --arg m "$MESSAGE" --arg p "$ZELLIJ_PANE_ID" \
        '{title: $t, message: $m, pane_id: $p}')
      if printf '%s' "$NOTIFY_JSON" | nc -w 1 127.0.0.1 "$NOTIFY_PORT" >/dev/null 2>&1; then
        : # sent to notify server
      else
        # Fall back to local desktop notification
        case "$(uname)" in
          Darwin)
            [ -n "${TERM_PROGRAM:-}" ] && FOCUS_CMD="open -a '$(escape_sq "${TERM_PROGRAM}")' && ${FOCUS_CMD}"
            if command -v terminal-notifier >/dev/null 2>&1; then
              terminal-notifier \
                -title "$TITLE" \
                -message "$MESSAGE" \
                -execute "$FOCUS_CMD" &
            else
              # Pass values via argv to avoid AppleScript injection
              osascript -e 'on run argv' \
                -e 'display notification (item 2 of argv) with title (item 1 of argv)' \
                -e 'end run' \
                -- "$TITLE" "$MESSAGE" &
            fi
            ;;
          Linux)
            if command -v notify-send >/dev/null 2>&1; then
              notify-send "$TITLE" "$MESSAGE" &
            fi
            ;;
        esac
      fi
    fi
  fi
fi

# Send to plugin (hook is already async, no need to background)
zellij pipe --name "zellaude" -- "$PAYLOAD"

