#!/usr/bin/env python3
"""zellaude notification server — receives JSON over TCP and shows macOS notifications.

Run on your laptop, forward the port over SSH:
  python3 notify-server.py                              # defaults
  python3 notify-server.py --port 2365 --pid /tmp/zellaude-notify.pid --log /tmp/zellaude-notify.log
  ssh -R 2365:localhost:2365 server
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time

RATE_LIMIT_SECS = 10

last_notify: dict[str, float] = {}
log_file = None


def log(msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    if log_file:
        with open(log_file, "a") as f:
            f.write(line + "\n")
    else:
        print(line, flush=True)


def is_already_running(pid_path: str) -> bool:
    if not os.path.exists(pid_path):
        return False
    try:
        with open(pid_path) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True
    except (ValueError, ProcessLookupError, PermissionError, OSError):
        return False


def write_pid(pid_path: str) -> None:
    with open(pid_path, "w") as f:
        f.write(str(os.getpid()))


def remove_pid(pid_path: str) -> None:
    try:
        os.remove(pid_path)
    except OSError:
        pass


def notify(title: str, message: str) -> None:
    subprocess.Popen(
        [
            "osascript",
            "-e", "on run argv",
            "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
            "-e", "end run",
            "--", title, message,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def handle(data: bytes) -> None:
    try:
        msg = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        log("bad payload, ignoring")
        return

    title = str(msg.get("title", "Notification"))
    message = str(msg.get("message", ""))
    pane_id = str(msg.get("pane_id", ""))

    now = time.time()
    if now - last_notify.get(pane_id, 0) < RATE_LIMIT_SECS:
        log(f"rate-limited (pane {pane_id})")
        return
    last_notify[pane_id] = now

    log(f"-> {title}: {message}")
    notify(title, message)


def main() -> None:
    global log_file

    parser = argparse.ArgumentParser(description="zellaude notification server")
    parser.add_argument("--port", type=int, default=2365, help="listen port (default: 2365)")
    parser.add_argument("--pid", default="/tmp/zellaude-notify.pid", help="pid file path")
    parser.add_argument("--log", default=None, help="log file path (default: stdout)")
    args = parser.parse_args()

    log_file = args.log

    if is_already_running(args.pid):
        print(f"Already running (pid file: {args.pid})", file=sys.stderr)
        sys.exit(0)

    write_pid(args.pid)

    def cleanup(_sig=None, _frame=None):
        remove_pid(args.pid)
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", args.port))
    sock.listen(5)
    log(f"Listening on 127.0.0.1:{args.port} (pid {os.getpid()})")

    try:
        while True:
            conn, addr = sock.accept()
            try:
                data = conn.recv(4096)
                log(f"Received from {addr[0]}:{addr[1]}")
                handle(data)
            finally:
                conn.close()
    except KeyboardInterrupt:
        log("Shutting down")
    finally:
        sock.close()
        remove_pid(args.pid)


if __name__ == "__main__":
    main()
