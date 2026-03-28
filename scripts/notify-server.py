#!/usr/bin/env python3
"""zellaude notification server — desktop notifications over TCP, with optional TLS.

Commands:

  serve — run the notification server:
    python3 notify-server.py serve                                  # plain, localhost only
    python3 notify-server.py serve --host 0.0.0.0 --tls-dir certs  # plain + TLS on same port

  connect — subscribe to a server, show notifications locally:
    python3 notify-server.py connect --host server:2365                     # plain
    python3 notify-server.py connect --host server:2365 --tls-dir certs    # TLS

  pair — trust-on-first-use: connect to server, verify shared code, download cert:
    python3 notify-server.py pair --host server:2365 --tls-dir certs

  forward — tell a running server to forward notifications to a remote host:
    python3 notify-server.py forward --host remote:2365

  gen-cert — generate TLS certificates (uses openssl CLI):
    python3 notify-server.py gen-cert --ca                        # create CA + server cert
    python3 notify-server.py gen-cert --name phone                # create client cert signed by CA

Protocol (single port, plain + TLS):
  - Plain TCP (from localhost): hook scripts send JSON via nc, one-shot.
  - TLS connections: authenticated via client certificate, full access.
  - First byte detection: 0x16 = TLS ClientHello, otherwise plain TCP.
  - Pairing: client connects with TLS (no cert verification), both sides show
    an 8-char code. If codes match, server signs a client cert and sends it back.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

RATE_LIMIT_SECS = 10
DEFAULT_TLS_DIR = os.path.expanduser("~/.config/zellaude/certs")

last_notify: dict[str, float] = {}
log_file = None


def log(msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    if log_file:
        with open(log_file, "a") as f:
            f.write(line + "\n")
    else:
        print(line, flush=True)


# --- PID file helpers ---

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
    os.makedirs(os.path.dirname(pid_path) or ".", exist_ok=True)
    with open(pid_path, "w") as f:
        f.write(str(os.getpid()))


def remove_pid(pid_path: str) -> None:
    try:
        os.remove(pid_path)
    except OSError:
        pass


# --- Notification backends ---

def detect_backend() -> str:
    if shutil.which("termux-notification"):
        return "termux"
    system = platform.system()
    if system == "Darwin":
        if shutil.which("terminal-notifier"):
            return "terminal-notifier"
        return "osascript"
    if system == "Linux" and shutil.which("notify-send"):
        return "notify-send"
    return "none"


def notify(title: str, message: str, backend: str) -> None:
    if backend == "osascript":
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
    elif backend == "terminal-notifier":
        subprocess.Popen(
            ["terminal-notifier", "-title", title, "-message", message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    elif backend == "termux":
        subprocess.Popen(
            ["termux-notification", "--title", title, "--content", message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    elif backend == "notify-send":
        subprocess.Popen(
            ["notify-send", title, message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        log("no notification backend available")


# --- Server state ---

subscribers: list[socket.socket] = []
subscribers_lock = threading.Lock()

forward_targets: list[tuple[str, int]] = []
forward_targets_lock = threading.Lock()

# Pending pairing requests: nonce -> threading.Event (set when approved)
pairing_requests: dict[str, threading.Event] = {}
pairing_lock = threading.Lock()


def push_to_subscribers(data: bytes) -> None:
    line = data.strip() + b"\n"
    with subscribers_lock:
        dead = []
        for sock in subscribers:
            try:
                sock.sendall(line)
            except OSError:
                dead.append(sock)
        for sock in dead:
            subscribers.remove(sock)
            log(f"Subscriber disconnected ({len(subscribers)} remaining)")
            try:
                sock.close()
            except OSError:
                pass


def forward_to_targets(data: bytes) -> None:
    with forward_targets_lock:
        targets = list(forward_targets)
    for host, port in targets:
        threading.Thread(
            target=_send_one_shot, args=(data.strip(), host, port), daemon=True
        ).start()


def _send_one_shot(data: bytes, host: str, port: int) -> None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        sock.sendall(data)
        sock.close()
        log(f"  -> forwarded to {host}:{port}")
    except OSError as e:
        log(f"  -> forward to {host}:{port} failed: {e}")


def handle_notification(data: bytes, backend: str) -> None:
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
    notify(title, message, backend)
    push_to_subscribers(data)
    forward_to_targets(data)


bind_host = "127.0.0.1"


def is_control_allowed(addr: tuple, has_client_cert: bool) -> bool:
    if has_client_cert:
        return True
    if bind_host in ("127.0.0.1", "::1", "localhost"):
        return addr[0] in ("127.0.0.1", "::1")
    return True


def make_pairing_code(nonce: str, server_random: str) -> str:
    """Derive an 8-char verification code from nonce + server_random."""
    h = hashlib.sha256(f"{nonce}:{server_random}".encode()).hexdigest()
    return f"{h[:4]}-{h[4:8]}"


def handle_connection(conn: socket.socket, addr: tuple, backend: str,
                      tls_ctx: ssl.SSLContext | None,
                      tls_dir: str | None) -> None:
    is_tls = False
    has_client_cert = False
    try:
        conn.settimeout(2.0)
        first_byte = conn.recv(1, socket.MSG_PEEK)
        if not first_byte:
            conn.close()
            return

        if first_byte[0] == 0x16:
            if not tls_ctx:
                log(f"TLS connection from {addr[0]} but TLS not configured, rejecting")
                conn.close()
                return
            try:
                conn = tls_ctx.wrap_socket(conn, server_side=True)
                is_tls = True
                peer_cert = conn.getpeercert()
                cn = ""
                if peer_cert:
                    has_client_cert = True
                    for rdn in peer_cert.get("subject", ()):
                        for attr, val in rdn:
                            if attr == "commonName":
                                cn = val
                    log(f"TLS connection from {addr[0]}:{addr[1]} (CN={cn})")
                else:
                    log(f"TLS connection from {addr[0]}:{addr[1]} (no client cert)")
            except ssl.SSLError as e:
                log(f"TLS handshake failed from {addr[0]}:{addr[1]}: {e}")
                conn.close()
                return

        conn.settimeout(2.0)
        data = conn.recv(4096)
        if not data:
            conn.close()
            return

        try:
            msg = json.loads(data.strip())

            # Subscribe
            if msg.get("subscribe"):
                if not is_control_allowed(addr, has_client_cert):
                    log(f"Rejected subscribe from {addr[0]} (not authenticated)")
                    conn.close()
                    return
                conn.settimeout(None)
                with subscribers_lock:
                    subscribers.append(conn)
                tag = " [TLS]" if is_tls else ""
                log(f"Subscriber connected from {addr[0]}:{addr[1]}{tag} ({len(subscribers)} total)")
                return

            # Forward instruction
            if "forward" in msg:
                if not is_control_allowed(addr, has_client_cert):
                    log(f"Rejected forward from {addr[0]} (not authenticated)")
                    conn.close()
                    return
                target = msg["forward"]
                host, port = parse_host_port(target, 2365)
                with forward_targets_lock:
                    if (host, port) not in forward_targets:
                        forward_targets.append((host, port))
                        log(f"Forward target added: {host}:{port} ({len(forward_targets)} total)")
                    else:
                        log(f"Forward target already exists: {host}:{port}")
                conn.sendall(json.dumps({"ok": True, "forward": f"{host}:{port}"}).encode())
                conn.close()
                return

            # Pairing request
            if "pair" in msg and is_tls and tls_dir:
                client_name = str(msg.get("name", "client"))
                nonce = msg["pair"]
                server_random = secrets.token_hex(16)
                code = make_pairing_code(nonce, server_random)

                W = 28
                log(f"")
                log(f"  ┌{'─' * W}┐")
                log(f"  │{f'  PAIRING CODE:  {code}  ':<{W}}│")
                log(f"  │{f'  Client: {client_name}':<{W}}│")
                log(f"  │{f'  From:   {addr[0]}':<{W}}│")
                log(f"  └{'─' * W}┘")
                log(f"")
                log(f"  Type 'yes' to approve, anything else to reject:")

                # Send server_random to client so it can derive the same code
                conn.sendall(json.dumps({"pairing_code": code, "server_random": server_random}).encode() + b"\n")

                # Wait for server operator to approve (via stdin on server)
                evt = threading.Event()
                with pairing_lock:
                    pairing_requests[code] = evt

                approved = evt.wait(timeout=60)

                with pairing_lock:
                    pairing_requests.pop(code, None)

                if not approved:
                    conn.sendall(json.dumps({"error": "pairing rejected or timed out"}).encode())
                    conn.close()
                    return

                # Generate and sign client cert
                csr_data = conn.recv(8192)
                if not csr_data:
                    conn.close()
                    return

                try:
                    csr_msg = json.loads(csr_data.strip())
                    csr_pem = csr_msg.get("csr", "")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    conn.sendall(json.dumps({"error": "bad CSR"}).encode())
                    conn.close()
                    return

                # Sign the CSR with our CA
                signed_cert = _sign_csr_with_openssl(csr_pem, tls_dir, client_name)
                if not signed_cert:
                    conn.sendall(json.dumps({"error": "signing failed"}).encode())
                    conn.close()
                    return

                # Send back signed cert + CA cert
                ca_pem = _read_file(os.path.join(tls_dir, "ca.pem"))
                conn.sendall(json.dumps({
                    "cert": signed_cert,
                    "ca": ca_pem,
                }).encode())
                log(f"Pairing complete for {client_name} from {addr[0]}")
                conn.close()
                return

        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # One-shot notification
        log(f"Notification from {addr[0]}:{addr[1]}")
        handle_notification(data, backend)
        conn.close()
    except OSError:
        try:
            conn.close()
        except OSError:
            pass


def _read_file(path: str) -> str:
    with open(path) as f:
        return f.read()


def _sign_csr_with_openssl(csr_pem: str, tls_dir: str, name: str) -> str | None:
    """Sign a CSR using the CA key/cert via openssl CLI."""
    ca_cert = os.path.join(tls_dir, "ca.pem")
    ca_key = os.path.join(tls_dir, "ca-key.pem")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as csr_f:
        csr_f.write(csr_pem)
        csr_path = csr_f.name

    cert_path = csr_path + ".cert"

    try:
        subprocess.run(
            [
                "openssl", "x509", "-req",
                "-in", csr_path,
                "-CA", ca_cert,
                "-CAkey", ca_key,
                "-CAserial", os.path.join(tls_dir, "ca.srl"), "-CAcreateserial",
                "-out", cert_path,
                "-days", "3650",
                "-sha256",
            ],
            check=True, capture_output=True,
        )
        with open(cert_path) as f:
            return f.read()
    except (subprocess.CalledProcessError, OSError) as e:
        log(f"CSR signing failed: {e}")
        return None
    finally:
        for p in (csr_path, cert_path):
            try:
                os.remove(p)
            except OSError:
                pass


def make_server_tls_ctx(tls_dir: str) -> ssl.SSLContext:
    """Single TLS context: accepts clients with or without certs (CERT_OPTIONAL).
    Uses PROTOCOL_TLS for LibreSSL compatibility (PROTOCOL_TLS_SERVER is broken
    on macOS Python 3.9 + LibreSSL 3.3)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx.load_cert_chain(
        certfile=os.path.join(tls_dir, "server.pem"),
        keyfile=os.path.join(tls_dir, "server-key.pem"),
    )
    ctx.load_verify_locations(cafile=os.path.join(tls_dir, "ca.pem"))
    ctx.verify_mode = ssl.CERT_OPTIONAL
    # Disable client-side protocols — this context is server-only
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    ctx.set_ciphers("DEFAULT:!aNULL:!MD5")
    return ctx


def make_client_tls_ctx(tls_dir: str, name: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx.load_cert_chain(
        certfile=os.path.join(tls_dir, f"{name}.pem"),
        keyfile=os.path.join(tls_dir, f"{name}-key.pem"),
    )
    ctx.load_verify_locations(cafile=os.path.join(tls_dir, "ca.pem"))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    ctx.set_ciphers("DEFAULT:!aNULL:!MD5")
    return ctx


def approval_input_loop():
    """Background thread reading stdin for pairing approvals."""
    while True:
        try:
            line = input().strip().lower()
        except EOFError:
            break
        if line == "yes":
            with pairing_lock:
                # Approve the most recent pending request
                for code, evt in pairing_requests.items():
                    if not evt.is_set():
                        evt.set()
                        log(f"Pairing {code} approved")
                        break
        elif line.startswith("no"):
            log("Pairing rejected")


def cmd_serve(args: argparse.Namespace) -> None:
    global log_file, bind_host
    log_file = args.log
    bind_host = args.host
    backend = args.backend or detect_backend()

    tls_ctx = None
    tls_dir = args.tls_dir
    if tls_dir:
        try:
            tls_ctx = make_server_tls_ctx(tls_dir)
            log(f"TLS enabled (certs from {tls_dir})")
        except (ssl.SSLError, FileNotFoundError, OSError) as e:
            log(f"TLS setup failed: {e}")
            sys.exit(1)

    if is_already_running(args.pid):
        print(f"Already running (pid file: {args.pid})", file=sys.stderr)
        sys.exit(0)

    write_pid(args.pid)

    def cleanup(_sig=None, _frame=None):
        remove_pid(args.pid)
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    # Start approval input thread if TLS is configured
    if tls_dir:
        threading.Thread(target=approval_input_loop, daemon=True).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(5)
    tls_str = " +TLS" if tls_ctx else ""
    log(f"Serving on {args.host}:{args.port}{tls_str} (pid {os.getpid()}, backend: {backend})")

    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(
                target=handle_connection,
                args=(conn, addr, backend, tls_ctx, tls_dir),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        log("Shutting down")
    finally:
        with subscribers_lock:
            for s in subscribers:
                try:
                    s.close()
                except OSError:
                    pass
        sock.close()
        remove_pid(args.pid)


# --- Client mode ---

def cmd_connect(args: argparse.Namespace) -> None:
    global log_file
    log_file = args.log
    backend = args.backend or detect_backend()

    host, port = args.host, args.port

    tls_ctx = None
    if args.tls_dir:
        tls_ctx = make_client_tls_ctx(args.tls_dir, args.cert_name)
        log(f"TLS enabled (cert: {args.cert_name}, certs from {args.tls_dir})")

    log(f"Connecting to {host}:{port} (backend: {backend})")

    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if tls_ctx:
                sock = tls_ctx.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))
            sock.sendall(json.dumps({"subscribe": True}).encode() + b"\n")
            log(f"Connected to {host}:{port}")

            buf = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    raise ConnectionError("server closed connection")
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        log("bad line from server, ignoring")
                        continue

                    title = str(msg.get("title", "Notification"))
                    message = str(msg.get("message", ""))
                    pane_id = str(msg.get("pane_id", ""))

                    now = time.time()
                    if now - last_notify.get(pane_id, 0) < RATE_LIMIT_SECS:
                        log(f"rate-limited (pane {pane_id})")
                        continue
                    last_notify[pane_id] = now

                    log(f"-> {title}: {message}")
                    notify(title, message, backend)

        except KeyboardInterrupt:
            log("Disconnected")
            break
        except OSError as e:
            log(f"Connection lost ({e}), reconnecting in 5s...")
            time.sleep(5)


# --- Forward command ---

def cmd_forward(args: argparse.Namespace) -> None:
    host, port = args.host, args.port
    target = f"{host}:{port}"
    server_port = args.server_port

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect(("127.0.0.1", server_port))
        sock.sendall(json.dumps({"forward": target}).encode())
        resp = sock.recv(4096)
        sock.close()
        try:
            result = json.loads(resp)
            if result.get("ok"):
                print(f"Server will forward to {result['forward']}")
            else:
                print(f"Unexpected response: {resp.decode()}", file=sys.stderr)
                sys.exit(1)
        except json.JSONDecodeError:
            print(f"Bad response: {resp.decode()}", file=sys.stderr)
            sys.exit(1)
    except OSError as e:
        print(f"Could not reach server on 127.0.0.1:{server_port}: {e}", file=sys.stderr)
        sys.exit(1)


# --- Pairing command ---

def cmd_pair(args: argparse.Namespace) -> None:
    host, port = args.host, args.port
    tls_dir = args.tls_dir
    name = args.name

    os.makedirs(tls_dir, exist_ok=True)

    # Generate client key + CSR
    key_path = os.path.join(tls_dir, f"{name}-key.pem")
    csr_path = os.path.join(tls_dir, f"{name}.csr")

    subprocess.run(
        ["openssl", "req", "-new", "-newkey", "rsa:2048",
         "-nodes", "-keyout", key_path, "-out", csr_path, "-subj", f"/CN={name}"],
        check=True, capture_output=True,
    )
    os.chmod(key_path, 0o600)

    with open(csr_path) as f:
        csr_pem = f.read()

    # Connect with TLS but don't verify server cert (trust-on-first-use)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    ctx.set_ciphers("DEFAULT:!aNULL:!MD5")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.connect((host, port))

    # Send pairing request with a nonce
    nonce = secrets.token_hex(16)
    sock.sendall(json.dumps({"pair": nonce, "name": name}).encode() + b"\n")

    # Receive server's response with the pairing code
    data = sock.recv(4096)
    resp = json.loads(data.strip())

    if "error" in resp:
        print(f"Error: {resp['error']}", file=sys.stderr)
        sys.exit(1)

    server_random = resp["server_random"]
    code = make_pairing_code(nonce, server_random)

    W = 28
    print(f"")
    print(f"  ┌{'─' * W}┐")
    print(f"  │{f'  PAIRING CODE:  {code}  ':<{W}}│")
    print(f"  └{'─' * W}┘")
    print(f"")
    print(f"  Verify this code matches the server, then approve on the server.")
    print(f"  Waiting...")

    # Send CSR
    sock.sendall(json.dumps({"csr": csr_pem}).encode() + b"\n")

    # Receive signed cert + CA
    sock.settimeout(90)
    cert_data = sock.recv(16384)
    sock.close()

    try:
        cert_resp = json.loads(cert_data.strip())
    except json.JSONDecodeError:
        print(f"Bad response from server", file=sys.stderr)
        sys.exit(1)

    if "error" in cert_resp:
        print(f"Error: {cert_resp['error']}", file=sys.stderr)
        sys.exit(1)

    # Save cert and CA
    cert_path = os.path.join(tls_dir, f"{name}.pem")
    ca_path = os.path.join(tls_dir, "ca.pem")

    with open(cert_path, "w") as f:
        f.write(cert_resp["cert"])
    with open(ca_path, "w") as f:
        f.write(cert_resp["ca"])

    # Cleanup CSR
    try:
        os.remove(csr_path)
    except OSError:
        pass

    print(f"")
    print(f"  Pairing complete!")
    print(f"  Certificate: {cert_path}")
    print(f"  CA:          {ca_path}")
    print(f"  Key:         {key_path}")
    print(f"")
    print(f"  Connect with:")
    print(f"    python3 notify-server.py connect --host {host}:{port} --tls-dir {tls_dir} --cert-name {name}")


# --- Certificate generation (openssl CLI) ---

def cmd_gen_cert(args: argparse.Namespace) -> None:
    if not shutil.which("openssl"):
        print("Error: openssl CLI required", file=sys.stderr)
        sys.exit(1)

    tls_dir = args.tls_dir
    os.makedirs(tls_dir, exist_ok=True)

    if args.ca:
        ca_key = os.path.join(tls_dir, "ca-key.pem")
        ca_cert = os.path.join(tls_dir, "ca.pem")

        # Generate CA
        subprocess.run(
            ["openssl", "req", "-x509", "-new", "-newkey", "rsa:2048",
             "-nodes", "-keyout", ca_key, "-out", ca_cert, "-days", "3650",
             "-subj", "/CN=zellaude-ca"],
            check=True, capture_output=True,
        )
        os.chmod(ca_key, 0o600)
        print(f"CA certificate: {ca_cert}")
        print(f"CA private key: {ca_key}")

        # Generate server cert signed by CA
        _gen_signed_cert_openssl("server", tls_dir)
    else:
        name = args.name
        if not name:
            print("Error: --name required (or use --ca to create CA + server cert)", file=sys.stderr)
            sys.exit(1)

        ca_key = os.path.join(tls_dir, "ca-key.pem")
        ca_cert = os.path.join(tls_dir, "ca.pem")
        if not os.path.exists(ca_key) or not os.path.exists(ca_cert):
            print(f"Error: CA not found in {tls_dir}. Run with --ca first.", file=sys.stderr)
            sys.exit(1)

        _gen_signed_cert_openssl(name, tls_dir)


def _gen_signed_cert_openssl(name: str, tls_dir: str) -> None:
    ca_key = os.path.join(tls_dir, "ca-key.pem")
    ca_cert = os.path.join(tls_dir, "ca.pem")
    key_path = os.path.join(tls_dir, f"{name}-key.pem")
    cert_path = os.path.join(tls_dir, f"{name}.pem")
    csr_path = os.path.join(tls_dir, f"{name}.csr")

    # Generate key + CSR
    subprocess.run(
        ["openssl", "req", "-new", "-newkey", "rsa:2048",
         "-nodes", "-keyout", key_path, "-out", csr_path,
         "-subj", f"/CN={name}"],
        check=True, capture_output=True,
    )
    os.chmod(key_path, 0o600)

    # Sign with CA — try with SAN extensions first, fall back without
    ext_file = csr_path + ".ext"
    with open(ext_file, "w") as f:
        f.write(f"subjectAltName=DNS:{name},DNS:localhost,IP:127.0.0.1\n")

    sign_cmd = [
        "openssl", "x509", "-req", "-in", csr_path,
        "-CA", ca_cert, "-CAkey", ca_key, "-CAserial", os.path.join(tls_dir, "ca.srl"), "-CAcreateserial",
        "-out", cert_path, "-days", "3650", "-sha256",
    ]

    result = subprocess.run(sign_cmd + ["-extfile", ext_file], capture_output=True)
    if result.returncode != 0:
        # LibreSSL on macOS may not support -extfile with x509 -req; retry without
        result = subprocess.run(sign_cmd, capture_output=True)
        if result.returncode != 0:
            print(f"openssl error: {result.stderr.decode()}", file=sys.stderr)
            sys.exit(1)

    # Cleanup
    for p in (csr_path, ext_file):
        try:
            os.remove(p)
        except OSError:
            pass

    print(f"Certificate: {cert_path}")
    print(f"Private key: {key_path}")


# --- CLI ---

def parse_host_port(value: str, default_port: int) -> tuple[str, int]:
    if ":" in value:
        host, port_str = value.rsplit(":", 1)
        return host, int(port_str)
    return value, default_port


def main() -> None:
    parser = argparse.ArgumentParser(
        description="zellaude notification server/client"
    )
    sub = parser.add_subparsers(dest="command")

    serve_p = sub.add_parser("serve", help="run notification server")
    serve_p.add_argument("--host", default="127.0.0.1", help="listen address (default: 127.0.0.1)")
    serve_p.add_argument("--port", type=int, default=2365, help="listen port (default: 2365)")
    serve_p.add_argument("--pid", default="/tmp/zellaude-notify.pid", help="pid file path")
    serve_p.add_argument("--log", default=None, help="log file path (default: stdout)")
    serve_p.add_argument("--backend", default=None,
                         choices=["osascript", "terminal-notifier", "termux", "notify-send", "none"],
                         help="notification backend (default: auto-detect)")
    serve_p.add_argument("--tls-dir", default=None,
                         help="TLS certificate directory (expects ca.pem, server.pem, server-key.pem)")

    conn_p = sub.add_parser("connect", help="connect to notification server as client")
    conn_p.add_argument("--host", default="localhost", help="server host (default: localhost)")
    conn_p.add_argument("--port", type=int, default=2365, help="server port (default: 2365)")
    conn_p.add_argument("--log", default=None, help="log file path (default: stdout)")
    conn_p.add_argument("--backend", default=None,
                         choices=["osascript", "terminal-notifier", "termux", "notify-send", "none"],
                         help="notification backend (default: auto-detect)")
    conn_p.add_argument("--tls-dir", default=None, help="TLS certificate directory")
    conn_p.add_argument("--cert-name", default="client",
                         help="client cert name in tls-dir (default: client)")

    fwd_p = sub.add_parser("forward", help="tell server to forward to a remote host")
    fwd_p.add_argument("--host", required=True, help="remote host (or host:port)")
    fwd_p.add_argument("--port", type=int, default=2365,
                        help="remote port (default: 2365, overridden by host:port)")
    fwd_p.add_argument("--server-port", type=int, default=2365,
                        help="local server port (default: 2365)")

    pair_p = sub.add_parser("pair", help="pair with a server (trust-on-first-use)")
    pair_p.add_argument("--host", required=True, help="server host (or host:port)")
    pair_p.add_argument("--port", type=int, default=2365,
                        help="server port (default: 2365, overridden by host:port)")
    pair_p.add_argument("--tls-dir", default=DEFAULT_TLS_DIR,
                        help=f"save certs here (default: {DEFAULT_TLS_DIR})")
    pair_p.add_argument("--name", default="client", help="client certificate name (default: client)")

    cert_p = sub.add_parser("gen-cert", help="generate TLS certificates")
    cert_p.add_argument("--ca", action="store_true", help="create CA + server cert (run first)")
    cert_p.add_argument("--name", default=None, help="client certificate name")
    cert_p.add_argument("--tls-dir", default=DEFAULT_TLS_DIR,
                        help=f"output directory (default: {DEFAULT_TLS_DIR})")

    args = parser.parse_args()

    if args.command == "serve":
        cmd_serve(args)
    elif args.command == "connect":
        cmd_connect(args)
    elif args.command == "forward":
        host, port = parse_host_port(args.host, args.port)
        args.host = host
        args.port = port
        cmd_forward(args)
    elif args.command == "pair":
        host, port = parse_host_port(args.host, args.port)
        args.host = host
        args.port = port
        cmd_pair(args)
    elif args.command == "gen-cert":
        cmd_gen_cert(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
