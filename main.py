#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           WebSocket test server — ws:// and wss://           ║
╠══════════════════════════════════════════════════════════════╣
║  Install:                                                    ║
║    pip install websockets cryptography                       ║
║                                                              ║
║  Script parameters (PyCharm Run → Edit Configurations):      ║
║    (empty)             both ports, authentication ON         ║
║    --ws                ws:// only, authentication ON         ║
║    --wss               wss:// only, authentication ON        ║
║    --both              both ports (same as empty)            ║
║    --no-auth           both ports, authentication OFF        ║
║    --ws --no-auth      ws:// only, authentication OFF        ║
║    --wss --no-auth     wss:// only, authentication OFF       ║
║                                                              ║
║  Addresses:                                                  ║
║    ws://localhost:8765                                       ║
║    wss://localhost:8766                                      ║
║                                                              ║
║  Authentication:                                             ║
║    Type:    Basic Auth (Authorization: Basic <base64>)       ║
║    Format:  Authorization: Basic <base64(user:password)>     ║
║    Users:   see USERS dict below                             ║
║                                                              ║
║  WSS note:                                                   ║
║    Uses a self-signed certificate (cert.pem / key.pem).      ║
║    Client must ignore certificate verification.              ║
║    Certificate is generated automatically via cryptography.  ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import argparse
import base64
import logging
import os
import ssl
from datetime import datetime

import websockets
try:
    from websockets.server import ServerConnection as WebSocketServerProtocol  # v12+
except ImportError:
    from websockets.legacy.server import WebSocketServerProtocol               # v10/11

# ── logging ──────────────────────────────────────────────────────────────────

LOG_FILE = "ws_server.log"

fmt = logging.Formatter(
    fmt="%(asctime)s.%(msecs)03d  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

console = logging.StreamHandler()
console.setFormatter(fmt)

fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setFormatter(fmt)

log = logging.getLogger("ws")
log.setLevel(logging.DEBUG)
log.addHandler(console)
log.addHandler(fh)

logging.getLogger("websockets").setLevel(logging.WARNING)

# ── config ───────────────────────────────────────────────────────────────────

WS_PORT   = 8765
WSS_PORT  = 8766
CERT_FILE = "cert.pem"
KEY_FILE  = "key.pem"

# allowed users  { "user": "password", ... }
USERS = {
    "admin": "secret",
    "test":  "1234",
}

connected: dict[str, WebSocketServerProtocol] = {}   # addr → ws


# ── TLS ──────────────────────────────────────────────────────────────────────

def make_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        log.info(f"TLS  certificate found ({CERT_FILE}), skipping generation")
        return
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        log.info("TLS  generating self-signed certificate (cryptography)...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256())
        )
        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        log.info(f"TLS  certificate created → {CERT_FILE} / {KEY_FILE}")
    except ImportError:
        log.error("TLS  missing library 'cryptography'. Run: pip install cryptography")
        raise


def build_ssl_context() -> ssl.SSLContext:
    make_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    return ctx


# ── auth ─────────────────────────────────────────────────────────────────────

def check_basic_auth(headers: dict) -> tuple[bool, str]:
    """Returns (ok, username). If failed, username contains the reason."""
    raw = headers.get("Authorization", "")
    if not raw.lower().startswith("basic "):
        return False, "missing Authorization header"
    try:
        decoded = base64.b64decode(raw[6:]).decode("utf-8")
        user, pwd = decoded.split(":", 1)
    except Exception:
        return False, "invalid Base64 / format"
    if user not in USERS:
        return False, f"unknown user '{user}'"
    if USERS[user] != pwd:
        return False, f"wrong password for '{user}'"
    return True, user


# ── handler ──────────────────────────────────────────────────────────────────

def sep(char="─", n=56) -> str:
    return char * n


async def handler(ws: WebSocketServerProtocol, auth: bool):
    try:
        is_tls = isinstance(ws.transport.get_extra_info("ssl_object"), ssl.SSLObject)
    except Exception:
        is_tls = False
    proto = "WSS" if is_tls else "WS "
    addr  = f"{ws.remote_address[0]}:{ws.remote_address[1]}"
    key   = addr

    # ── handshake received ───────────────────────────────────────────────────
    log.info(sep())
    log.info(f"{proto} HANDSHAKE   {addr}")

    path        = getattr(ws, "path", None) or getattr(ws.request, "path", "—")
    subprotocol = getattr(ws, "subprotocol", None) or "—"
    log.info(f"     path       : {path}")
    log.info(f"     subprotocol: {subprotocol}")

    hdrs = dict(getattr(ws, "request_headers", None) or ws.request.headers)
    for h in ("Host", "Origin", "Upgrade", "Connection",
              "Sec-WebSocket-Key", "Sec-WebSocket-Version",
              "Sec-WebSocket-Extensions", "User-Agent", "Authorization"):
        if h in hdrs:
            val = hdrs[h]
            if h == "Authorization":
                val = val[:10] + "…"
            log.info(f"     {h:<28}: {val}")

    # ── authentication ───────────────────────────────────────────────────────
    if auth:
        raw_auth = hdrs.get("Authorization", "")
        log.info(f"{proto} AUTH HEADER {addr}  Authorization: '{raw_auth[:60] or '—'}'")
        ok, user_or_reason = check_basic_auth(hdrs)
        if not ok:
            log.warning(f"{proto} AUTH FAIL   {addr}  → {user_or_reason}")
            log.warning(f"{proto}              Expected: Authorization: Basic <base64(user:pass)>")
            log.warning(f"{proto}              Received headers: {', '.join(hdrs.keys())}")
            await ws.close(1008, "Unauthorized")
            return
        log.info(f"{proto} AUTH OK     {addr}  user='{user_or_reason}'")
    else:
        log.info(f"{proto} AUTH SKIP   {addr}  (authentication disabled)")

    connected[key] = ws
    log.info(f"{proto} CONNECTED   {addr}  (active: {len(connected)})")

    # send welcome message immediately (for response time measurement)
    await ws.send("OK")

    # ── keep connection alive ────────────────────────────────────────────────
    try:
        async for raw in ws:
            preview = raw[:240] + ("…" if len(raw) > 240 else "")
            log.info(f"{proto} MESSAGE     {addr}  {preview!r}")

    except websockets.exceptions.ConnectionClosedOK as e:
        log.info(f"{proto} CLOSE OK    {addr}  code={e.code}  reason={e.reason!r}")
    except websockets.exceptions.ConnectionClosedError as e:
        log.warning(f"{proto} CLOSE ERR   {addr}  code={e.code}  reason={e.reason!r}")
    except Exception as e:
        log.error(f"{proto} ERROR       {addr}  {type(e).__name__}: {e}")
    finally:
        connected.pop(key, None)
        log.info(f"{proto} DISCONNECTED {addr}  (active: {len(connected)})")
        log.info(sep())


# ── main ─────────────────────────────────────────────────────────────────────

async def main(mode: str, auth: bool):
    servers = []

    if mode in ("ws", "both"):
        srv = await websockets.serve(lambda ws: handler(ws, auth), "0.0.0.0", WS_PORT)
        servers.append(srv)
        log.info(f"Listening  ws://localhost:{WS_PORT}")

    if mode in ("wss", "both"):
        ssl_ctx = build_ssl_context()
        srv = await websockets.serve(lambda ws: handler(ws, auth), "0.0.0.0", WSS_PORT, ssl=ssl_ctx)
        servers.append(srv)
        log.info(f"Listening  wss://localhost:{WSS_PORT}  (self-signed cert)")

    log.info(f"Authentication: {'ON' if auth else 'OFF'}")
    log.info(f"Logs also saved to → {LOG_FILE}")
    log.info("Ctrl+C to stop")
    log.info(sep("═"))

    await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WS/WSS handshake test server")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--wss",  action="store_true", help="wss:// only")
    grp.add_argument("--both", action="store_true", help="ws:// and wss://")
    grp.add_argument("--ws",   action="store_true", help="ws:// only")
    parser.add_argument("--no-auth", action="store_true", help="disable authentication")
    args = parser.parse_args()

    mode = "wss" if args.wss else ("ws" if args.ws else ("both" if args.both else "both"))
    AUTH_ENABLED = not args.no_auth

    try:
        asyncio.run(main(mode, AUTH_ENABLED))
    except KeyboardInterrupt:
        log.info("Server stopped.")