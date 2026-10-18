# WebSocket Test Server

A lightweight Python WebSocket test server for monitoring and testing WebSocket handshakes.
Supports both `ws://` and `wss://` protocols with optional Basic Auth.

## Features
- Simultaneous `ws://` and `wss://` support
- Detailed handshake logging (headers, auth, connect/disconnect, incoming messages)
- Basic Auth (enable/disable via flag)
- Auto-generated self-signed certificate (no OpenSSL required)
- Logs to console and `ws_server.log`

## Requirements

- Python 3.9+
- `websockets` 13+ and `cryptography` (see `requirements.txt`)

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py [--ws | --wss | --both] [--no-auth] [--host ADDR]
```

| Parameters | Result |
|---|---|
| _(empty)_ | both ports, auth ON |
| `--ws` | `ws://` only, auth ON |
| `--wss` | `wss://` only, auth ON |
| `--both` | both ports, auth ON |
| `--no-auth` | both ports, auth OFF |
| `--ws --no-auth` | `ws://` only, auth OFF |
| `--wss --no-auth` | `wss://` only, auth OFF |
| `--host 127.0.0.1` | listen on localhost only (default `0.0.0.0` = all interfaces) |

## Endpoints

| Protocol | Address |
|---|---|
| WS | `ws://localhost:8765` |
| WSS | `wss://localhost:8766` |

Ports can be changed via `WS_PORT` / `WSS_PORT` at the top of `main.py`.

## Authentication

Uses HTTP Basic Auth (`Authorization: Basic <base64(user:password)>`).
Edit the `USERS` dict in `main.py` to add/change credentials. The default
users (`admin` / `secret`, `test` / `1234`) are for testing only.

The handshake itself is accepted; if the credentials are missing or wrong,
the server closes the connection right away with code `1008 Unauthorized`.

Example with [websocat](https://github.com/vi/websocat) (`YWRtaW46c2VjcmV0` = `admin:secret`):

```bash
websocat -H "Authorization: Basic YWRtaW46c2VjcmV0" ws://localhost:8765
```

## Notes

- WSS uses a self-signed certificate (`cert.pem` / `key.pem`, generated on first run, valid 365 days) — clients must ignore certificate verification. Delete both files to regenerate.
- Server sends `OK` immediately after a successful handshake (for response time monitoring)
- Incoming text/binary messages are logged (first 240 characters/bytes), not answered
- All activity is logged to `ws_server.log` in the working directory

## Security

This is a testing tool, not a production server. It listens on all interfaces
by default and ships with well-known demo credentials — use `--host 127.0.0.1`
or a firewall if the machine is reachable from untrusted networks.
