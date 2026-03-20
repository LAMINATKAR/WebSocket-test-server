# WebSocket Test Server

A lightweight Python WebSocket test server for monitoring and testing WebSocket handshakes.
Supports both `ws://` and `wss://` protocols with optional Basic Auth.

## Features
- Simultaneous `ws://` and `wss://` support
- Detailed handshake logging (headers, auth, connect/disconnect)
- Basic Auth (enable/disable via flag)
- Auto-generated self-signed certificate (no OpenSSL required)
- Logs to console and `ws_server.log`

## Install

```bash
pip install websockets cryptography
```

## Usage

| Parameters | Result |
|---|---|
| _(empty)_ | both ports, auth ON |
| `--ws` | `ws://` only, auth ON |
| `--wss` | `wss://` only, auth ON |
| `--both` | both ports, auth ON |
| `--no-auth` | both ports, auth OFF |
| `--ws --no-auth` | `ws://` only, auth OFF |
| `--wss --no-auth` | `wss://` only, auth OFF |

## Endpoints

| Protocol | Address |
|---|---|
| WS | `ws://localhost:8765` |
| WSS | `wss://localhost:8766` |

## Authentication

Uses HTTP Basic Auth (`Authorization: Basic <base64>`).  
Edit the `USERS` dict in the script to add/change credentials.

## Notes

- WSS uses a self-signed certificate — clients must ignore certificate verification
- Server sends `OK` immediately after handshake (for response time monitoring)
- All activity is logged to `ws_server.log`