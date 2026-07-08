# ws

A **nimony-native WebSocket** (RFC 6455) — server and client, over plaintext
(`ws://`) or TLS (`wss://`) — built on the [aoughwl](https://aoughwl.github.io)
`net` stack. No framework runtime, no exceptions: status-based returns and
caller-owned buffers throughout.

```nim
import ws

# --- server: upgrade a connected socket and echo ---
var conn = acceptWebSocket(sock)          # reads the Upgrade, sends 101
var msg: WsMessage
while conn.receive(msg):
  if msg.opcode == opClose: break
  discard conn.sendText("echo: " & msg.data)

# --- client ---
var conn = newClientWebSocket(sock, "example.com", "/chat")
discard conn.sendText("hello")
```

## Contents
{: .no_toc }

- [Motivation](#motivation)
- [What it does](#what-it-does)
- [Layout](#layout)
- [Design notes](#design-notes)
- [Limitations](#limitations)
- [Testing](#testing)
- [Requirements](#requirements)
- [License](#license)

## Motivation

| Want | `ws` |
|---|---|
| A WebSocket that speaks the wire protocol correctly | RFC 6455 framing + the `base64(SHA1(key‖GUID))` accept handshake, verified against the RFC test vector and a live public server |
| The same code for `ws://` and `wss://` | one `WebSocket` over either a `net.Socket` or a `net/tls.TlsSocket` |
| Both ends | server (`acceptWebSocket` / `newServerWebSocket`) and client (`newClientWebSocket`) roles, with correct masking rules per role |
| No surprises on control frames | pings answered with pongs automatically, close frames echoed, fragments reassembled — all inside `receive` |

## What it does

| Capability | Detail |
|---|---|
| Handshake | server validates `Upgrade`/`Connection`/`Sec-WebSocket-Key`, replies `101`; client sends a 16-byte nonce key and verifies `Sec-WebSocket-Accept` |
| Framing | FIN + opcode, 7/16/64-bit lengths, per-role masking (client masks, server never does) |
| Messages | `sendText` / `sendBinary`; `receive` reassembles continuation fragments into one `WsMessage` |
| Control | `ping` / `pong` (auto-pong on inbound ping), `sendClose(code, reason)` + echo |
| Transport | plaintext (`ws://`) and TLS (`wss://`) via the same API |

## Layout

```
ws.nim              # WebSocket type, transport dispatch, send/receive, handshakes
ws/frame.nim        # Opcode + RFC 6455 frame encoder (mask-aware)
ws/handshake.nim    # accept-key (SHA1+base64), Upgrade request/response, validation
tests/
  tws_echo.nim      # loopback: our client ⇄ our server, masking + 200-byte frame + close
  tws_interop.nim   # RFC 6455 accept-key vector + live wss:// echo round-trip
```

## Design notes

- **One socket abstraction.** A private `WsTransport` dispatches reads/writes to a
  plaintext `Socket` or a `TlsSocket`, so `ws://` and `wss://` share every byte of
  the protocol code.
- **Role decides masking.** A client masks every frame with a fresh key; a server
  never masks. `receive` unmasks inbound client frames transparently.
- **Blocking, exact reads.** Frames are read with a `readExactly` loop, so a frame
  never bleeds into the next; the header block reader stops at CRLFCRLF so the
  handshake never swallows following frame bytes.
- nimony-isms: string slices are `.raises`, so everything is char-walked; the
  masking key uses `std/random` seeded per-connection (masking need only be
  well-formed, not cryptographically strong, for the server to unmask).

## Limitations

- `permessage-deflate` (RFC 7692 compression) is not negotiated.
- No built-in ping-timeout / idle timer (set a socket read timeout via `net`).
- The server side upgrades an already-accepted socket; a turnkey `serve`
  integration (handler-level upgrade) is a separate helper.

## Testing

```
nimony c -r --path:. --path:../aoughwl-net --path:../aoughwl-tcp --path:../aoughwl-http tests/tws_echo.nim
nimony c -r --path:. --path:../aoughwl-net --path:../aoughwl-tcp --path:../aoughwl-http tests/tws_interop.nim
```

`tws_echo` round-trips small and >125-byte messages through our own server (masking,
extended length, close). `tws_interop` checks the RFC 6455 accept-key vector and, when
online, a real `wss://` echo server.

## Requirements

- Nimony.
- [`net`](https://github.com/aoughwl/net) (+ its `net/tls`, OpenSSL 3) and
  [`http`](https://github.com/aoughwl/http).

## License

MIT.
