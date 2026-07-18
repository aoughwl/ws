## ws — a nimony-native WebSocket (RFC 6455), server and client, over plaintext
## (`ws://`, a `net.Socket`) or TLS (`wss://`, a `tls.TlsSocket`).
##
##   import ws
##
##   # server: after parsing an HTTP request that is a WebSocket Upgrade
##   var sock = acceptSomeConnection()
##   var conn = newServerWebSocket(sock, req)   # sends 101 Switching Protocols
##   var msg: WsMessage
##   while conn.receive(msg):
##     discard conn.sendText("echo: " & msg.data)
##
##   # client
##   var conn = newClientWebSocket(sock, "example.com", "/chat")
##   discard conn.sendText("hello")
##
## Framing, fragmentation reassembly, automatic pong replies to pings, and the
## close handshake are handled by `receive`. Per RFC 6455 a client masks every
## frame it sends and a server never masks; both are done for you by role.

import std/base64
import net
import tls
import http/request
import ws/frame
import ws/handshake
import ws/rng
import ws/deflate

export frame

type
  WsRole* = enum
    wsServer, wsClient

  WsTransport = object
    isTls: bool
    sock: Socket
    tls: TlsSocket

  WebSocket* = object
    tr: WsTransport
    role*: WsRole
    open*: bool
    # Keepalive (opt-in; both zero = disabled, fully-blocking receive).
    pingIntervalMs: int   ## how often to auto-send a ping when idle
    pongTimeoutMs: int    ## deadline for a pong reply before declaring the peer dead
    nextPingAt: int64     ## monotonic-ms timestamp of the next scheduled ping
    pongDeadline: int64   ## monotonic-ms deadline for an outstanding pong (0 = none)
    deflate*: bool        ## permessage-deflate negotiated (RFC 7692, no_context_takeover)

  WsMessage* = object
    ## A fully-reassembled application message (all fragments joined). `opcode`
    ## is `opText`, `opBinary`, or `opClose` (a close frame is delivered once).
    opcode*: Opcode
    data*: string

# ---------------------------------------------------------------------------
# Transport dispatch (plaintext Socket vs TlsSocket)
# ---------------------------------------------------------------------------

proc plainTransport(sock: Socket): WsTransport =
  WsTransport(isTls: false, sock: sock,
              tls: TlsSocket(socket: invalidSocket(), ssl: nil, handshakeDone: false))

proc tlsTransport(t: TlsSocket): WsTransport =
  WsTransport(isTls: true, sock: invalidSocket(), tls: t)

proc twRead(t: var WsTransport; buf: pointer; n: int): int =
  if t.isTls:
    var st = tlsOk
    return tlsReadInto(t.tls, buf, n, st)
  return recvInto(t.sock, buf, n)

proc twWriteAll(t: var WsTransport; s: string): bool =
  if t.isTls:
    return sendAll(t.tls, s)
  return sendAll(t.sock, s)

proc twClose(t: var WsTransport) =
  if t.isTls:
    t.tls.closeTls()
  else:
    t.sock.close()

proc twWaitReadable(t: var WsTransport; ms: int): bool =
  ## True if the transport has bytes ready within `ms` milliseconds. For TLS,
  ## already-buffered plaintext (SSL_pending) counts as ready.
  if t.isTls:
    if pending(t.tls) > 0: return true
    return waitReadable(t.tls.socket, ms)
  return waitReadable(t.sock, ms)

# ---------------------------------------------------------------------------
# Monotonic clock (for keepalive deadlines)
# ---------------------------------------------------------------------------

type Timespec = object
  tvSec: clong
  tvNsec: clong

proc clockGettime(clkId: cint; tp: ptr Timespec): cint {.cdecl,
  importc: "clock_gettime", header: "<time.h>".}

const CLOCK_MONOTONIC = cint(1)

proc nowMs(): int64 =
  var ts = default(Timespec)
  discard clockGettime(CLOCK_MONOTONIC, addr ts)
  int64(ts.tvSec) * 1000'i64 + int64(ts.tvNsec) div 1_000_000'i64

proc readExactly(t: var WsTransport; n: int): string =
  ## Read exactly `n` bytes; returns "" if the stream ends first (n > 0).
  result = ""
  if n <= 0: return result
  var buf = default(array[4096, char])
  var got = 0
  while got < n:
    var want = n - got
    if want > buf.len: want = buf.len
    let r = twRead(t, addr buf[0], want)
    if r <= 0:
      return ""
    var i = 0
    while i < r:
      result.add buf[i]
      inc i
    got = got + r

proc readHeaderBlock(t: var WsTransport): string =
  ## Read up to and including the CRLFCRLF that ends an HTTP header block.
  result = ""
  var one = default(array[1, char])
  while true:
    let r = twRead(t, addr one[0], 1)
    if r <= 0:
      return result
    result.add one[0]
    let n = result.len
    if n >= 4 and result[n-4] == '\r' and result[n-3] == '\n' and
       result[n-2] == '\r' and result[n-1] == '\n':
      return result

# ---------------------------------------------------------------------------
# Frame read/write
# ---------------------------------------------------------------------------

proc toOpcode(v: int; op: var Opcode): bool =
  case v
  of 0x0: op = opContinuation
  of 0x1: op = opText
  of 0x2: op = opBinary
  of 0x8: op = opClose
  of 0x9: op = opPing
  of 0xA: op = opPong
  else: return false
  return true

proc readFrame(ws: var WebSocket; op: var Opcode; payload: var string;
               fin: var bool; rsv1: var bool): bool =
  let h = readExactly(ws.tr, 2)
  if h.len < 2: return false
  let b0 = uint8(ord(h[0]))
  let b1 = uint8(ord(h[1]))
  fin = (b0 and 0x80'u8) != 0'u8
  rsv1 = (b0 and 0x40'u8) != 0'u8
  if not toOpcode(int(b0 and 0x0f'u8), op):
    return false
  let masked = (b1 and 0x80'u8) != 0'u8
  var length = int(b1 and 0x7f'u8)
  if length == 126:
    let e = readExactly(ws.tr, 2)
    if e.len < 2: return false
    length = (int(uint8(ord(e[0]))) shl 8) or int(uint8(ord(e[1])))
  elif length == 127:
    let e = readExactly(ws.tr, 8)
    if e.len < 8: return false
    length = 0
    var i = 0
    while i < 8:
      length = (length shl 8) or int(uint8(ord(e[i])))
      inc i
  var mask = default(array[4, uint8])
  if masked:
    let m = readExactly(ws.tr, 4)
    if m.len < 4: return false
    var i = 0
    while i < 4:
      mask[i] = uint8(ord(m[i]))
      inc i
  payload = readExactly(ws.tr, length)
  if length > 0 and payload.len < length: return false
  if masked:
    var i = 0
    while i < payload.len:
      payload[i] = char(uint8(ord(payload[i])) xor mask[i and 3])
      inc i
  return true

proc sendFrame(ws: var WebSocket; op: Opcode; data: string; fin: bool): bool =
  let masked = ws.role == wsClient
  # permessage-deflate: compress data messages (never control frames) and flag
  # RSV1. no_context_takeover ⇒ each message is an independent DEFLATE stream.
  var body = data
  var rsv1 = false
  if ws.deflate and (op == opText or op == opBinary):
    let c = deflateMessage(data)
    if c.ok:
      body = c.data
      rsv1 = true
  var mask = default(array[4, uint8])
  if masked:
    mask = randomMask()
  let bytes = encodeFrame(op, body, fin, masked, mask, rsv1)
  twWriteAll(ws.tr, bytes)

# ---------------------------------------------------------------------------
# Public send API
# ---------------------------------------------------------------------------

proc sendText*(ws: var WebSocket; s: string): bool =
  ## Send a complete text message.
  if not ws.open: return false
  sendFrame(ws, opText, s, true)

proc sendBinary*(ws: var WebSocket; s: string): bool =
  ## Send a complete binary message.
  if not ws.open: return false
  sendFrame(ws, opBinary, s, true)

proc ping*(ws: var WebSocket; payload = ""): bool =
  if not ws.open: return false
  sendFrame(ws, opPing, payload, true)

proc pong*(ws: var WebSocket; payload = ""): bool =
  if not ws.open: return false
  sendFrame(ws, opPong, payload, true)

proc sendClose*(ws: var WebSocket; code = 1000; reason = ""): bool =
  ## Send a close frame (2-byte status code + optional UTF-8 reason) and mark the
  ## socket closing.
  var payload = ""
  payload.add char(uint8((code shr 8) and 0xff))
  payload.add char(uint8(code and 0xff))
  payload.add reason
  let ok = sendFrame(ws, opClose, payload, true)
  ws.open = false
  ok

proc close*(ws: var WebSocket) =
  ## Close the underlying transport (after an optional `sendClose`).
  ws.open = false
  twClose(ws.tr)

# ---------------------------------------------------------------------------
# Keepalive (idle ping / dead-peer timeout)
# ---------------------------------------------------------------------------

proc setPingInterval*(ws: var WebSocket; intervalMs: int; timeoutMs = 0) =
  ## Enable keepalive: when the connection has been idle for `intervalMs`,
  ## `receive` auto-sends a ping; if no frame arrives within `timeoutMs` after
  ## that ping (default: same as `intervalMs`), the peer is declared dead and the
  ## connection is closed (`receive` returns false). Opt-in — pass `intervalMs =
  ## 0` (the default) to disable and keep `receive` fully blocking.
  ws.pingIntervalMs = intervalMs
  if timeoutMs > 0:
    ws.pongTimeoutMs = timeoutMs
  else:
    ws.pongTimeoutMs = intervalMs
  ws.pongDeadline = 0
  if intervalMs > 0:
    ws.nextPingAt = nowMs() + int64(intervalMs)
  else:
    ws.nextPingAt = 0

proc keepaliveOn(ws: WebSocket): bool =
  ws.pingIntervalMs > 0

proc resetKeepalive(ws: var WebSocket) =
  ## Called after any frame is received: the peer is alive, so clear an
  ## outstanding pong deadline and push the next ping out.
  if keepaliveOn(ws):
    ws.pongDeadline = 0
    ws.nextPingAt = nowMs() + int64(ws.pingIntervalMs)

proc awaitFrame(ws: var WebSocket): bool =
  ## Block until a frame is readable, driving keepalive. Returns true when the
  ## transport has data to read; false if the peer missed its pong deadline (dead)
  ## and the socket was closed. With keepalive off this blocks indefinitely.
  if not keepaliveOn(ws):
    return true
  while ws.open:
    let now = nowMs()
    var waitMs = ws.pingIntervalMs
    let toPing = int(ws.nextPingAt - now)
    if toPing < waitMs: waitMs = toPing
    if ws.pongDeadline != 0'i64:
      let toDead = int(ws.pongDeadline - now)
      if toDead < waitMs: waitMs = toDead
    if waitMs < 0: waitMs = 0
    if twWaitReadable(ws.tr, waitMs):
      return true
    let now2 = nowMs()
    if ws.pongDeadline != 0'i64 and now2 >= ws.pongDeadline:
      # No pong within the deadline: peer is dead.
      ws.open = false
      twClose(ws.tr)
      return false
    if ws.pongDeadline == 0'i64 and now2 >= ws.nextPingAt:
      if not sendFrame(ws, opPing, "", true):
        ws.open = false
        twClose(ws.tr)
        return false
      ws.pongDeadline = now2 + int64(ws.pongTimeoutMs)
      ws.nextPingAt = now2 + int64(ws.pingIntervalMs)
  return false

# ---------------------------------------------------------------------------
# Public receive API
# ---------------------------------------------------------------------------

proc receive*(ws: var WebSocket; msg: var WsMessage): bool =
  ## Read the next application message, reassembling fragments. Ping frames are
  ## answered with a pong automatically; a close frame is echoed, delivered once
  ## as `msg` (opcode `opClose`), and closes the socket. Returns false at EOF /
  ## protocol error / after close.
  var assembled = ""
  var firstOp = opText
  var started = false
  var compressed = false   ## RSV1 of the message's first frame (permessage-deflate)
  while ws.open:
    if not awaitFrame(ws):
      return false
    var op = opText
    var payload = ""
    var fin = false
    var rsv1 = false
    if not readFrame(ws, op, payload, fin, rsv1):
      ws.open = false
      return false
    resetKeepalive(ws)
    if op == opPing:
      discard sendFrame(ws, opPong, payload, true)
    elif op == opPong:
      discard
    elif op == opClose:
      discard sendFrame(ws, opClose, payload, true)
      ws.open = false
      msg.opcode = opClose
      msg.data = payload
      return true
    elif op == opText or op == opBinary:
      firstOp = op
      started = true
      compressed = rsv1 and ws.deflate
      assembled = payload
      if fin:
        if compressed:
          let d = inflateMessage(assembled)
          if not d.ok:
            ws.open = false
            return false
          assembled = d.data
        msg.opcode = firstOp
        msg.data = assembled
        return true
    elif op == opContinuation:
      if not started:
        ws.open = false
        return false
      assembled.add payload
      if fin:
        if compressed:
          let d = inflateMessage(assembled)
          if not d.ok:
            ws.open = false
            return false
          assembled = d.data
        msg.opcode = firstOp
        msg.data = assembled
        return true
  return false

# ---------------------------------------------------------------------------
# Handshake constructors
# ---------------------------------------------------------------------------

proc newServerWebSocket*(sock: Socket; req: Request; allowDeflate = true): WebSocket =
  ## Complete the server handshake over a plaintext socket: validate the Upgrade
  ## request, send `101 Switching Protocols`, and return an open server-role
  ## WebSocket. On a non-upgrade request the result has `open == false`. When
  ## `allowDeflate` (default) and the client offered `permessage-deflate`, accept
  ## it in no_context_takeover mode.
  result = WebSocket(tr: plainTransport(sock), role: wsServer, open: false)
  if not isWebSocketUpgrade(req):
    return result
  let useDeflate = allowDeflate and requestOffersDeflate(req)
  if twWriteAll(result.tr, serverHandshakeResponse(websocketKey(req), useDeflate)):
    result.open = true
    result.deflate = useDeflate

proc acceptWebSocket*(sock: Socket): WebSocket =
  ## Convenience for a bare server: read the HTTP Upgrade request directly off
  ## `sock`, parse it, and complete the handshake — no need to wire up request
  ## parsing yourself. `open == false` if it is not a valid Upgrade.
  var tr = plainTransport(sock)
  let raw = readHeaderBlock(tr)
  newServerWebSocket(sock, parseRequest(raw))

proc newServerWebSocketTls*(t: TlsSocket; req: Request; allowDeflate = true): WebSocket =
  ## `newServerWebSocket` over TLS (`wss://`).
  result = WebSocket(tr: tlsTransport(t), role: wsServer, open: false)
  if not isWebSocketUpgrade(req):
    return result
  let useDeflate = allowDeflate and requestOffersDeflate(req)
  if twWriteAll(result.tr, serverHandshakeResponse(websocketKey(req), useDeflate)):
    result.open = true
    result.deflate = useDeflate

proc clientKey(): string =
  ## 16 random bytes, base64-encoded, for `Sec-WebSocket-Key`.
  encode(randomBytes(16))

proc doClientHandshake(ws: var WebSocket; host: string; path: string;
                       offerDeflate: bool): bool =
  let key = clientKey()
  if not twWriteAll(ws.tr, clientHandshakeRequest(host, path, key, offerDeflate)):
    return false
  let resp = readHeaderBlock(ws.tr)
  if not clientHandshakeValid(resp, key):
    return false
  ws.deflate = offerDeflate and responseAcceptsDeflate(resp)
  return true

proc newClientWebSocket*(sock: Socket; host: string; path = "/";
                         offerDeflate = false): WebSocket =
  ## Perform the client handshake over an already-connected plaintext socket.
  ## Returns an open client-role WebSocket, or `open == false` if the handshake
  ## is rejected. When `offerDeflate`, advertise `permessage-deflate`
  ## (no_context_takeover); `ws.deflate` reflects whether the server accepted.
  result = WebSocket(tr: plainTransport(sock), role: wsClient, open: false)
  if doClientHandshake(result, host, path, offerDeflate):
    result.open = true

proc newClientWebSocketTls*(t: TlsSocket; host: string; path = "/";
                            offerDeflate = false): WebSocket =
  ## `newClientWebSocket` over TLS (`wss://`).
  result = WebSocket(tr: tlsTransport(t), role: wsClient, open: false)
  if doClientHandshake(result, host, path, offerDeflate):
    result.open = true
