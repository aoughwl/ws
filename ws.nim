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

import std/random
import std/base64
import net
import tls
import http/request
import ws/frame
import ws/handshake

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
    rng: Rand

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
               fin: var bool): bool =
  let h = readExactly(ws.tr, 2)
  if h.len < 2: return false
  let b0 = uint8(ord(h[0]))
  let b1 = uint8(ord(h[1]))
  fin = (b0 and 0x80'u8) != 0'u8
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

proc nextMask(ws: var WebSocket): array[4, uint8] =
  result = default(array[4, uint8])
  let r = next(ws.rng)
  result[0] = uint8(r and 0xff'u64)
  result[1] = uint8((r shr 8) and 0xff'u64)
  result[2] = uint8((r shr 16) and 0xff'u64)
  result[3] = uint8((r shr 24) and 0xff'u64)

proc sendFrame(ws: var WebSocket; op: Opcode; data: string; fin: bool): bool =
  let masked = ws.role == wsClient
  var mask = default(array[4, uint8])
  if masked:
    mask = nextMask(ws)
  let bytes = encodeFrame(op, data, fin, masked, mask)
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
  while ws.open:
    var op = opText
    var payload = ""
    var fin = false
    if not readFrame(ws, op, payload, fin):
      ws.open = false
      return false
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
      assembled = payload
      if fin:
        msg.opcode = firstOp
        msg.data = assembled
        return true
    elif op == opContinuation:
      if not started:
        ws.open = false
        return false
      assembled.add payload
      if fin:
        msg.opcode = firstOp
        msg.data = assembled
        return true
  return false

# ---------------------------------------------------------------------------
# Handshake constructors
# ---------------------------------------------------------------------------

var gWsSeed = 0x9e3779b9'i64

proc seedRng(fd: int): Rand =
  gWsSeed = gWsSeed + 0x6d2b79f5'i64
  initRand(gWsSeed + int64(fd) * 2654435761'i64)

proc newServerWebSocket*(sock: Socket; req: Request): WebSocket =
  ## Complete the server handshake over a plaintext socket: validate the Upgrade
  ## request, send `101 Switching Protocols`, and return an open server-role
  ## WebSocket. On a non-upgrade request the result has `open == false`.
  result = WebSocket(tr: plainTransport(sock), role: wsServer, open: false,
                     rng: seedRng(int(sock.handle)))
  if not isWebSocketUpgrade(req):
    return result
  if twWriteAll(result.tr, serverHandshakeResponse(websocketKey(req))):
    result.open = true

proc acceptWebSocket*(sock: Socket): WebSocket =
  ## Convenience for a bare server: read the HTTP Upgrade request directly off
  ## `sock`, parse it, and complete the handshake — no need to wire up request
  ## parsing yourself. `open == false` if it is not a valid Upgrade.
  var tr = plainTransport(sock)
  let raw = readHeaderBlock(tr)
  newServerWebSocket(sock, parseRequest(raw))

proc newServerWebSocketTls*(t: TlsSocket; req: Request): WebSocket =
  ## `newServerWebSocket` over TLS (`wss://`).
  result = WebSocket(tr: tlsTransport(t), role: wsServer, open: false,
                     rng: seedRng(int(t.socket.handle)))
  if not isWebSocketUpgrade(req):
    return result
  if twWriteAll(result.tr, serverHandshakeResponse(websocketKey(req))):
    result.open = true

proc clientKey(ws: var WebSocket): string =
  ## 16 random bytes, base64-encoded, for `Sec-WebSocket-Key`.
  var raw = ""
  var j = 0
  while j < 2:
    let r = next(ws.rng)
    var shift = 0
    while shift < 64:
      raw.add char(uint8((r shr shift) and 0xff'u64))
      shift = shift + 8
    inc j
  encode(raw)

proc doClientHandshake(ws: var WebSocket; host: string; path: string): bool =
  let key = clientKey(ws)
  if not twWriteAll(ws.tr, clientHandshakeRequest(host, path, key)):
    return false
  let resp = readHeaderBlock(ws.tr)
  clientHandshakeValid(resp, key)

proc newClientWebSocket*(sock: Socket; host: string; path = "/"): WebSocket =
  ## Perform the client handshake over an already-connected plaintext socket.
  ## Returns an open client-role WebSocket, or `open == false` if the handshake
  ## is rejected.
  result = WebSocket(tr: plainTransport(sock), role: wsClient, open: false,
                     rng: seedRng(int(sock.handle)))
  if doClientHandshake(result, host, path):
    result.open = true

proc newClientWebSocketTls*(t: TlsSocket; host: string; path = "/"): WebSocket =
  ## `newClientWebSocket` over TLS (`wss://`).
  result = WebSocket(tr: tlsTransport(t), role: wsClient, open: false,
                     rng: seedRng(int(t.socket.handle)))
  if doClientHandshake(result, host, path):
    result.open = true
