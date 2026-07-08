## ws/handshake.nim — the HTTP/1.1 Upgrade handshake for WebSocket (RFC 6455 §4).
##
## Server side: recognize an Upgrade request, read its `Sec-WebSocket-Key`, and
## build the `101 Switching Protocols` response whose `Sec-WebSocket-Accept` is
## base64(SHA1(key & GUID)). Client side: build the Upgrade request and verify
## the server's accept value.

import std/sha1
import std/base64
import http/headers
import http/request

const wsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

proc acceptKey*(clientKey: string): string =
  ## base64(SHA1(clientKey & GUID)) — the value the server echoes back so the
  ## client can prove the peer understood the WebSocket handshake.
  var st = newSha1State()
  let combined = clientKey & wsGuid
  st.update(combined)
  let digest = st.finalize()
  encode(digest)

proc containsToken(hay: string; token: string): bool =
  ## Case-insensitive substring match (headers like `Connection: keep-alive,
  ## Upgrade` list multiple tokens).
  if token.len == 0: return true
  if token.len > hay.len: return false
  var i = 0
  while i + token.len <= hay.len:
    var j = 0
    var ok = true
    while j < token.len:
      var a = hay[i + j]
      var b = token[j]
      if a >= 'A' and a <= 'Z': a = chr(ord(a) + 32)
      if b >= 'A' and b <= 'Z': b = chr(ord(b) + 32)
      if a != b:
        ok = false
        break
      inc j
    if ok: return true
    inc i
  return false

proc isWebSocketUpgrade*(req: Request): bool =
  ## True when `req` is a WebSocket Upgrade request (Upgrade: websocket +
  ## Connection: Upgrade + a Sec-WebSocket-Key).
  if not containsToken(headerValue(req.headers, "Upgrade"), "websocket"):
    return false
  if not containsToken(headerValue(req.headers, "Connection"), "upgrade"):
    return false
  headerValue(req.headers, "Sec-WebSocket-Key").len > 0

proc websocketKey*(req: Request): string =
  ## The client's `Sec-WebSocket-Key` header value.
  headerValue(req.headers, "Sec-WebSocket-Key")

proc serverHandshakeResponse*(clientKey: string): string =
  ## The `101 Switching Protocols` response completing the server handshake.
  result = "HTTP/1.1 101 Switching Protocols\r\n"
  result.add "Upgrade: websocket\r\n"
  result.add "Connection: Upgrade\r\n"
  result.add "Sec-WebSocket-Accept: "
  result.add acceptKey(clientKey)
  result.add "\r\n\r\n"

proc clientHandshakeRequest*(host: string; path: string; key: string): string =
  ## The client's Upgrade request. `key` is a base64-encoded 16-byte nonce.
  var p = path
  if p.len == 0:
    p = "/"
  result = "GET " & p & " HTTP/1.1\r\n"
  result.add "Host: " & host & "\r\n"
  result.add "Upgrade: websocket\r\n"
  result.add "Connection: Upgrade\r\n"
  result.add "Sec-WebSocket-Key: " & key & "\r\n"
  result.add "Sec-WebSocket-Version: 13\r\n\r\n"

proc clientHandshakeValid*(responseHeaders: string; sentKey: string): bool =
  ## Verify a server's raw handshake response: it must carry the expected
  ## `Sec-WebSocket-Accept` for the key we sent.
  containsToken(responseHeaders, "101") and
    containsToken(responseHeaders, acceptKey(sentKey))
