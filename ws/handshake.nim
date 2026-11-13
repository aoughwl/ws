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
import http/response

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

const deflateOffer = "permessage-deflate; client_no_context_takeover; server_no_context_takeover"

proc requestOffersDeflate*(req: Request): bool =
  ## True when the client offered the `permessage-deflate` extension (RFC 7692).
  containsToken(headerValue(req.headers, "Sec-WebSocket-Extensions"), "permessage-deflate")

proc responseAcceptsDeflate*(responseHeaders: string): bool =
  ## True when the server's handshake response accepted `permessage-deflate`.
  containsToken(responseHeaders, "permessage-deflate")

proc serverHandshakeResponse*(clientKey: string; withDeflate = false): string =
  ## The `101 Switching Protocols` response completing the server handshake. When
  ## `withDeflate`, echo a `permessage-deflate` acceptance in no_context_takeover
  ## mode.
  result = "HTTP/1.1 101 Switching Protocols\r\n"
  result.add "Upgrade: websocket\r\n"
  result.add "Connection: Upgrade\r\n"
  result.add "Sec-WebSocket-Accept: "
  result.add acceptKey(clientKey)
  result.add "\r\n"
  if withDeflate:
    result.add "Sec-WebSocket-Extensions: " & deflateOffer & "\r\n"
  result.add "\r\n"

proc clientHandshakeRequest*(host: string; path: string; key: string;
                             offerDeflate = false; protocols = ""): string =
  ## The client's Upgrade request. `key` is a base64-encoded 16-byte nonce. When
  ## `offerDeflate`, advertise `permessage-deflate` in no_context_takeover mode. `protocols`
  ## is a comma separated subprotocol offer (Sec-WebSocket-Protocol), "" for none; `host` is
  ## what goes on the Host line, so include ":port" when it is not the scheme's default.
  var p = path
  if p.len == 0:
    p = "/"
  result = "GET " & p & " HTTP/1.1\r\n"
  result.add "Host: " & host & "\r\n"
  result.add "Upgrade: websocket\r\n"
  result.add "Connection: Upgrade\r\n"
  result.add "Sec-WebSocket-Key: " & key & "\r\n"
  if offerDeflate:
    result.add "Sec-WebSocket-Extensions: " & deflateOffer & "\r\n"
  if protocols.len > 0:
    result.add "Sec-WebSocket-Protocol: " & protocols & "\r\n"
  result.add "Sec-WebSocket-Version: 13\r\n\r\n"

proc clientHandshakeValid*(responseHeaders: string; sentKey: string): bool =
  ## Verify a server's raw handshake response (RFC 6455 4.2.2): status 101, `Upgrade: websocket`,
  ## `Connection: Upgrade` and a `Sec-WebSocket-Accept` equal to the one we expect. This used to be
  ## two substring searches over the whole block ("101" and the accept value anywhere), so a 200
  ## or 301 that happened to contain both strings passed.
  let r = parseResponse(responseHeaders)
  if r.status != 101: return false
  if not containsToken(headerValue(r.headers, "Upgrade"), "websocket"): return false
  if not containsToken(headerValue(r.headers, "Connection"), "upgrade"): return false
  headerValue(r.headers, "Sec-WebSocket-Accept") == acceptKey(sentKey)

proc responseProtocol*(responseHeaders: string): string =
  ## The subprotocol the server picked (Sec-WebSocket-Protocol), "" when it picked none.
  headerValue(parseResponse(responseHeaders).headers, "Sec-WebSocket-Protocol")

proc protocolAccepted*(offered: string; chosen: string): bool =
  ## RFC 6455 4.2.2: the server may only answer with one of the subprotocols the client offered
  ## (comma separated list, compared exactly after trimming). Nothing chosen is fine.
  if chosen.len == 0: return true
  var i = 0
  while i <= offered.len:
    var item = ""
    while i < offered.len and offered[i] != ',':
      item.add offered[i]
      inc i
    var a = 0
    var b = item.len
    while a < b and (item[a] == ' ' or item[a] == '\t'): inc a
    while b > a and (item[b - 1] == ' ' or item[b - 1] == '\t'): dec b
    var trimmed = ""
    var k = a
    while k < b:
      trimmed.add item[k]
      inc k
    if trimmed == chosen: return true
    inc i
  return false
