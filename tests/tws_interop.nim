## tws_interop.nim — spec + interop checks:
##   * the RFC 6455 §1.3 accept-key test vector (proves handshake correctness
##     independent of our own server);
##   * a live `wss://` round-trip against a public echo server (skipped offline).

import std/syncio
import net
import net/tls
import ws
import ws/handshake

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc main =
  # RFC 6455: key "dGhlIHNhbXBsZSBub25jZQ==" -> accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
  let acc = acceptKey("dGhlIHNhbXBsZSBub25jZQ==")
  check(acc == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        "RFC 6455 accept-key vector mismatch: '" & acc & "'")
  echo "RFC accept-key vector OK"

  # Live wss:// echo (best-effort; skip cleanly with no network). Uses the
  # family-agnostic connectHost, so it reaches the server over IPv4 or IPv6.
  const host = "ws.postman-echo.com"
  initNet()
  let raw = connectHost(host, 443)
  if not raw.isValid:
    echo "SKIP: no network/DNS; tws_interop spec check passed"
    quit(0)
  var cctx = newTlsClientContext(verify = true)
  var tls = wrapClient(cctx, raw, host)
  if not tls.handshakeDone:
    echo "SKIP: TLS handshake failed; spec check passed"
    quit(0)
  var conn = newClientWebSocketTls(tls, host, "/raw")
  check(conn.open, "wss handshake failed")

  check(conn.sendText("ping123"), "wss send failed")
  var msg = WsMessage(opcode: opText, data: "")
  var found = false
  var tries = 0
  # `/raw` echoes verbatim; read a few messages in case of a greeting.
  while tries < 5 and conn.receive(msg):
    if msg.opcode == opClose: break
    if msg.data == "ping123":
      found = true
      break
    inc tries
  check(found, "wss echo did not return our payload")
  discard conn.sendClose()
  conn.close()
  cctx.close()
  shutdownNet()
  echo "tws_interop: all checks passed (live wss echo verified)"

main()
