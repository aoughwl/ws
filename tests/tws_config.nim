## tws_config.nim — connection policy as a record, in force from the first frame.
##
## `maxFrame` and `maxMessage` were public fields you set on the socket the
## handshake returned. That leaves a window: the handshake itself and anything
## read before the assignment run under the defaults. tws_limits.nim shows the
## old shape — accept, then assign the bounds, then loop. Here the bounds
## arrive with the constructor, and the hostile frame is the *first* thing the
## client sends, so nothing but a policy applied at construction can catch it.

import std/syncio
import std/rawthreads
import net
import ws
import ws/protocol

const ServerMaxFrame = 4096

var gListen = invalidSocket()

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc serverThread(arg: pointer) {.nimcall.} =
  discard arg
  let sock = accept(gListen)
  if not sock.isValid:
    echo "FAIL: server accept"
    return
  # The whole policy, at construction. Note this also uses the handshake cap,
  # which no other entry point can reach: the header block is read here, before
  # any WebSocket exists to carry a bound.
  var cfg = defaultWsConfig()
  cfg.maxFrame = ServerMaxFrame
  cfg.maxMessage = ServerMaxFrame
  cfg.maxHandshake = 4096
  var conn = acceptWebSocket(sock, cfg)
  if not conn.open:
    echo "FAIL: server handshake rejected"
    return
  if conn.maxFrame != ServerMaxFrame:
    echo "FAIL: the config did not reach the connection"
    return
  var msg = WsMessage(opcode: opText, data: "")
  while conn.receive(msg):
    if msg.opcode == opClose:
      break
    discard conn.sendText("echo:" & msg.data)
  if conn.tooBig:
    echo "SERVER_TOOBIG"
  conn.close()

proc main =
  # --- the record on its own ---------------------------------------------
  check(WsUnset != 0,
        "unset must differ from 0, which means unlimited for a bound and off for a timer")
  check(defaultWsConfig().pingIntervalMs == 0,
        "keepalive is off by default: it changes receive from blocking to timer-driven")
  check(strictWsConfig().pingIntervalMs > 0, "the strict profile turns keepalive on")
  check(strictWsConfig().maxFrame < defaultWsConfig().maxFrame,
        "the strict profile really is stricter")

  var over = noWsConfig()
  over.maxFrame = 1234
  let merged = merge(defaultWsConfig(), over)
  check(merged.maxFrame == 1234, "the set field overrides")
  check(merged.maxMessage == DefaultMaxMessage,
        "tightening one bound does not disturb the others")
  check(merged.maxHandshake == DefaultMaxHandshake, "nor the handshake cap")

  # A config that says nothing about compression must not change what a call
  # would otherwise negotiate — and the default differs by role.
  check(wantsDeflate(defaultWsConfig(), true), "unset keeps a server's default of on")
  check(not wantsDeflate(defaultWsConfig(), false), "unset keeps a client's default of off")
  var noComp = noWsConfig()
  noComp.deflate = wsOff
  check(not wantsDeflate(noComp, true), "an explicit off overrides the caller's default")
  check(handshakeCap(noWsConfig()) == DefaultMaxHandshake, "unset cap resolves")

  # --- the bound is in force for the first frame -------------------------
  initNet()
  gListen = listen(0)
  check(gListen.isValid, "listen failed")
  let port = localEndpoint(gListen).port

  var t = default(RawThread)
  try:
    create(t, serverThread, nil)
  except:
    echo "FAIL: thread create failed"
    quit(1)

  let sock = connectLocalhost(port)
  check(sock.isValid, "client connect failed")
  var conn = newClientWebSocket(sock, "localhost", "/chat", defaultWsConfig())
  check(conn.open, "client handshake failed")

  # FIN|text, masked, extended length 2^40, and no payload. This is the first
  # frame on the connection: under the old shape the server had to have already
  # run its post-handshake assignment to catch it.
  var hostile = ""
  hostile.add char(0x81)
  hostile.add char(0xFF)
  let huge = 1'i64 shl 40
  var i = 7
  while i >= 0:
    hostile.add char(uint8((huge shr (8 * i)) and 0xff'i64))
    dec i
  var k = 0
  while k < 4:
    hostile.add char(0x00)
    inc k
  check(sendAll(sock, hostile), "send hostile frame failed")

  var reply = WsMessage(opcode: opText, data: "")
  check(conn.receive(reply), "no reply to the oversized first frame")
  check(reply.opcode == opClose, "expected a close frame")
  check(reply.data.len >= 2, "close frame carries no status code")
  let code = (int(uint8(ord(reply.data[0]))) shl 8) or int(uint8(ord(reply.data[1])))
  check(code == CloseMessageTooBig, "expected close 1009, got " & $code)

  conn.close()
  join(t)
  gListen.close()
  shutdownNet()
  echo "ok"

main()
