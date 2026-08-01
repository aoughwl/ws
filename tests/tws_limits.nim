## tws_limits.nim — the frame/message size bounds.
##
## A WebSocket frame header carries a peer-chosen 64-bit length, and `readFrame`
## used to hand it straight to `readExactly`: a header claiming 2^40 bytes made
## the receiver try to allocate 2^40 bytes. Fragment reassembly was likewise
## unbounded. Close code 1009 was defined and never sent.
##
## Here a hostile client hand-writes a frame header advertising a huge payload
## WITHOUT sending the payload. The server must refuse it from the header alone
## — before allocating, and without waiting for bytes that never arrive — and
## answer Close 1009.

import std/syncio
import std/rawthreads
import net
import http/request
import ws
import ws/protocol

const ServerMaxFrame = 4096

var gListen = invalidSocket()

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc readRequestBytes(sock: Socket): string =
  result = ""
  var one = default(array[1, char])
  while true:
    let r = recvInto(sock, addr one[0], 1)
    if r <= 0:
      return result
    result.add one[0]
    let n = result.len
    if n >= 4 and result[n-4] == '\r' and result[n-3] == '\n' and
       result[n-2] == '\r' and result[n-1] == '\n':
      return result

proc serverThread(arg: pointer) {.nimcall.} =
  discard arg
  let sock = accept(gListen)
  if not sock.isValid:
    echo "FAIL: server accept"
    return
  let req = parseRequest(readRequestBytes(sock))
  var conn = newServerWebSocket(sock, req)
  if not conn.open:
    echo "FAIL: server handshake rejected"
    return
  conn.maxFrame = ServerMaxFrame
  conn.maxMessage = ServerMaxFrame
  var msg = WsMessage(opcode: opText, data: "")
  # one legitimate message first, then the hostile frame ends the loop
  while conn.receive(msg):
    if msg.opcode == opClose:
      break
    discard conn.sendText("echo:" & msg.data)
  if conn.tooBig:
    echo "SERVER_TOOBIG"
  conn.close()

proc main =
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
  var conn = newClientWebSocket(sock, "localhost", "/chat")
  check(conn.open, "client handshake failed")

  # a normal message still works with bounds in force
  var msg = WsMessage(opcode: opText, data: "")
  check(conn.sendText("hello"), "send text failed")
  check(conn.receive(msg), "receive failed")
  check(msg.data == "echo:hello", "echo mismatch: '" & msg.data & "'")

  # --- the hostile frame -------------------------------------------------
  # FIN|text, masked, 127 extended length = 2^40, and then NOTHING. A receiver
  # that trusts the length allocates a terabyte or blocks forever; a bounded
  # one rejects on the header alone.
  var hostile = ""
  hostile.add char(0x81)          # FIN + opText
  hostile.add char(0xFF)          # MASK + length == 127
  let huge = 1'i64 shl 40
  var i = 7
  while i >= 0:
    hostile.add char(uint8((huge shr (8 * i)) and 0xff'i64))
    dec i
  var k = 0
  while k < 4:                    # masking key; no payload follows
    hostile.add char(0x00)
    inc k
  check(sendAll(sock, hostile), "send hostile frame failed")

  # the server must answer Close 1009 rather than hang or die
  var reply = WsMessage(opcode: opText, data: "")
  let got = conn.receive(reply)
  check(got, "no reply to the oversized frame")
  check(reply.opcode == opClose, "expected a close frame")
  check(reply.data.len >= 2, "close frame carries no status code")
  let code = (int(uint8(ord(reply.data[0]))) shl 8) or int(uint8(ord(reply.data[1])))
  check(code == CloseMessageTooBig,
        "expected close 1009, got " & $code)

  conn.close()
  join(t)
  gListen.close()
  shutdownNet()
  echo "ok"

main()
