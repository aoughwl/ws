## tws_echo.nim — real WebSocket loopback: a server thread accepts an Upgrade,
## an echo client on the main thread does the full handshake, then a small and a
## >125-byte message round-trip (exercising masking + the 126 extended length),
## followed by the close handshake.

import std/syncio
import std/rawthreads
import net
import http/request
import ws

var gListen = invalidSocket()

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc readRequestBytes(sock: Socket): string =
  ## Read an HTTP request header block (up to CRLFCRLF) one byte at a time so we
  ## don't consume any following WebSocket frame bytes.
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
  var msg = WsMessage(opcode: opText, data: "")
  while conn.receive(msg):
    if msg.opcode == opClose:
      break
    discard conn.sendText("echo:" & msg.data)
  conn.close()

proc bigPayload(): string =
  result = ""
  var i = 0
  while i < 200:
    result.add 'x'
    inc i

proc main =
  initNet()
  gListen = listen(0)
  check(gListen.isValid, "listen failed")
  let port = localEndpoint(gListen).port
  check(port > 0, "no ephemeral port")

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

  var msg = WsMessage(opcode: opText, data: "")

  check(conn.sendText("hello"), "send text failed")
  check(conn.receive(msg), "receive failed")
  check(msg.opcode == opText and msg.data == "echo:hello",
        "echo mismatch: '" & msg.data & "'")

  let big = bigPayload()
  check(conn.sendText(big), "send big failed")
  check(conn.receive(msg), "receive big failed")
  check(msg.data == "echo:" & big, "big echo mismatch (len " & $msg.data.len & ")")

  discard conn.sendClose()
  conn.close()
  join(t)
  gListen.close()
  shutdownNet()
  echo "tws_echo: all checks passed"

main()
