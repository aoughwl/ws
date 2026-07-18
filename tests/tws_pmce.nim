## tws_pmce.nim — permessage-deflate (RFC 7692) end to end. A loopback server and
## client both negotiate the extension in no_context_takeover mode; a large,
## highly-compressible message and a small one round-trip through the compressed
## path (RSV1 set on the wire, deflate on send, inflate on receive).

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
  var conn = newServerWebSocket(sock, req)      # allowDeflate defaults on
  if not conn.open:
    echo "FAIL: server handshake rejected"
    return
  if not conn.deflate:
    echo "FAIL: server did not negotiate permessage-deflate"
    return
  var msg = WsMessage(opcode: opText, data: "")
  while conn.receive(msg):
    if msg.opcode == opClose:
      break
    discard conn.sendText(msg.data)             # echo verbatim, re-compressed
  conn.close()

proc repeat(ch: char; n: int): string =
  result = ""
  var i = 0
  while i < n:
    result.add ch
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
  var conn = newClientWebSocket(sock, "localhost", "/chat", offerDeflate = true)
  check(conn.open, "client handshake failed")
  check(conn.deflate, "client did not negotiate permessage-deflate")

  var msg = WsMessage(opcode: opText, data: "")

  # Highly-compressible large payload — exercises the compressed path hard.
  let big = repeat('A', 4000) & " the quick brown fox " & repeat('Z', 1000)
  check(conn.sendText(big), "send big failed")
  check(conn.receive(msg), "receive big failed")
  check(msg.opcode == opText and msg.data == big,
        "compressed round-trip mismatch (got len " & $msg.data.len & ")")

  # A small message through the same path.
  check(conn.sendText("hi"), "send small failed")
  check(conn.receive(msg), "receive small failed")
  check(msg.data == "hi", "small compressed round-trip mismatch: '" & msg.data & "'")

  # Binary-ish content with all byte values.
  var blob = ""
  var i = 0
  while i < 512:
    blob.add char(uint8((i * 73 + 5) and 0xff))
    inc i
  check(conn.sendBinary(blob), "send blob failed")
  check(conn.receive(msg), "receive blob failed")
  check(msg.data == blob, "binary compressed round-trip mismatch")

  discard conn.sendClose()
  conn.close()
  join(t)
  gListen.close()
  shutdownNet()
  echo "tws_pmce: all checks passed (permessage-deflate round-trip, big msg ",
       $big.len, " bytes)"

main()
