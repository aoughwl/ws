## tws_ping.nim — keepalive / dead-peer timeout. A server accepts the handshake
## then goes silent (never reads, never pongs). The client enables keepalive with
## a short ping interval + pong deadline; `receive` must auto-ping, get no pong,
## and close the connection within the deadline — well before the silent server
## eventually hangs up.

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

# --- tiny FFI helpers for sleep + monotonic timing (test-local) --------------
proc cUsleep(usec: cuint): cint {.cdecl, importc: "usleep", header: "<unistd.h>".}

type Timespec = object
  tvSec: clong
  tvNsec: clong
proc clockGettime(clkId: cint; tp: ptr Timespec): cint {.cdecl,
  importc: "clock_gettime", header: "<time.h>".}
proc monoMs(): int64 =
  var ts = default(Timespec)
  discard clockGettime(cint(1), addr ts)
  int64(ts.tvSec) * 1000'i64 + int64(ts.tvNsec) div 1_000_000'i64

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

proc silentServer(arg: pointer) {.nimcall.} =
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
  # Deliberately unresponsive: never read, never pong. Hold the socket open long
  # enough that the client's keepalive deadline (not our hangup) is what closes.
  discard cUsleep(cuint(5_000_000))   # 5 s
  conn.close()

proc main =
  initNet()
  gListen = listen(0)
  check(gListen.isValid, "listen failed")
  let port = localEndpoint(gListen).port
  check(port > 0, "no ephemeral port")

  var t = default(RawThread)
  try:
    create(t, silentServer, nil)
  except:
    echo "FAIL: thread create failed"
    quit(1)

  let sock = connectLocalhost(port)
  check(sock.isValid, "client connect failed")
  var conn = newClientWebSocket(sock, "localhost", "/chat")
  check(conn.open, "client handshake failed")

  # Ping every 200 ms; a missing pong for 300 ms means the peer is dead. Expected
  # close at ~500 ms.
  conn.setPingInterval(200, 300)

  var msg = WsMessage(opcode: opText, data: "")
  let t0 = monoMs()
  let alive = conn.receive(msg)
  let elapsed = monoMs() - t0

  check(not alive, "receive should return false on a dead (no-pong) peer")
  check(not conn.open, "connection should be closed after the pong timeout")
  # Must fire on the deadline (~500 ms), long before the server's 5 s hangup.
  check(elapsed >= 300'i64, "closed too early (" & $elapsed & " ms) — not deadline-driven")
  check(elapsed < 3000'i64, "closed too late (" & $elapsed & " ms) — deadline not enforced")

  conn.close()
  join(t)
  gListen.close()
  shutdownNet()
  echo "tws_ping: all checks passed (dead peer closed in ", $elapsed, " ms)"

main()
