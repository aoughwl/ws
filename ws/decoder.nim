## ws/decoder.nim — an incremental, transport-free RFC 6455 frame decoder.
##
## `ws.nim`'s `receive` reads frames straight off a blocking transport (`readFrame` -> `readExactly`),
## so nothing can decode from a byte buffer: not a poll loop, not a reader thread that must also
## answer pings under a write lock, not a test. This is the same job as a value you feed:
##
##   var d = newWsDecoder(clientRole = true, maxMessage = 16 * 1024 * 1024, checkUtf8 = true)
##   wsFeed(d, bytesJustRead)            # any split, down to one byte at a time
##   while wsPending(d) > 0:
##     let kind = wsNextKind(d)          # 1 text, 2 binary
##     let data = wsPop(d)
##   # d.pings: payloads to answer with a pong (the caller owns the socket, so the caller sends);
##   # d.closeSeen / d.closeCode / d.closeReason: the peer's Close; d.err / d.errCode: a protocol error,
##   # `errCode` being the close code to send (1002 protocol error, 1007 bad UTF-8, 1009 too big).
##
## Checks `readFrame`/`receive` do not make: reserved bits and unknown opcodes (1002), control frames
## that are fragmented or longer than 125 bytes (1002), a continuation with nothing to continue or a
## new data frame inside a fragmented message (1002), masking that does not match the role (a server
## must not mask, a client must), a 64-bit length with the top bit set, UTF-8 validity of text and
## of the Close reason (1007), Close code validity and a 1-byte Close payload (1002), and a bound on
## the reassembled message (1009) that also covers a single large frame.
##
## Status-based, nothing raises, char-walked (no slices).

import protocol

type
  WsDecoder* = object
    buf: string
    pos: int
    partial: string          ## fragments of the message being reassembled
    partialKind: int         ## 0 none, 1 text, 2 binary
    msgs*: seq[string]       ## complete messages, oldest first (use wsPending / wsPop)
    kinds*: seq[int]
    qhead: int
    pings*: seq[string]      ## ping payloads to answer; clear with wsClearPings
    pongs*: int              ## pongs seen
    closeSeen*: bool
    closeCode*: int          ## 1005 when the Close carried no code
    closeReason*: string
    err*: string             ## "" while healthy
    errCode*: int            ## the close code to send for `err`
    maxMessage*: int         ## 0 = unlimited
    expectMasked*: bool      ## true when decoding frames from a client (we are the server)
    checkUtf8*: bool

proc newWsDecoder*(clientRole: bool; maxMessage: int; checkUtf8: bool): WsDecoder =
  ## `clientRole`: we are the client, so the peer is a server and its frames must NOT be masked.
  WsDecoder(buf: "", pos: 0, partial: "", partialKind: 0, msgs: @[], kinds: @[], qhead: 0,
            pings: @[], pongs: 0, closeSeen: false, closeCode: 0, closeReason: "",
            err: "", errCode: 0, maxMessage: maxMessage, expectMasked: not clientRole,
            checkUtf8: checkUtf8)

proc wsFail(d: var WsDecoder; code: int; msg: string) =
  if d.err.len == 0:
    d.err = msg
    d.errCode = code

proc copyRange(s: string; a, b: int): string =
  ## [a, b)
  result = ""
  var i = a
  while i < b and i < s.len:
    result.add s[i]
    inc i

proc deliver(d: var WsDecoder; kind: int; data: string) =
  if kind == 1 and d.checkUtf8 and not validateUtf8(data):
    wsFail(d, CloseInvalidPayload, "a text message is not valid UTF-8")
    return
  d.msgs.add data
  d.kinds.add kind

proc handleClose(d: var WsDecoder; payload: string) =
  d.closeSeen = true
  if payload.len == 0:
    d.closeCode = 1005
    return
  if payload.len == 1:
    wsFail(d, CloseProtocolError, "a Close frame has a 1-byte payload")
    return
  let code = (ord(payload[0]) shl 8) or ord(payload[1])
  if not isValidCloseCode(code):
    wsFail(d, CloseProtocolError, "a Close frame carries an invalid status code")
    return
  let reason = copyRange(payload, 2, payload.len)
  if not validateUtf8(reason):
    wsFail(d, CloseInvalidPayload, "a Close reason is not valid UTF-8")
    return
  d.closeCode = code
  d.closeReason = reason

proc wsFeed*(d: var WsDecoder; data: string) =
  ## Append bytes and decode every complete frame in them. After an error or a Close the decoder
  ## ignores further input.
  if d.err.len > 0 or d.closeSeen: return
  d.buf.add data
  while d.err.len == 0 and not d.closeSeen:
    let avail = d.buf.len - d.pos
    if avail < 2: break
    let b0 = ord(d.buf[d.pos])
    let b1 = ord(d.buf[d.pos + 1])
    let fin = (b0 and 0x80) != 0
    let opcode = b0 and 0x0f
    let masked = (b1 and 0x80) != 0
    let l7 = b1 and 0x7f
    if (b0 and 0x70) != 0:
      wsFail(d, CloseProtocolError, "a frame used reserved bits and no extension is negotiated")
      break
    if not (opcode == 0 or opcode == 1 or opcode == 2 or opcode == 8 or opcode == 9 or opcode == 10):
      wsFail(d, CloseProtocolError, "a frame has an unknown opcode")
      break
    if masked != d.expectMasked:
      wsFail(d, CloseProtocolError, "a frame is masked (or not) against the rules for its sender")
      break
    let control = opcode >= 8
    var hl = 2
    if l7 == 126: hl = hl + 2
    elif l7 == 127: hl = hl + 8
    if masked: hl = hl + 4
    if avail < hl: break
    var plen = l7
    if l7 == 126:
      plen = (ord(d.buf[d.pos + 2]) shl 8) or ord(d.buf[d.pos + 3])
    elif l7 == 127:
      if ord(d.buf[d.pos + 2]) >= 128:
        wsFail(d, CloseProtocolError, "a 64-bit frame length has its top bit set")
        break
      var huge = false
      plen = 0
      var k = 0
      while k < 8:
        let bv = ord(d.buf[d.pos + 2 + k])
        if k < 4:
          if bv != 0: huge = true
        else:
          plen = (plen shl 8) or bv
        inc k
      if huge:
        wsFail(d, CloseMessageTooBig, "a frame is larger than 4 GiB")
        break
    if control:
      if not fin:
        wsFail(d, CloseProtocolError, "a control frame is fragmented")
        break
      if plen > 125:
        wsFail(d, CloseProtocolError, "a control frame is longer than 125 bytes")
        break
    elif d.maxMessage > 0 and d.partial.len + plen > d.maxMessage:
      wsFail(d, CloseMessageTooBig, "message over the " & $d.maxMessage & " byte limit")
      break
    if avail < hl + plen: break
    var payload = ""
    let start = d.pos + hl
    var i = 0
    if masked:
      let keyAt = d.pos + hl - 4
      while i < plen:
        payload.add char(ord(d.buf[start + i]) xor ord(d.buf[keyAt + (i and 3)]))
        inc i
    else:
      while i < plen:
        payload.add d.buf[start + i]
        inc i
    d.pos = d.pos + hl + plen
    if opcode == 8:
      handleClose(d, payload)
    elif opcode == 9:
      d.pings.add payload
    elif opcode == 10:
      inc d.pongs
    elif opcode == 0:
      if d.partialKind == 0:
        wsFail(d, CloseProtocolError, "a continuation frame has no message to continue")
      else:
        d.partial.add payload
        if fin:
          let whole = d.partial
          let kind = d.partialKind
          d.partial = ""
          d.partialKind = 0
          deliver(d, kind, whole)
    else:
      if d.partialKind != 0:
        wsFail(d, CloseProtocolError, "a new message started before the previous one ended")
      elif fin:
        deliver(d, opcode, payload)
      else:
        d.partialKind = opcode
        d.partial = payload
  if d.pos > 0 and (d.pos >= d.buf.len or d.pos > 65536):
    d.buf = copyRange(d.buf, d.pos, d.buf.len)
    d.pos = 0

proc wsPending*(d: WsDecoder): int =
  ## Complete messages waiting to be popped.
  d.msgs.len - d.qhead

proc wsNextKind*(d: WsDecoder): int =
  ## 0 none waiting, 1 text, 2 binary.
  if d.qhead >= d.msgs.len: return 0
  d.kinds[d.qhead]

proc wsPop*(d: var WsDecoder): string =
  ## The oldest complete message ("" when none; check wsPending first).
  if d.qhead >= d.msgs.len: return ""
  let m = d.msgs[d.qhead]
  inc d.qhead
  if d.qhead >= d.msgs.len:
    d.msgs = @[]
    d.kinds = @[]
    d.qhead = 0
  return m

proc wsClearPings*(d: var WsDecoder) =
  d.pings = @[]
