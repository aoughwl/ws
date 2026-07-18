## ws/frame.nim — RFC 6455 frame codec (encode side; decode is streamed in ws.nim).
##
## A frame on the wire is: a FIN+opcode byte, a MASK+7-bit-length byte, an
## optional extended length (2 or 8 bytes, big-endian), an optional 4-byte
## masking key, then the payload (XOR-masked with the key when MASK is set).
## Per RFC 6455 a client MUST mask every frame it sends; a server MUST NOT mask.

type
  Opcode* = enum
    opContinuation = 0x0
    opText = 0x1
    opBinary = 0x2
    opClose = 0x8
    opPing = 0x9
    opPong = 0xA

proc isControl*(op: Opcode): bool =
  ## Control frames (close/ping/pong) — must be <= 125 bytes and not fragmented.
  ord(op) >= 0x8

proc encodeFrame*(op: Opcode; payload: string; fin: bool; masked: bool;
                  maskKey: array[4, uint8]; rsv1 = false): string =
  ## Serialize one frame. When `masked`, the payload is XOR-masked with `maskKey`
  ## and the key is written into the header (client role); otherwise the payload
  ## is written verbatim (server role). `rsv1` sets the RSV1 bit, which
  ## permessage-deflate (RFC 7692) uses on the first frame of a compressed
  ## message.
  result = ""
  var b0 = uint8(ord(op)) and 0x0f'u8
  if fin:
    b0 = b0 or 0x80'u8
  if rsv1:
    b0 = b0 or 0x40'u8
  result.add char(b0)

  let n = payload.len
  var maskBit = 0'u8
  if masked:
    maskBit = 0x80'u8
  if n < 126:
    result.add char(maskBit or uint8(n))
  elif n <= 0xffff:
    result.add char(maskBit or 126'u8)
    result.add char(uint8((n shr 8) and 0xff))
    result.add char(uint8(n and 0xff))
  else:
    result.add char(maskBit or 127'u8)
    var shift = 56
    while shift >= 0:
      result.add char(uint8((n shr shift) and 0xff))
      shift = shift - 8

  if masked:
    var k = 0
    while k < 4:
      result.add char(maskKey[k])
      inc k
    var i = 0
    while i < n:
      result.add char(uint8(ord(payload[i])) xor maskKey[i and 3])
      inc i
  else:
    result.add payload
