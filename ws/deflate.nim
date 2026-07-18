## ws/deflate.nim — RFC 7692 permessage-deflate payload codec, no_context_takeover
## mode. Each message is an independent raw-DEFLATE stream (windowBits -15): the
## z_stream is created and destroyed per call, so no compression context is
## carried between messages. On the wire the sender DEFLATEs with a sync flush and
## strips the trailing empty block `00 00 FF FF`; the receiver appends it back
## before inflating (RFC 7692 §7.2). Uses zlib (`libz.so.1`) via FFI.

const zlib = "libz.so.1"

type
  ZStream = object
    ## C `z_stream` layout on LP64 (size 112) — mirrors compress.nim's binding.
    nextIn: nil pointer      # 0
    availIn: uint32          # 8
    totalIn: uint            # 16
    nextOut: nil pointer     # 24
    availOut: uint32         # 32
    totalOut: uint           # 40
    msg: nil pointer         # 48
    state: nil pointer       # 56
    zalloc: nil pointer      # 64
    zfree: nil pointer       # 72
    opaque: nil pointer      # 80
    dataType: int32          # 88
    adler: uint              # 96
    reserved: uint           # 104

proc deflateInit2Raw(strm: ptr ZStream; level, meth, windowBits, memLevel, strategy: cint;
                   version: cstring; streamSize: cint): cint {.cdecl, importc: "deflateInit2_", dynlib: zlib.}
proc deflate(strm: ptr ZStream; flush: cint): cint {.cdecl, importc: "deflate", dynlib: zlib.}
proc deflateEnd(strm: ptr ZStream): cint {.cdecl, importc: "deflateEnd", dynlib: zlib.}
proc inflateInit2Raw(strm: ptr ZStream; windowBits: cint; version: cstring;
                   streamSize: cint): cint {.cdecl, importc: "inflateInit2_", dynlib: zlib.}
proc inflate(strm: ptr ZStream; flush: cint): cint {.cdecl, importc: "inflate", dynlib: zlib.}
proc inflateEnd(strm: ptr ZStream): cint {.cdecl, importc: "inflateEnd", dynlib: zlib.}
proc zlibVersion(): cstring {.cdecl, importc: "zlibVersion", dynlib: zlib.}

const
  Z_NO_FLUSH = cint(0)
  Z_SYNC_FLUSH = cint(2)
  Z_OK = cint(0)
  Z_STREAM_END = cint(1)
  Z_DEFLATED = cint(8)
  RAW_WINDOW = cint(-15)   # negative windowBits ⇒ raw DEFLATE (no zlib header/trailer)

type
  DeflateResult* = object
    ## `ok = false` on a codec error (e.g. malformed compressed data).
    ok*: bool
    data*: string

proc deflateMessage*(data: string; level = 6; maxSize = 16 * 1024 * 1024): DeflateResult =
  ## Compress one message body for permessage-deflate: raw DEFLATE with a sync
  ## flush, trailing `00 00 FF FF` removed. A fresh stream each call
  ## (no_context_takeover). Empty input encodes to a single `0x00` block.
  result = DeflateResult(ok: false, data: "")
  if data.len == 0:
    # An empty payload is one uncompressed empty DEFLATE block; after stripping
    # the sync-flush tail this is a lone 0x00 byte (RFC 7692 §7.2.3.6).
    result = DeflateResult(ok: true, data: "\x00")
    return result
  var strm = default(ZStream)
  if deflateInit2Raw(addr strm, cint(level), Z_DEFLATED, RAW_WINDOW, cint(8), cint(0),
                   zlibVersion(), cint(sizeof(ZStream))) != Z_OK:
    return result
  var inCopy = data
  strm.nextIn = cast[pointer](toCString(inCopy))
  strm.availIn = uint32(data.len)
  var outBuf = default(array[16384, char])
  var produced = ""
  while true:
    strm.nextOut = addr outBuf[0]
    strm.availOut = uint32(outBuf.len)
    let rc = deflate(addr strm, Z_SYNC_FLUSH)
    if rc < Z_OK:
      discard deflateEnd(addr strm)
      return DeflateResult(ok: false, data: "")
    let n = outBuf.len - int(strm.availOut)
    var i = 0
    while i < n:
      produced.add outBuf[i]
      inc i
    if produced.len > maxSize:
      discard deflateEnd(addr strm)
      return DeflateResult(ok: false, data: "")
    # A sync flush drains all pending output once availOut != 0.
    if strm.availOut != 0'u32:
      break
  discard deflateEnd(addr strm)
  # Strip the 4-byte empty-block tail 00 00 FF FF appended by the sync flush.
  if produced.len >= 4:
    result.data = produced.substr(0, produced.len - 5)
  else:
    result.data = produced
  result.ok = true

proc inflateMessage*(data: string; maxSize = 16 * 1024 * 1024): DeflateResult =
  ## Decompress one permessage-deflate message body: append the `00 00 FF FF`
  ## tail the sender stripped, then raw-inflate. Fresh stream each call. Bounded
  ## by `maxSize` (decompression-bomb guard).
  result = DeflateResult(ok: false, data: "")
  var strm = default(ZStream)
  if inflateInit2Raw(addr strm, RAW_WINDOW, zlibVersion(), cint(sizeof(ZStream))) != Z_OK:
    return result
  var inCopy = data
  inCopy.add '\x00'
  inCopy.add '\x00'
  inCopy.add '\xff'
  inCopy.add '\xff'
  strm.nextIn = cast[pointer](toCString(inCopy))
  strm.availIn = uint32(inCopy.len)
  var outBuf = default(array[16384, char])
  while true:
    strm.nextOut = addr outBuf[0]
    strm.availOut = uint32(outBuf.len)
    let rc = inflate(addr strm, Z_NO_FLUSH)
    let n = outBuf.len - int(strm.availOut)
    if result.data.len + n > maxSize:
      discard inflateEnd(addr strm)
      return DeflateResult(ok: false, data: "")
    var i = 0
    while i < n:
      result.data.add outBuf[i]
      inc i
    if rc == Z_STREAM_END:
      break
    # All input for this (whole-message) payload consumed ⇒ done. A further
    # inflate call with no input would return Z_BUF_ERROR, which is not an error.
    if strm.availIn == 0'u32:
      break
    if rc < Z_OK:
      discard inflateEnd(addr strm)
      return DeflateResult(ok: false, data: "")
  discard inflateEnd(addr strm)
  result.ok = true
