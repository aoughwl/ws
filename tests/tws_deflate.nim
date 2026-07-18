## tws_deflate.nim — RFC 7692 permessage-deflate payload codec round-trip.

import std/syncio
import ws/deflate

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc roundtrip(s: string) =
  let c = deflateMessage(s)
  check(c.ok, "deflate failed len " & $s.len)
  let d = inflateMessage(c.data)
  check(d.ok, "inflate failed len " & $s.len)
  check(d.data == s, "round-trip mismatch len " & $s.len &
        " got len " & $d.data.len)

proc repeat(ch: char; n: int): string =
  result = ""
  var i = 0
  while i < n:
    result.add ch
    inc i

proc main =
  roundtrip("")
  roundtrip("hello")
  roundtrip("The quick brown fox jumps over the lazy dog")
  # Highly-compressible: 5000 identical bytes must shrink a lot.
  let big = repeat('A', 5000)
  let c = deflateMessage(big)
  check(c.ok, "deflate big failed")
  check(c.data.len < 200, "expected strong compression, got " & $c.data.len)
  let d = inflateMessage(c.data)
  check(d.ok and d.data == big, "big round-trip mismatch")
  # Mixed content across sizes.
  var mixed = ""
  var i = 0
  while i < 1000:
    mixed.add char(uint8((i * 37 + 11) and 0xff))
    inc i
  roundtrip(mixed)
  echo "tws_deflate: all checks passed (5000xA -> ", $c.data.len, " bytes)"

main()
