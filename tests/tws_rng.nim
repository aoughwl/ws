## tws_rng.nim — the client masking key must come from a strong source: prove it
## is non-zero and varies across frames (RFC 6455 §5.3). Exercises ws/rng
## directly (the same generator sendFrame uses per client frame).

import std/syncio
import ws/rng

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc isZero(m: array[4, uint8]): bool =
  m[0] == 0'u8 and m[1] == 0'u8 and m[2] == 0'u8 and m[3] == 0'u8

proc same(a, b: array[4, uint8]): bool =
  a[0] == b[0] and a[1] == b[1] and a[2] == b[2] and a[3] == b[3]

proc main =
  const N = 64
  var masks = default(array[N, array[4, uint8]])
  var nonZero = 0
  var i = 0
  while i < N:
    masks[i] = randomMask()
    if not isZero(masks[i]):
      inc nonZero
    inc i

  # Not every 4-byte key is non-zero in principle, but all-zero across a run is
  # astronomically unlikely from a CSPRNG; at least require the vast majority.
  check(nonZero >= N - 1, "masking keys are (nearly) all zero — not random")

  # Keys must vary: count distinctN values. A 32-bit key repeating within 64 draws
  # is a ~5e-7 birthday chance; require overwhelmingly-distinctN output.
  var distinctN = 0
  i = 0
  while i < N:
    var seen = false
    var j = 0
    while j < i:
      if same(masks[i], masks[j]):
        seen = true
        break
      inc j
    if not seen: inc distinctN
    inc i
  check(distinctN >= N - 1, "masking keys do not vary across frames")

  # randomBytes must also yield entropy (used for Sec-WebSocket-Key).
  let a = randomBytes(16)
  let b = randomBytes(16)
  check(a.len == 16 and b.len == 16, "randomBytes wrong length")
  check(a != b, "randomBytes returned identical 16-byte keys")

  echo "tws_rng: all checks passed (", nonZero, "/", N, " non-zero, ",
       distinctN, "/", N, " distinctN)"

main()
