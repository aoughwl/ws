## tws_protocol.nim — the conformance predicates behind Autobahn cases 6.x
## (UTF-8) and 7.x (close codes). Exercises ws/protocol directly.

import std/syncio
import ws/protocol

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc s(bytes: openArray[int]): string =
  result = ""
  for b in bytes:
    result.add char(b)

proc main =
  # --- valid UTF-8 (Autobahn 6.x "good" cases) --------------------------------
  check(validateUtf8(""), "empty is valid")
  check(validateUtf8("Hello-\xc2\xb5@\xc3\x9f\xc3\xb6\xc3\xa4\xc3\xbc\xc3\xa0\xc3\xa1-UTF-8!!"),
        "valid mixed 1/2-byte")
  check(validateUtf8(s([0xce,0xba,0xe1,0xbd,0xb9,0xcf,0x83,0xce,0xbc,0xce,0xb5])),
        "valid greek")
  check(validateUtf8(s([0xf0,0x90,0x80,0x80])), "valid 4-byte U+10000")
  check(validateUtf8(s([0xf4,0x8f,0xbf,0xbf])), "valid U+10FFFF (max)")
  check(validateUtf8(s([0xed,0x9f,0xbf])), "U+D7FF (just below surrogates)")
  check(validateUtf8(s([0xee,0x80,0x80])), "U+E000 (just above surrogates)")

  # --- invalid UTF-8 (must be rejected -> close 1007) -------------------------
  check(not validateUtf8(s([0xc0])), "lone lead byte")
  check(not validateUtf8(s([0x80])), "unexpected continuation")
  check(not validateUtf8(s([0xc3,0x28])), "bad continuation (2-byte)")
  check(not validateUtf8(s([0xe2,0x82,0x28])), "bad continuation (3-byte)")
  check(not validateUtf8(s([0xf0,0x28,0x8c,0x28])), "bad continuation (4-byte)")
  check(not validateUtf8(s([0xc0,0xaf])), "overlong '/' (2-byte)")
  check(not validateUtf8(s([0xe0,0x80,0xaf])), "overlong (3-byte)")
  check(not validateUtf8(s([0xf0,0x80,0x80,0xaf])), "overlong (4-byte)")
  check(not validateUtf8(s([0xed,0xa0,0x80])), "surrogate U+D800")
  check(not validateUtf8(s([0xed,0xbf,0xbf])), "surrogate U+DFFF")
  check(not validateUtf8(s([0xf4,0x90,0x80,0x80])), "> U+10FFFF")
  check(not validateUtf8(s([0xfe])), "0xfe never valid")
  check(not validateUtf8(s([0xff])), "0xff never valid")
  check(not validateUtf8(s([0x48,0x65,0xc3])), "truncated tail (Autobahn 6.3.x)")

  # --- incremental validation across fragment boundaries (Autobahn 6.4.x) -----
  # A single é (0xc3 0xa9) split byte-by-byte must validate as a continuous DFA.
  block:
    var state = Utf8Accept
    state = utf8Step(state, 0xc3'u8)
    check(state != Utf8Reject and state != Utf8Accept, "mid-sequence after lead")
    state = utf8Step(state, 0xa9'u8)
    check(state == Utf8Accept, "sequence completes across the split")
  block:
    # An invalid split must be caught at the offending byte.
    var state = Utf8Accept
    state = utf8Step(state, 0xc3'u8)
    state = utf8Step(state, 0x28'u8)
    check(state == Utf8Reject, "bad continuation rejected mid-stream")

  # --- close-code validity (Autobahn 7.x) -------------------------------------
  for c in [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 3999, 4000, 4999]:
    check(isValidCloseCode(c), "valid close code " & $c)
  for c in [0, 999, 1004, 1005, 1006, 1012, 1013, 1014, 1015, 1016, 2000, 2999, 5000, 65535]:
    check(not isValidCloseCode(c), "invalid close code " & $c)

  echo "tws_protocol: all checks passed"

main()
