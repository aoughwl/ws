## ws/protocol.nim — RFC 6455 protocol-conformance helpers, transport-free.
##
## Pure predicates the framing layer needs to be Autobahn-conformant: an
## *incremental* UTF-8 validator (so a text message split across fragments can be
## validated as bytes arrive, and rejected mid-stream — Autobahn 6.x) and the
## close-code validity rule (RFC 6455 §7.4.1 + IANA registry — Autobahn 7.x).
##
## No sockets, no allocation on the hot path: both are reusable by the blocking
## `ws.nim` reader and the async `serve/reactorws.nim` coroutine alike.

when defined(nimony):
  {.feature: "lenientnils".}

# ---------------------------------------------------------------------------
# Incremental UTF-8 validation — Björn Höhrmann's branchless DFA.
#   http://bjoern.hoehrmann.de/utf-8/decoder/dfa/
# `state` is carried between calls, so a codepoint straddling a fragment
# boundary is validated correctly. state 0 = ACCEPT (a clean boundary),
# state 12 = REJECT (malformed — overlong, surrogate, out-of-range, or a
# broken continuation). Any other value = mid-sequence (more bytes needed).
# ---------------------------------------------------------------------------

const Utf8Accept* = 0'u32
const Utf8Reject* = 12'u32

const utf8d: array[364, uint8] = [
  # byte-class table, 256 entries (0x00..0xff):
  0'u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  # 00-1f
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,      # 20-3f
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,      # 40-5f
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,      # 60-7f
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,      # 80-9f
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,      # a0-bf
  8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,      # c0-df
  10,3,3,3,3,3,3,3,3,3,3,3,3,4,3,3, 11,6,6,6,5,8,8,8,8,8,8,8,8,8,8,8,    # e0-ff
  # transition table, 108 entries — (state + class) -> state, states are ×12:
  0,12,24,36,60,96,84,12,12,12,48,72,   # state 0  (ACCEPT)
  12,12,12,12,12,12,12,12,12,12,12,12,  # state 12 (REJECT, absorbing)
  12,0,12,12,12,12,12,0,12,0,12,12,     # state 24
  12,24,12,12,12,12,12,24,12,24,12,12,  # state 36
  12,12,12,12,12,12,12,24,12,12,12,12,  # state 48
  12,24,12,12,12,12,12,12,12,24,12,12,  # state 60
  12,12,12,12,12,12,12,36,12,36,12,12,  # state 72
  12,36,12,12,12,12,12,36,12,36,12,12,  # state 84
  12,36,12,12,12,12,12,12,12,12,12,12]  # state 96

proc utf8Step*(state: uint32; b: uint8): uint32 =
  ## Advance the DFA by one byte. Returns the new state (Utf8Reject once the
  ## input is invalid; it stays rejected thereafter).
  let cls = utf8d[int(b)]
  utf8d[256 + int(state) + int(cls)]

proc validateUtf8*(s: string): bool =
  ## Whole-string UTF-8 validity (a complete, self-contained message).
  var state = Utf8Accept
  var i = 0
  while i < s.len:
    state = utf8Step(state, uint8(ord(s[i])))
    if state == Utf8Reject:
      return false
    inc i
  state == Utf8Accept

# ---------------------------------------------------------------------------
# Close-code validity (RFC 6455 §7.4.1 + IANA WebSocket Close Code registry).
# ---------------------------------------------------------------------------

proc isValidCloseCode*(code: int): bool =
  ## A code a peer is allowed to send in a Close frame body. 1004/1005/1006 and
  ## 1015 are reserved/never-on-the-wire; 1016..2999 are reserved for the
  ## protocol/registry; 1000..1003, 1007..1011, plus the library (3000..3999)
  ## and application (4000..4999) ranges are valid.
  if code >= 3000 and code <= 4999:
    return true
  if code >= 1000 and code <= 1011:
    # 1004 (reserved), 1005 / 1006 (must not appear on the wire) are invalid.
    return code != 1004 and code != 1005 and code != 1006
  false

# Standard close codes worth naming at call sites.
const
  CloseNormal* = 1000
  CloseGoingAway* = 1001
  CloseProtocolError* = 1002
  CloseUnsupportedData* = 1003
  CloseInvalidPayload* = 1007   # non-UTF-8 in a text/close-reason payload
  ClosePolicyViolation* = 1008
  CloseMessageTooBig* = 1009
  CloseInternalError* = 1011
