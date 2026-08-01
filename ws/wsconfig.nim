## ws/wsconfig.nim — WebSocket connection policy as a record.
##
## The bounds and the keepalive timers already existed, but each arrived by a
## different route: `maxFrame`/`maxMessage` as public fields set after the
## handshake, the handshake-block cap as a default argument on a private
## reader, keepalive through `setPingInterval`, and compression as a bool
## parameter on four separate constructors. A server that accepts connections
## in a loop had to remember to reapply all of it, one call at a time, to every
## socket — and the handshake cap could not be reached at all, because the
## handshake is read before the `WebSocket` exists.
##
## `WsConfig` is the one value that covers all of it, applied at construction
## so a bound is in force for the very first frame rather than the second.

const
  WsUnset* = -1
    ## Inherit this field. Distinct from 0, which for the size bounds means
    ## "unlimited" and for the timers means "disabled" — both real choices.

  DefaultMaxFrame* = 16 * 1024 * 1024
    ## Largest single frame payload accepted.
  DefaultMaxMessage* = 64 * 1024 * 1024
    ## Largest reassembled message accepted. Fragments are joined into one
    ## string, so a message can pass every per-frame check and still be
    ## unbounded without this.
  DefaultMaxHandshake* = 16 * 1024
    ## Largest handshake header block read before giving up.

type
  TriState* = enum
    ## Same three-state idea as `TriOpt` in `tcp`, spelled locally because `ws`
    ## does not otherwise depend on the transport layer's vocabulary.
    wsUnset, wsOff, wsOn

  WsConfig* = object
    ## What a connection will accept, and what it negotiates. Applied by the
    ## constructors, so every bound is in force before the first frame is read.
    maxFrame*: int              ## 0 = unlimited
    maxMessage*: int            ## 0 = unlimited
    maxHandshake*: int          ## header-block cap during the handshake
    deflate*: TriState          ## offer (client) / accept (server) permessage-deflate
    pingIntervalMs*: int        ## 0 = keepalive off, receive stays fully blocking
    pongTimeoutMs*: int         ## 0 = same as pingIntervalMs

proc defaultWsConfig*(): WsConfig =
  ## The bounds and behaviour every connection has had. Keepalive stays off:
  ## turning it on changes `receive` from fully blocking to timer-driven, which
  ## is a caller's decision, not a default.
  WsConfig(
    maxFrame: DefaultMaxFrame, maxMessage: DefaultMaxMessage,
    maxHandshake: DefaultMaxHandshake, deflate: wsUnset,
    pingIntervalMs: 0, pongTimeoutMs: 0)

proc noWsConfig*(): WsConfig =
  ## The empty override: every field inherits.
  WsConfig(
    maxFrame: WsUnset, maxMessage: WsUnset, maxHandshake: WsUnset,
    deflate: wsUnset, pingIntervalMs: WsUnset, pongTimeoutMs: WsUnset)

proc strictWsConfig*(): WsConfig =
  ## Bounds sized for a public endpoint taking untrusted peers: a megabyte per
  ## frame and per message, and keepalive on, so a peer that stops answering is
  ## noticed rather than occupying a connection indefinitely.
  result = defaultWsConfig()
  result.maxFrame = 1024 * 1024
  result.maxMessage = 1024 * 1024
  result.pingIntervalMs = 30000
  result.pongTimeoutMs = 10000

proc merge*(base: WsConfig; over: WsConfig): WsConfig =
  ## A field set in `over` wins; `WsUnset` / `wsUnset` inherits.
  result = base
  if over.maxFrame != WsUnset: result.maxFrame = over.maxFrame
  if over.maxMessage != WsUnset: result.maxMessage = over.maxMessage
  if over.maxHandshake != WsUnset: result.maxHandshake = over.maxHandshake
  if over.deflate != wsUnset: result.deflate = over.deflate
  if over.pingIntervalMs != WsUnset: result.pingIntervalMs = over.pingIntervalMs
  if over.pongTimeoutMs != WsUnset: result.pongTimeoutMs = over.pongTimeoutMs

proc handshakeCap*(cfg: WsConfig; fallback = DefaultMaxHandshake): int =
  ## The handshake header-block cap to enforce, resolving unset.
  if cfg.maxHandshake == WsUnset: fallback else: cfg.maxHandshake

proc wantsDeflate*(cfg: WsConfig; fallback: bool): bool =
  ## Whether to offer or accept permessage-deflate. `wsUnset` keeps whatever
  ## the calling constructor's own default was, so adding a config parameter
  ## never silently changes an existing call's negotiation.
  if cfg.deflate == wsUnset: fallback else: cfg.deflate == wsOn
