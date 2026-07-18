## ws/rng.nim — cryptographically strong random bytes for RFC 6455 frame masking.
##
## RFC 6455 §5.3 requires the 4-byte client masking key to be derived from a
## strong source of entropy so a hostile server cannot predict it. We use the
## OS CSPRNG directly: `getrandom(2)` on Linux (the libc symbol), falling back to
## reading `/dev/urandom` if the syscall is unavailable. No `std/random` (that is
## a deterministic PRNG, unfit for masking keys).

# getrandom(2): ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
proc cGetrandom(buf: pointer; buflen: csize_t; flags: cuint): clong {.cdecl,
  importc: "getrandom", header: "<sys/random.h>".}

# POSIX file primitives for the /dev/urandom fallback.
proc cOpen(path: cstring; flags: cint): cint {.cdecl,
  importc: "open", header: "<fcntl.h>".}
proc cRead(fd: cint; buf: pointer; n: csize_t): clong {.cdecl,
  importc: "read", header: "<unistd.h>".}
proc cClose(fd: cint): cint {.cdecl,
  importc: "close", header: "<unistd.h>".}

const O_RDONLY = cint(0)

proc offsetPtr(p: pointer; off: int): pointer =
  cast[pointer](cast[uint](p) + uint(off))

proc fillFromUrandom(buf: pointer; n: int): bool =
  let fd = cOpen(cstring"/dev/urandom", O_RDONLY)
  if fd < cint(0): return false
  var got = 0
  var ok = true
  while got < n:
    let r = cRead(fd, offsetPtr(buf, got), csize_t(n - got))
    if r <= clong(0):
      ok = false
      break
    got = got + int(r)
  discard cClose(fd)
  ok and got >= n

proc fillRandom*(buf: pointer; n: int): bool =
  ## Fill `n` bytes at `buf` with OS entropy. True on success. Tries
  ## `getrandom(2)` first, then `/dev/urandom`.
  if n <= 0: return true
  var got = 0
  while got < n:
    let r = cGetrandom(offsetPtr(buf, got), csize_t(n - got), cuint(0))
    if r <= clong(0):
      break
    got = got + int(r)
  if got >= n: return true
  fillFromUrandom(offsetPtr(buf, got), n - got)

proc randomMask*(): array[4, uint8] =
  ## A fresh 4-byte masking key from the OS CSPRNG (RFC 6455 §5.3).
  result = default(array[4, uint8])
  discard fillRandom(addr result[0], 4)

proc randomBytes*(n: int): string =
  ## `n` bytes of OS entropy as a `string` (used for `Sec-WebSocket-Key`).
  result = newString(n)
  if n > 0:
    discard fillRandom(cast[pointer](toCString(result)), n)
