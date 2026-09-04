# interop

The [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner)
client, and the only thing in this repository that talks to an implementation
somebody else wrote.

Everything else here is fed by this package. The unit tests, the fuzz targets
and `sim/` all encode one reading of seven RFCs, and a misreading shared between
the encoder and the decoder passes all three — docs/VERIFICATION.md §1 calls
that "the `AckRanges` tests asserted the bug". `corpus/qifs.zig` was the cheap
half of the answer and reaches only QPACK's representation choices. This is the
other half.

It found four defects on the first connection it completed, three more on the
first HTTP/3 one, and paid for itself twice over by closing `retry` and
`http3` — nine RFC 9000 §17.2.5 rules and §7.3's connection-ID authentication,
then the whole of RFC 9114's connection layer. All of it is summarised in
docs/VERIFICATION.md §5.5.

Set `TESTCASE=retry` on a server container and every case in the table below
runs the Retry path as well, which is the cheapest way to exercise it.

## What it is not

**Not part of the library.** `build.zig.zon`'s `paths` lists `src` and nothing
here, and `zig build lint` does not reach this directory. Everything `src/`
forbids is in it, because the runner's contract requires it: a UDP socket, a
clock, an allocator, an entropy draw and a TLS handshake, all in one binary, all
on the far side of the seam docs/DESIGN.md §3 draws.

**Not a TLS library.** `tls.zig` does not verify certificates. The runner issues
its own throwaway CA per run and configures every client in it to trust
anything; that is the test bed's contract, not a shortcut taken here. Pointing
this binary at a real server would be pointing an unauthenticated client at it.

**Client-only.** The server side needs a certificate, a Retry token and address
validation this package does not issue, so `ROLE=server` exits 127.

## What it covers

Over `hq-interop` — HTTP/0.9, which is `GET /path\r\n` on a bidirectional
stream and the response until the FIN:

| test case | what it exercises |
| --- | --- |
| `handshake` | the handshake, and nothing else |
| `transfer` | several streams, flow control, a megabyte of data |
| `chacha20` | ChaCha20-Poly1305 packet protection, offered alone |
| `keyupdate` | RFC 9001 §6's key update, initiated by this client |
| `multiconnect` | one connection per request, sequentially |
| `retry` | the server's Retry: a new identifier, new Initial keys, a token |
| `http3` | HTTP/3 proper: the control stream, SETTINGS, HEADERS and DATA |
| `handshakeloss`, `transferloss` | the same, through the runner's lossy path |

Everything except `http3` runs over `hq-interop`, which is HTTP/0.9 and
exercises the transport without the framing on top of it. `http3` is the one
case that offers `h3` as an ALPN, and it does so honestly: `src/Http3.zig` is
the connection layer.

A test case this binary has never heard of — `zerortt`, `resumption`,
`amplificationlimit` — is exit 127, which is the runner's "unsupported".
Reporting 1 for an unimplemented feature is how an implementation ends up with
a red square meaning "not attempted" and a red square meaning "wrong" in the
same colour.

## Running it against a real server

The runner drives its endpoints inside a network simulator that needs
`NET_ADMIN` and two docker networks. None of that is required to point this
client at an interop *server* image, and the server images run standalone. This
is the loop the four defects were found in.

```sh
zig build interop            # zig-out/bin/h3-interop

# The runner's certificates. Any self-signed pair works — nothing here checks
# them — but this is the script the runner itself uses.
mkdir -p /tmp/qi && cd /tmp/qi
curl -sO https://raw.githubusercontent.com/quic-interop/quic-interop-runner/master/certs.sh
curl -sO https://raw.githubusercontent.com/quic-interop/quic-interop-runner/master/cert_config.txt
docker run --rm -v "$PWD":/work -w /work alpine sh -c \
  'apk add --no-cache openssl bash >/dev/null && bash certs.sh certs 1'
docker run --rm -v "$PWD":/work alpine chmod 644 /work/certs/priv.key

# Something to fetch.
mkdir -p www downloads logs
head -c 1048576 /dev/urandom > www/file.bin

# A server. Any image from the runner's implementations_quic.json will do;
# these three are the ones the fixes were verified against.
docker run -d --name quic-go -p 4433:443/udp \
  -v "$PWD/certs":/certs:ro -v "$PWD/www":/www:ro -v "$PWD/logs":/logs \
  -e ROLE=server -e TESTCASE=transfer -e SSLKEYLOGFILE=/logs/keys.log \
  -e QLOGDIR=/logs/qlog/ \
  martenseemann/quic-go-interop:latest
# ghcr.io/ngtcp2/ngtcp2-interop:latest   on 4434
# aiortc/aioquic-qns:latest              on 4435

ROLE=client TESTCASE=transfer \
  REQUESTS="https://127.0.0.1:4433/file.bin" \
  DOWNLOADS="$PWD/downloads" SSLKEYLOGFILE="$PWD/logs/client-keys.log" \
  VERBOSE=1 \
  ~/zoxy-io/h3/zig-out/bin/h3-interop

cmp www/file.bin downloads/file.bin && echo ok
```

The container will complain that it cannot set up routes — that is the
simulator's scaffolding, and the server starts anyway.

### The two things worth knowing while debugging

**`SSLKEYLOGFILE` on both sides is the oracle.** The server images write one
too, at whatever path their `SSLKEYLOGFILE` names. Diffing them answers the
question a stalled handshake otherwise cannot: *is our key schedule wrong, or is
our transport wrong?* When `interop/` was first pointed at quic-go, the two
files agreed octet for octet on `SERVER_HANDSHAKE_TRAFFIC_SECRET` while the
connection went nowhere, which located the defect in `Connection` rather than in
`tls.zig` in one step.

**`VERBOSE=1` narrates the loop**, flushed per line. Buffered would be worse
than silent: the interesting runs are the ones killed by a timeout, and a buffer
that never flushed loses exactly the lines that say where it stopped. A peer's
CONNECTION_CLOSE is reported with its code whether or not the run is verbose,
because "the peer closed" without the code throws away the only thing that says
why.

### And one thing that is not our bug

**Set `QLOGDIR` on the server containers even if you never read a qlog.**
ngtcp2's `run_endpoint.sh` interpolates it unquoted, so an unset `QLOGDIR`
produces `--qlog-dir --cc bbr` — the flag swallows the next argument and the
server comes up misconfigured and answers nothing. It costs an hour to find
from the client side, where it is indistinguishable from a handshake the client
got wrong.

## Environment

| variable | meaning |
| --- | --- |
| `ROLE` | `client`; anything else exits 127 |
| `TESTCASE` | see the table above; unknown exits 127 |
| `REQUESTS` | space-separated `https://host:port/path` URLs |
| `DOWNLOADS` | where bodies are written, `/downloads` by default |
| `SSLKEYLOGFILE` | NSS key log, written if set |
| `VERBOSE` | narrate the loop on stderr if set |

`QLOGDIR` is accepted by the runner and ignored here: a qlog writer wants the
event trace `Connection.poll` now produces, and writing one is
docs/VERIFICATION.md §5.3's remaining half.
