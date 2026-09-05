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

**Both roles.** `ROLE=client` is the runner's client; `ROLE=server` runs
`server.zig` under the runner's server contract — port 443, `/www` for the
files, `/certs` for the key — and issues a Retry when the `retry` case asks for
one. `h3-server` is the same code as a standalone binary, for h3spec; see
"h3spec" below.

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
| *(server)* | `handshake`, `transfer`, `chacha20`, `multiplexing`, `retry`, `http3`, `amplificationlimit`, the loss and corruption cases, `multiconnect`, `longrtt`, `blackhole`, `ipv6`, `goodput`, `crosstraffic` |
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

## The server, by hand

The runner drives the server through its own compose file; pointing a
third-party *client* at it needs two workarounds and is worth the trouble,
because it is the only way to find out what a real client thinks of the
handshake this package produces.

```sh
ROLE=server TESTCASE=transfer CERT=/tmp/qi/certs/cert.pem \
  KEY=/tmp/qi/certs/priv.key WWW=/tmp/qi/www PORT=4453 \
  ./zig-out/bin/h3-interop &

# The client images wait for the network simulator before they start, so
# something has to be listening on 57832; and they resolve `server4`.
python3 -c "import socket;s=socket.socket();s.bind(('0.0.0.0',57832));s.listen(64)
while True: s.accept()[0].close()" &

docker run --rm --network host --add-host sim:127.0.0.1 --add-host server4:127.0.0.1 \
  -v /tmp/qi/certs:/certs:ro -v /tmp/qi/cdown:/downloads -v /tmp/qi/logs:/logs \
  -e ROLE=client -e TESTCASE=transfer \
  -e REQUESTS="https://server4:4453/file.bin" \
  martenseemann/quic-go-interop:latest
```

Set `TESTCASE=retry` on the *server* for the Retry path. ngtcp2's client image
does not run this way — its endpoint script derives an address from routes it
cannot set outside the simulator — so the third-party client evidence here is
quic-go's and aioquic's.

A client that fails with `expected initial_source_connection_id to equal X, is
Y` is telling you the server answered two datagrams of one flight as two
connections. It is worth knowing that message on sight: it is what a
multi-datagram ClientHello does to a server that keys its table only on the
identifier it chose.

## The real runner, inside the network simulator

The runner drives both endpoints through ns-3 — `simple-p2p --delay=15ms
--bandwidth=10Mbps --queue=25` by default — which is a path no loopback
resembles. Getting this far found two defects on its own; see
docs/VERIFICATION.md section 5.5.

**1. A statically linked endpoint binary**, so it runs in the runner's image:

```sh
zig build interop -Dtarget=x86_64-linux-musl -Doptimize=ReleaseFast
```

**2. The endpoint image.** `setup.sh` and `wait-for-it.sh` come from the base
image; the entry point is `/run_endpoint.sh`, which the runner's contract
names.

```sh
mkdir -p /tmp/qi/endpoint && cd /tmp/qi/endpoint
cp ~/zoxy-io/h3/zig-out/bin/h3-interop .

printf '%s\n' '#!/bin/bash' 'set -e' '/setup.sh' \
  'if [ "$ROLE" == "client" ]; then /wait-for-it.sh sim:57832 -s -t 30; fi' \
  'exec /usr/local/bin/h3-interop' > run_endpoint.sh
chmod +x run_endpoint.sh

printf '%s\n' 'FROM martenseemann/quic-network-simulator-endpoint:latest' \
  'COPY h3-interop /usr/local/bin/h3-interop' \
  'COPY run_endpoint.sh /run_endpoint.sh' \
  'RUN chmod +x /usr/local/bin/h3-interop /run_endpoint.sh' \
  'ENTRYPOINT [ "/run_endpoint.sh" ]' > Dockerfile

docker build -t h3-interop:local .
```

**3. The runner**, its Python environment, and the two host tools it shells out
to — `openssl` makes the certificates and `tshark` reads the pcaps:

```sh
cd /tmp/qi
git clone --depth 1 https://github.com/quic-interop/quic-interop-runner runner
cd runner
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt

# Add this implementation to the list the runner chooses from.
./.venv/bin/python -c "import json; \
  d = json.load(open('implementations_quic.json')); \
  d['h3'] = {'image': 'h3-interop:local', 'url': 'https://github.com/zoxy-io/h3', 'role': 'both'}; \
  json.dump(d, open('implementations_quic.json','w'), indent=2)"

nix-shell -p openssl wireshark-cli --run \
  './.venv/bin/python run.py -s h3 -c quic-go -t handshake,transfer'
```

As of the last run: **as a client, seven of eight** — `handshake`, `transfer`,
`chacha20`, `retry`, `http3`, `transferloss`, `keyupdate` — with
`handshakeloss` short of the runner's budget. **As a server, five of eight**,
with multi-stream transfers of several megabytes still stalling. See
docs/VERIFICATION.md §5.5.

```sh
```

### Before believing a failure, run the control

```sh
./.venv/bin/python run.py -s quic-go -c quic-go -t handshake
```

If that fails too, the simulator is not passing packets on this host and no
result about this package means anything.

That is what happened here, twice over.

**The bridge filter.** ns-3 re-emits frames with raw sockets, and on a host
with `bridge-nf-call-iptables=1` those bridged frames traverse iptables and
meet docker's `DOCKER` chain, which ends in `DROP`. A narrow `DOCKER-USER`
accept for `193.167.0.0/16` *is hit* — the counters move — and is not
sufficient. What works is the host-wide setting the simulator's own
documentation names:

```sh
sudo sysctl -w net.bridge.bridge-nf-call-iptables=0
sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=0
# and to put it back:
sudo sysctl -w net.bridge.bridge-nf-call-iptables=1
sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1
```

It changes how *all* bridged traffic on the machine is filtered, so it is a
decision rather than a step.

**The Python.** pyshark still calls `asyncio.set_child_watcher`, removed in
3.14, so the venv needs an older interpreter — `nix-shell -p python312` and
`python3 -m venv` from that. The symptom is a traceback out of `trace.py`
*after* a test has already run, which reads like a failed test and is not one.

The control is the only thing that separates "the runner does not pass" from
"the runner does not run", and it is one command.

### The matrix

As a **client** against quic-go's server: `handshake`, `transfer`, `chacha20`,
`retry`, `http3`, `transferloss`, `keyupdate` and `multiplexing`. As a
**server** against quic-go's client: the same list without `keyupdate`, which
a server does not initiate here.

Run the matrix twice before believing it. `http3` in particular depends on
where a DATA frame's last octet falls relative to the FIN, and a defect there
failed one run and passed the next.

`handshakeloss` fails in both roles: fifty handshakes through 30% loss in three
hundred seconds, of which about thirty-eight finish. The median is half a
second and the tail is RFC 9002's PTO backoff at 1, 2, 4, 8, 16 seconds — a
recovery slower than quic-go's rather than a rule broken.

## h3spec

[h3spec](https://github.com/kazu-yamamoto/h3spec) is a conformance tester for
HTTP/3 **servers**: it connects as a client and checks what the server does
with input a client should never send. `h3-server` passes **49 of 49**.

```sh
# The binary, and the same certificates as above.
zig build interop            # zig-out/bin/h3-server
CERT=/tmp/qi/certs/cert.pem KEY=/tmp/qi/certs/priv.key PORT=4443 \
  ./zig-out/bin/h3-server &

# h3spec ships a dynamically linked release binary, which NixOS will not run
# directly; a two-line Debian image is the shortest way round it.
curl -sLO https://github.com/kazu-yamamoto/h3spec/releases/download/v0.1.13/h3spec-linux-x86_64
printf 'FROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y --no-install-recommends libgmp10 libnuma1\nCOPY h3spec-linux-x86_64 /usr/local/bin/h3spec\nRUN chmod +x /usr/local/bin/h3spec\nENTRYPOINT ["/usr/local/bin/h3spec"]\n' > Dockerfile
docker build -q -t h3spec:local .
docker run --rm --network host h3spec:local -n 127.0.0.1 4443
```

`-n` skips chain validation, which the throwaway CA needs; it does **not** skip
the CertificateVerify signature, so a server whose transcript is wrong fails
every case with "cannot verify CertificateVerify" and no further explanation.

`-m "<substring>"` runs one case and `-d` adds a trace, which is the only way
to tell "the server did not detect this" from "the server answered nothing
because something earlier went wrong". Both mistakes look identical in the
summary, and the second one accounted for eleven of the failures in the first
full run.

## The server, by hand

The runner drives the server through its own compose file; pointing a
third-party *client* at it needs two workarounds and is worth the trouble,
because it is the only way to find out what a real client thinks of the
handshake this package produces.

```sh
ROLE=server TESTCASE=transfer CERT=/tmp/qi/certs/cert.pem \
  KEY=/tmp/qi/certs/priv.key WWW=/tmp/qi/www PORT=4453 \
  ./zig-out/bin/h3-interop &

# The client images wait for the network simulator before they start, so
# something has to be listening on 57832; and they resolve `server4`.
python3 -c "import socket;s=socket.socket();s.bind(('0.0.0.0',57832));s.listen(64)
while True: s.accept()[0].close()" &

docker run --rm --network host --add-host sim:127.0.0.1 --add-host server4:127.0.0.1 \
  -v /tmp/qi/certs:/certs:ro -v /tmp/qi/cdown:/downloads -v /tmp/qi/logs:/logs \
  -e ROLE=client -e TESTCASE=transfer \
  -e REQUESTS="https://server4:4453/file.bin" \
  martenseemann/quic-go-interop:latest
```

Set `TESTCASE=retry` on the *server* for the Retry path. ngtcp2's client image
does not run this way — its endpoint script derives an address from routes it
cannot set outside the simulator — so the third-party client evidence here is
quic-go's and aioquic's.

A client that fails with `expected initial_source_connection_id to equal X, is
Y` is telling you the server answered two datagrams of one flight as two
connections. It is worth knowing that message on sight: it is what a
multi-datagram ClientHello does to a server that keys its table only on the
identifier it chose.

## h3spec

[h3spec](https://github.com/kazu-yamamoto/h3spec) is a conformance tester for
HTTP/3 **servers**: it connects as a client and checks what the server does
with input a client should never send. `h3-server` passes **49 of 49**.

```sh
zig build interop            # zig-out/bin/h3-server, beside h3-interop
CERT=/tmp/qi/certs/cert.pem KEY=/tmp/qi/certs/priv.key PORT=4443 \
  ./zig-out/bin/h3-server &

# h3spec ships a dynamically linked release binary, which NixOS will not run
# directly; a four-line Debian image is the shortest way round it.
cd /tmp/qi
curl -sLO https://github.com/kazu-yamamoto/h3spec/releases/download/v0.1.13/h3spec-linux-x86_64
printf 'FROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y --no-install-recommends libgmp10 libnuma1\nCOPY h3spec-linux-x86_64 /usr/local/bin/h3spec\nRUN chmod +x /usr/local/bin/h3spec\nENTRYPOINT ["/usr/local/bin/h3spec"]\n' > Dockerfile
docker build -q -t h3spec:local .
docker run --rm --network host h3spec:local -n 127.0.0.1 4443
```

`-n` skips *chain* validation, which the throwaway CA needs. It does **not**
skip the CertificateVerify signature, so a server whose transcript is wrong
fails every case with "cannot verify CertificateVerify" and no further
explanation — which is what the first run of this server did.

`-m "<substring>"` runs one case and `-d` adds a trace. That combination is the
only way to tell "the server did not detect this" from "the server answered
nothing because something earlier went wrong": both read as
`did not get expected exception` in the summary, and the second accounted for
eleven of the failures in the first full run. If a case fails in the suite and
passes alone, the server is running out of something — connection slots, most
likely.

## Environment

| variable | meaning |
| --- | --- |
| `ROLE` | `client`; anything else exits 127 |
| `TESTCASE` | see the table above; unknown exits 127 |
| `REQUESTS` | space-separated `https://host:port/path` URLs |
| `DOWNLOADS` | where bodies are written, `/downloads` by default |
| `SSLKEYLOGFILE` | NSS key log, written if set |
| `VERBOSE` | narrate the loop on stderr if set |

And `h3-server`'s, which are its whole configuration:

| variable | meaning |
| --- | --- |
| `CERT` | PEM certificate, leaf first; `/certs/cert.pem` by default |
| `KEY` | PEM P-256 private key, SEC1 or PKCS#8; `/certs/priv.key` by default |
| `PORT` | UDP port; 4433 by default |
| `VERBOSE` | narrate on stderr if set |

And `h3-server`'s own, which are its whole configuration:

| variable | meaning |
| --- | --- |
| `CERT` | PEM certificate, leaf first; `/certs/cert.pem` by default |
| `KEY` | PEM P-256 private key, SEC1 or PKCS#8; `/certs/priv.key` by default |
| `PORT` | UDP port; 4433 by default |
| `VERBOSE` | narrate on stderr if set |

`QLOGDIR` is accepted by the runner and ignored here: a qlog writer wants the
event trace `Connection.poll` now produces, and writing one is
docs/VERIFICATION.md §5.3's remaining half.
