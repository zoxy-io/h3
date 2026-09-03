# qifs — QPACK field sections encoded by other implementations

Vendored from [qpackers/qifs](https://github.com/qpackers/qifs), the offline
interop corpus nghttp3 and ls-qpack check against. `LICENSE.md` is theirs.

## What is here

The `qpack-05` **capacity-zero** encodings of the two smallest inputs, from all
four encoders that produced them:

| file | encoder |
|---|---|
| `netbsd.qif`, `netbsd-hq.qif` | the input, `name<TAB>value` per line, blank line between sections |
| `*.ls-qpack.qpack` | ls-qpack |
| `*.nghttp3.qpack` | nghttp3 |
| `*.qthingey.qpack` | qthingey |
| `*.quinn.qpack` | quinn |

`.qpack` files are the
[offline interop format](https://github.com/quicwg/base-drafts/wiki/QPACK-Offline-Interop):
`[stream id: u64 big-endian][length: u32 big-endian][octets]`, repeated. Stream
0 is the encoder stream and is empty at capacity zero.

## Why only these

Only capacity-zero encodings are usable: this package advertises
`SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` and has no dynamic table, so an encoding
that references one is not something a conforming peer would send it. That is
48 files in the upstream corpus; taking the two smallest inputs across all four
encoders costs 40 KB rather than 5.8 MB.

All four are kept even though `ls-qpack`, `nghttp3` and `qthingey` are
byte-identical here. Three agreeing implementations are not the same evidence
as three implementations, and `quinn` — the one that differs — is the one most
likely to exercise a representation this package never emits.

## Refreshing

    git clone --depth 1 https://github.com/qpackers/qifs
    cp qifs/qifs/netbsd{,-hq}.qif corpus/qifs/
    for e in ls-qpack nghttp3 qthingey quinn; do
      for s in netbsd netbsd-hq; do
        cp qifs/encoded/qpack-05/$e/$s.out.0.0.0 corpus/qifs/$s.$e.qpack
      done
    done

The `.0.0.0` suffix is `capacity.blocked-streams.acknowledged`. The `.0.0.1`
variants are byte-identical at capacity zero — with no dynamic table there is
nothing an acknowledgement can change — so only one is vendored.

See `corpus/qifs.zig` for what this evidence does and does not establish.
