# P1 v9 typed byte-schedule receipt

Status: **typed schedule exact; FD23/FD28 remain MISSING; CONFIGURED0**.

This receipt freezes the part of the corrupt-P1 C03 stream that is determined
by the selected financial trace and the current v9 instrumentation. It does not
invent a storage cap, predict MP-SPDZ peer traffic, authorize a launch, or make
a privacy claim.

## Result

For a C03 logical payload of `p` bytes:

```text
W(p) = p + 112 * max(1, ceil(p / 65536))
```

For one typed scalar capture of `n` authenticated values (16-byte site binding,
32-byte share lane, and 32-byte MAC lane):

```text
S(n) = 128 + 64*n + 224*ceil(n / 2048)
```

The exact scalar schedule excluding historic-nullifier comparisons is:

```text
calls              3,996,653
elements         264,503,879
share chunks       4,023,154
logical messages  11,989,959
C03 records       12,042,961
wire bytes    18,341,006,336
```

The complete non-peer subtotal for one round is therefore:

```text
hidden candidate:      19,861,945,316 + 57,408*H
transparent baseline:  19,861,971,156 + 57,408*H
```

where `H` is the exact accepted-head historic-nullifier count. The full round
is:

```text
BaseNoFork(classification,H)
+ 208*F
+ sum(W(peer_event.payload_bytes) for peer_event in T)
```

`F` is the number of unique captured `Player::fork()` registrations. `T` is the
exact ordered peer transcript identified by fork, direction, peer, and payload
length. Neither is guessed here.

The machine-readable receipt has every scalar-site count, element count,
share-chunk count, byte total, and width-vector identity:
[P1-V9-TYPED-SCHEDULE.json](P1-V9-TYPED-SCHEDULE.json). The exact 570-line
site-11 width histogram is retained as
[site11-width-histogram.txt](site11-width-histogram.txt), SHA-256
`1e1777549364731f03e51feb1a13b8cb4666fba6a4fde62293e37776e553a0af`.

## Sites 12–14 repair

The registered path previously required sites 1–22 at stream close but did not
invoke the raw trace-check reduction. The repair calls
`trace_private_checks_hold()` exactly once on the genuine 33,896 authenticated
`ASSERT_ZERO` results, before context residuals and the site-16 validation
fold. The reduction is fixed and value-independent:

- site 12: 100 calls of width 33,896;
- site 13: 253 calls of width 33,896;
- site 14: widths `16948,8474,4237,2118,1059,530,265,132,66,33,17,8,4,2,1,1`.

The result is appended as an equivalent authenticated zero residual; the raw
checks remain in the frozen residual vector. Selected-path omission, duplicate,
wrong-order, and wrong-count mutations are rejected by
[test_registered_trace_private_check_capture.py](../../../../poc/local-private-payment/mpc-prover/financial/controls/test_registered_trace_private_check_capture.py).

Primary source anchors:

- [registered_construction.cpp](../../../../poc/local-private-payment/mpc-prover/financial/registered_construction.cpp)
- [trace_witness.cpp](../../../../poc/local-private-payment/mpc-prover/trace/trace_witness.cpp)
- [p1_scalar_capture_manifest.hpp](../../../../poc/local-private-payment/mpc-prover/p1_scalar_capture_manifest.hpp)
- [p1_capture_stream.cpp](../../../../poc/local-private-payment/mpc-prover/p1_capture_stream.cpp)
- [financial_assignment.cpp](../../../../poc/local-private-payment/mpc-prover/financial/financial_assignment.cpp)
- [financial_prover.cpp](../../../../poc/local-private-payment/mpc-prover/financial/financial_prover.cpp)

The trace is pinned to canonical SHA-256
`4c3dec7c553f66e45775bff2c950417060980cf443ab83a2d198587fc604808e`
and 2,576,450,912 canonical bytes. The upstream MP-SPDZ selection is pinned in
[SOURCE-SELECTION.json](../../../../.local/mpc-prover-softspoken-vendor/SOURCE-SELECTION.json)
to commit `113c4e47dd94bca9ecab029d2f0abe649bea5c52`.

## Why FD23 and FD28 remain missing

There is no selected registered executable or byte-schedule minter. The checked
entry point is CONFIGURED0. In addition, the pre-fork authority does not yet
bind:

1. the accepted-head value of `H`;
2. the exact selected main and immutable `OnlineOptions` state;
3. valid cached versus regenerated `Mascot-Secrets` setup;
4. SoftSpoken/KOS parameters and the resulting fork schedule; or
5. the ordered MP-SPDZ peer event vector `T`.

These branches are visible in the pinned upstream implementations:
[MascotMacKey.hpp](../../../../.local/mpc-prover-softspoken-vendor/MP-SPDZ/OT/MascotMacKey.hpp),
[MascotPrep.hpp](../../../../.local/mpc-prover-softspoken-vendor/MP-SPDZ/Protocols/MascotPrep.hpp),
[OTExtensionWithMatrix.cpp](../../../../.local/mpc-prover-softspoken-vendor/MP-SPDZ/OT/OTExtensionWithMatrix.cpp),
and [Player.cpp](../../../../.local/mpc-prover-softspoken-vendor/MP-SPDZ/Networking/Player.cpp).

An empirical prior-run size or an operational abort threshold cannot close a
protocol byte bound. The existing schedule authority correctly leaves slots 3
and 8 missing in
[privacy_selected_producer_byte_schedule_authority.cpp](../../../../poc/local-private-payment/private_batch_trial/privacy_selected_producer_byte_schedule_authority.cpp).

## Minimum future authority

A future source-owned per-round schedule must bind the exact RunBinding and
accepted head, `H`, trace/model/query/scalar-manifest identities, selected main,
owner geometry, per-site ordered-width digests, fixed typed lanes, immutable
MP-SPDZ options and secret-cache policy, and the ordered peer vector with exact
message/chunk/byte totals. It must split once before the role fork: one residual
reserves the archive; the other makes the capture compare the actual v9 sequence
and totals before emitting END.

Until that exists, `p1_round1_schedule`, `p1_round2_schedule`, the complete
schedule minter, archive consumer, and configured status must remain false.

## Recompute

```bash
python3 research/intensive-2026-10-22/evidence/2026-10-29-p1-v9-byte-schedule/verify_p1_v9_schedule.py
python3 -m unittest -v research/intensive-2026-10-22/evidence/2026-10-29-p1-v9-byte-schedule/test_p1_v9_schedule.py
```

The verifier checks source hashes, the compressed and canonical trace hashes,
every finite scalar subtotal, the retained histogram, framing, group/field
lanes, and the symbolic base formulas. Its success string still ends in
`FD23_FD28_MISSING` by design.
