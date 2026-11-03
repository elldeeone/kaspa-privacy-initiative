# Source-level privacy capture producer

Status: **UNQUALIFIED SOURCE ONLY — no executable actual mode**.

`privacy_capture_producer.py` defines the append-only seam required to prove
that the four observer views came from the selected protocol run instead of a
later hand-authored directory. It does not yet qualify any capture.

## Fixed stream contract

The future selected launcher must create ten one-way inherited pipes. File
descriptors 20 through 29 are fixed in round-major order:

1. public projection from the verified financial release;
2. complete terminal construction/native/retry/reorg history;
3. dispatcher connection, upload, release, route and retry metadata;
4. server P1 owner-TLS, peer, local authenticated/MAC/randomness and release
   lanes; and
5. owner C1's Original, invoices and decrypted receipts.

Each stream is `HELLO`, then either one raw projection or `META` plus ordered
semantic `RECORD` frames, then `END` and EOF. The producer derives the closure,
counts, payload-byte totals, per-stream counts and record-chain digest. Roles
cannot supply a closure or public producer receipt.

C1 records alone have the exact shape `{stream,source,value}`. `source` retains
the supervisor-observed invoice/pay/scan stage, stage and event sequences,
exact lifecycle-operation digest, prospective contact, qualification flag and
monotonic receive time. Legacy C1 `{stream,value}` records, worker-supplied
source fields, relabelled stages/contacts and reordered timing are rejected.
Contact qualification is currently always false because no authenticated
invoice peer-endpoint authority has been selected.

The fixed private output layout is:

```text
PRODUCER.json
round-1/{projection.bin,terminal.json,dispatcher.json,corrupt-server.json,colluder-wallet.json}
round-2/{projection.bin,terminal.json,dispatcher.json,corrupt-server.json,colluder-wallet.json}
```

`PRODUCER.json` is written last. The current schema is
`kpb-capture-producer-source-only/v1`; it carries
`UNQUALIFIED_SOURCE_ONLY`, `launch_authorized=false`, and
`actual_receipt_emitted=false`. The actual-capture worker must reject it.

## Exact missing hooks

The source-only hook interfaces now exist in `privacy_capture_hook.*` and
`privacy_capture_private_hook.*`. An actual receipt remains impossible until a
reviewed registered build calls all of them at the real boundaries below and
selects their exact source/build/launch closure:

- `financial_release.cpp` / the registered driver must send the same released
  10,685-byte projection that is retained in the qualified public handoff.
- The registered driver around `construct_registered` and owner intake must
  emit listeners-ready, each connection/upload completion, release order and
  every outbound route/retry. Public phase labels alone are incomplete.
- The selected P1 MPC transport/context must tee every admitted owner-TLS,
  peer, local share, MAC, randomness, proof and public-release lane before the
  lane is discarded. Reading diagnostic files after the run is not allowed.
- The owner-C1 namespace must emit its own Original/invoice/decrypted-receipt
  events directly. The existing post-hoc `privacy_colluder.py` derivation is
  not a source event hook and cannot qualify the producer.
- The selected terminal/native controller must emit construction, direct R0,
  rejection/orphan/reorg, grouping and close events in source order.
- A root-selected launcher must create the pipes, give each write end to only
  its selected role, give all read ends to only the producer, consume the trial
  identity before private intake, and bind the producer source/build plus all
  ten role source/build/launch identities. It must write a separate immutable
  launch receipt last.

Only after those hooks, a full transitive runtime closure, and adversarial
review exist may a reviewed source change enable
`kpb-capture-producer-receipt/v1`. There is no CLI flag or environment variable
that enables it now.

## Controls

Synthetic controls cover complete closure plus missing, duplicate,
out-of-order, truncated and extra frames; swapped roles; reused attempts or
cohorts; early close; self-authored output; source drift; deletion; and default
executable refusal. Synthetic fixtures are never privacy evidence.

The C++ hook controls additionally feed byte-exact projection, dispatcher,
server-P1, colluder-C1 and terminal streams into this producer. They exercise
wrong role/FD, cross-round replay, missing/extra/reordered events, early close,
broken consumers, retained direct leaks and retained retry/rejection/orphan/
reorg/cross-round histories. These prove the source-only framing seam, not that
any production role calls it or that a capture is complete.
