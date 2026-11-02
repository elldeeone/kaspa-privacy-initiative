# Depth-four full-drainage TN10 mode

**Checkpoint update, 2026-11-02:** the completed live run's finite public
evidence is now retained in the
[research archive](../../research/full-drainage-executed-lifecycle-2026-11-01/run/tn10-attempt-06-public/README.md).
Use the [corrected privacy assessment](../../research/full-drainage-executed-lifecycle-2026-11-01/CORRECTION.md),
not the archived original stronger-observer claim. This checkpoint does not
authorize another trial or resume MPC work.

This is an isolated feature of the existing trusted TN10 builder. The default
six-stage historical mode remains unchanged.

## Build and local qualification

```bash
CARGO_TARGET_DIR=.local/ci-target cargo +1.91.0 test --locked --release \
  --manifest-path poc/recovery-tn10/Cargo.toml \
  --no-default-features --features tn10-full-drainage-depth-4

KPI_FULL_DRAINAGE_RECEIPTS=research/full-drainage-executed-lifecycle-2026-11-01/tn10-depth4-preparation/receipts/local-p19 \
  CARGO_TARGET_DIR=.local/ci-target cargo +1.91.0 test --locked --release \
  --manifest-path poc/recovery-tn10/Cargo.toml \
  --no-default-features --features tn10-full-drainage-depth-4 \
  -- --ignored --nocapture
```

The fast tests cover one-command fresh identity creation, 0600 sponsor-secret
storage, both fixed 100,000,000-sompi deposit layouts, all seven accounting
checkpoints and the po2-19 resource binding. The ignored test uses all seven
genuine local receipts to build and execute the five permission-issuance/payout
layouts. It does not call RPC or broadcast.

## Frozen profile

- domain: `KPI/TN10/native-KAS/full-drainage-depth4-v1`;
- principal: two 100,000,000-sompi deposits;
- private schedule: H2 from the frozen selection;
- exits: 60M, 80M, 30M, 20M and 10M sompi;
- seven ordered settlement batches;
- pinned target segmentation: po2 20 for batches 1-6, po2 16 for batch 7;
- effective local proving resource profile: po2 19 for batches 1-6, po2 16
  for batch 7; and
- terminal principal, pending, exit and permission accounting: zero; state rent
  remains separate.

## Live order

1. Use either an independently authenticated gateway or the locally owned,
   pinned TN10 node. Recheck synchronization, network ID, lane state, fees and
   free-test-KAS source UTXOs.
2. Create a new unfunded identity with `init-full-drainage`; never reuse a used
   identity.
3. Activate/seed the lane, bootstrap and initialize the state covenant.
4. Fund only the fresh sponsor with free test KAS. Publish both deposits and the
   first three fresh wallet operations, then freeze/prove/verify/settle batch 1.
5. Publish the remaining two payments and exit 1, then settle batch 2.
6. For batches 3-6, include the prior permission issuance, confirmed payout and
   next owner-authorized exit in one complete capture.
7. Batch 7 reconciles payout 5. Confirm all five owner outputs, spent permissions
   and reserves, final state rent and zero terminal principal accounting.
8. Reconstruct from wallet backups/public authenticated history after the
   frozen service-loss point, retain all failures, and score the actual public
   transcript under the unchanged observer rules.

Every live capture creates a new input/journal and therefore requires a new
local Succinct receipt. The retained local receipts are regression/rehearsal
evidence only; they cannot authorize TN10 transactions with different inputs.

## Executed TN10 result — 2026-11-02

A fresh Testnet-10 identity completed the full lifecycle using free test KAS:
two exact 100,000,000-sompi deposits, three private transfers, five
owner-authorized exits, five confirmed native payouts and seven confirmed
receipt-backed settlements. The terminal checkpoint has zero reserve principal,
private liability, pending deposits, unpaid exits and permission rent; the
100,000,000-sompi state rent remains separately accounted.

Primary mutation/read evidence used the synchronized v2.1.0 endpoint at
`electron-10.kaspa.blue`; `vector-10.kaspa.green` independently agreed on
relevant UTXOs and terminal outputs. The locally owned node was still
synchronizing and was not treated as a live authority.

The final proof interval exceeded Node's single-string limit. The settlement
had already been durably accepted, so no transaction was retried. Read-only
recovery retained two complete native RPC passes as 36 gzip pages, kept every
selected-chain header and every transaction in KPI-lane-active blocks, and was
accepted by the unchanged pinned validator. The terminal public bundle and
secret-leak audit remain local under the private run directory; no public post,
mainnet action, commit or push occurred.

The finite local route is implemented by:

- `fund-sponsor.mjs`: one exact 10-test-KAS funding transaction with durable
  intent, no automatic resubmission and two-endpoint corroboration;
- `live-chain.mjs`: exact-U64 dual-route JSON-RPC query, submission and
  confirmation with a rechecked deep selected-chain anchor;
- `live-full-drainage.py`: ordered fresh wallet proofs, captures, receipts,
  settlements, payouts and checkpoints; and
- `../tn10-live/capture.mjs`: read-only complete accepted-chain/lane capture.
