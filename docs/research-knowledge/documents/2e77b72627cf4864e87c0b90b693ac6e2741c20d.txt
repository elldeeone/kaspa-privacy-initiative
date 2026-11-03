# Compact-state evidence

These are synthetic experiments, with separate offline and funded TN10 records.
The [report](../../COMPACT.md) explains the question, exact layout, results and
limits. The [second-pass review](../../COMPACT-REVIEW.md) records the attack cases.

| Directory | What it records |
| --- | --- |
| `offline/` | 100 intervening payments, every exit, native validation and hostile controls; no chain acceptance claim. |
| `rehearsal/` | Fresh two-payment TN10 rehearsal, including the actual terminal payout. |
| `trial/` | Fresh 100-payment TN10 trial, including public discovery, Bob's unchanged proof and the remaining exits. |
| `funding/` | Twelve ordinary-input consolidations reusing previously authorized test coins. These do not spend a privacy reserve. |
| `support/` | Public parameter metadata, five Rust test-group results, public-only offline process receipt and four unchanged-proof output controls. |

Each exported transaction has its native metrics. Live submissions, accepted
body/full-hash comparisons, payout observations and prover lifecycle receipts
are separate files. Export manifests record source and exported SHA256 digests;
the difference for JSON is canonical formatting or removal of local metadata.
Summary files are derived consistency checks, not independent consensus engines.

Only explicit public-artifact allowlists were copied. Private spending/viewing/
native keys, note plaintexts/randomness, proving keys and private requests stay
outside Git. This directory includes experiment labels and pre-payment public
bootstrap metadata; it is not a chain-only observer dataset. RPC access and the
correctness/availability of the node view remain separate assumptions.

To check a live export from the repository root:

```sh
python3 poc/shared-pool/check-compact-state.py poc/shared-pool/evidence/2026-10-19-compact/trial/public
python3 poc/shared-pool/summarize-compact.py poc/shared-pool/evidence/2026-10-19-compact/trial
```

The first checker independently reconstructs the three public trees, update
paths, native amounts, lineage and successor P2SH scripts. It does not implement
Groth16 verification or Kaspa consensus. The second verifies proof/authorization
byte equality, lifecycle timestamps, isolation receipts and exact accounting.
Neither estimates real-world anonymity or proves cryptographic correctness.
