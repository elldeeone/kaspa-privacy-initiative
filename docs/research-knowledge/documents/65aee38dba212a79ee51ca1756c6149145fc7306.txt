# RFC-0021: Confirmed native private-payment rehearsal and prover costs

**Status:** Bounded TN10 rehearsal complete; broader qualification open.
**Date:** 2026-10-23 UTC.

## Question and selected scope

Can the new relation from RFC-0020 execute its entire native test-KAS lifecycle
through both confirmed recipient payouts, with old-backup recovery and no prover
in the exit path? Preserve every invariant and native asset model. ADR-0046
selects a fresh TN10-genesis/nonce-bound domain, new development setup and private
identities; it does not deploy the public DO_NOT_FUND fixture or old S7 workflow.

The completed trace uses a dedicated ordinary test-only source of 306,866,100
sompi, two 100,000,000-sompi recipient notes and the unchanged 60,000,000 positive
note floor. It is a liveness pilot, not fee qualification. The earlier favorable
two-10-KAS fee result and all failed targets remain unchanged.

## Result and evidence

[The actual chain result](../../research/next-session/testnet-rehearsal/RESULTS.md)
records six accepted native bodies: preparation, founding, admission, genuine
private payment, continuing owner exit and terminal owner exit. Both recipients
restore from pre-payment seed-only backups and accepted public records in
separate network-isolated processes without the payer, other recipient, prover
or PK. Payouts are 95,026,200 and 95,036,800 sompi; final reserve and positive
liabilities are zero. Complete fees are 36,954,400 sompi.

The adapter checks exact canonical bodies, populated input UTXOs, amounts,
SPK version zero, covenant metadata, actual successors, accepting headers,
strictly greater than 20 blue-score depth, removals and current exact payout
UTXOs. A selected validating node and complete retained archive remain trusted.
This is neither independent consensus validation nor immutable finality.
Acknowledgement alone is never completion. Durable identity-bound submission
intents prevent a second send; ambiguity is reconciled read-only.

## Prover work and open decisions

ADR-0045's exact authenticated uncompressed cache reduces observed loading from
156.38 to 5.89 seconds; one genuine six-worker load/proof takes 30.87 seconds,
still exceeding wallet memory and warm-proof limits. ADR-0047's equivalent SHA
Ch/Maj circuit reduces constraints from 4,650,533 to 3,497,893, halving the FFT
domain. Its first genuine four-worker result still fails at 11.17 seconds and
4.009258 GiB. ADR-0048's separate selected-HMAC candidate further reduces the
relation to 3,199,529 constraints. Its first genuine four-worker proof measures
10.495 seconds and 3.82531 GiB whole-process peak: below the proof-process memory
screen, still above the warm latency target. It changes neither the funded
trial nor earlier failed measurements; p95 and aggregate wallet use remain open.

Strong financial privacy, durable public data, independent current-head/reorg
recovery, general recipient-plus-change fees, independent-owner aggregation,
setup integrity and whole-wallet p95 remain open. Passing implementation checks
is not a proof of cryptographic correctness or production safety.
