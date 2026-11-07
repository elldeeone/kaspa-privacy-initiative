# ADR-0113: cache verified operations, recheck current settlement

Status: executed bounded experiment; retain for new experimental banks, no production qualification.
Date: 7 November 2026 (Australia/Sydney).

The owner authorized reusable expensive approval verification, a complete
payment/privacy/retry path, and a small fresh testnet trial on functional success.
No consensus changes, real funds, new token or privileged withdrawal authority.

Reuse RISC Zero 3.0.3 composition. A pinned authorization guest checks existing
complete wallet proofs and commits domain, pool, pinned wallet-verifier ID and
the digest of the entire canonical packet. Keep its unconditional Succinct
receipt; the pinned compositional prover does not support Groth16 assumptions.

A fresh settlement guest pins that authorization image and verifies that exact
journal using an actual Proven receipt. Current nullifiers, accepted anchors,
deposits, payouts, bounds, fee caps and exact native effects remain freshly checked
by the economic kernel. The final native receipt must be complete, unconditional
and Groth16 compressed. Missing, corrupted, wrong-image, Claim-only or unresolved
assumptions cannot release funds. No old bank upgrade: a new guest means a new bank.

The initial supplied-state comparison keeps the original wallet circuit/setup.
The combined flow uses the existing dedicated TN10 domain/profile with the same
packed relation and fresh experimental one-party parameters (1,209,140
constraints). Its keys, cache image and settlement image are distinct; do not
mix offline and TN10 receipts or parameters. The setup remains unqualified for
production; no new cryptographic primitive or consensus change is introduced.
Count upfront setup/cache creation, resolution,
compression, misses and retries in total costs; do not assume first-use savings.
Static proof validity does not authenticate current spentness or accepted history.
For an exact comparison, one settlement image supports both full verification
and verified-certificate composition. The private execution-method selector
chooses two complete verification methods; it never asserts proof validity.
Both must produce the same economic journal and pass the same native bank policy.
All security invariants remain. Passing tests do not prove cryptographic safety.

The matched first comparison measures 418.999 seconds for cache creation,
30.527 seconds for the current settlement, and 445.735 seconds for direct full
verification of the same input under the same settlement image. Cold total is
449.526 seconds, so first use saves nothing; savings begin on the second attempt.
Three current-state contexts and the direct control pass actual native Full
validation with unchanged 16,555,100-sompi fees. This is supplied-state evidence,
not authenticated ancestry, a paid-chain result or complete-payment throughput.

The combined comparison fixes arrivals at 90/330/570 seconds and uses the same
withdrawal-priority prefix in both arms. It isolates work-conserving batching
versus individual payments under cached verification; it does not repeat the old
payment-first scheduler comparison. The competing update is accepted after cache
construction, during the fresh settlement job. Stop that owned job, retain the
certificate and consent, then prove against the current bank. Do not attribute
different whole-run timing to caching alone.

An adversarial measurement review found that the first reference arm reused
candidate-created certificates for its third payment and final payout packet.
Its native fees/complete receipts remain valid, but its queue times mix cold and
warm work. Preserve that result and rerun every post-prefix reference certificate
in a separate empty cache. Use the corrected cold reference for primary timing
and cost, and require its native transaction IDs to match the preserved reference.
Do not silently substitute modeled cold delays for measured waiting times.

On functional success, the small fresh TN10 rehearsal uses four test KAS of
principal, two of fee allowance and one of ordinary source change. It checks
real terminal payouts and restored-key spending, rather than qualifying cost at
that deliberately small amount. Old ordinary test sponsor change may fund it;
old banks/reserves and old trial identities are not reused.

See the frozen [selection](../../research/cached-approval-verification-2026-11-07/SELECTION.md)
and primary [sources](../../research/cached-approval-verification-2026-11-07/SOURCES.md).

The [complete result](../../research/cached-approval-verification-2026-11-07/RESULT.md)
now includes six/seven complete offline settlements, corrected cold-reference
timing, zero principal/liability and eight restored payout spends per history.
The fresh TN10 rehearsal pays all four test KAS principal, reuses the same three
approvals after a real accepted update (24.18-second fresh withdrawal proof),
and confirms all five restored-key payout spends. Two independent synced routes
agree on final UTXOs. Keep static verification reuse and optional batching/privacy;
complete financial privacy, first-use latency, full commercial cost and independent
recovery remain unqualified. Original native/claim checks and invariants remain.

The Claim-only control was refused by SDK 3.0.3 before receipt creation. The first
unfunded harness had expected a conditional proof and stopped before submission;
retain it and the fresh-identity retry. Record the actual SDK refusal layer, not
an unexecuted native conditional-proof test. This corrects test expectations only.
