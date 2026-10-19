# RFC-0007: Can native compact state preserve reusable private exits?

Design and hypothesis: [ADR-0019](../adr/0019-compact-public-settlement.md).
Status: bounded hypothesis supported offline and on TN10. The complete rehearsal
and fresh 100-payment trial passed, including Bob's exact old proof and full
drain. See [measurements](../../poc/shared-pool/COMPACT.md).

Bootstrap Alice and Bob. Bob authorizes a full exit before Alice makes 100
two-output payments to a third independently held wallet. Stop Bob's prover.
Reconstruct all current public witnesses, settle his identical proof, then drain
every outstanding claim. This is a synthetic serial workload, not 100 concurrent
users or a privacy measurement. A short complete TN10 rehearsal precedes the
100-payment live trial only after the offline gate passes.

Measure transaction size/mass/fees at payments 1, 10 and 100; include all public
history reconstruction, proof creation, cold loading and final cleanup separately.
Require same-proof exit, zero additional settlement proofs, native rejection of
forged roots/paths, lost spentness, duplicate spends, unauthorized payouts and
backing changes. Include capacity/position/unsigned-comparison boundaries and
terminal exits. Capacity is a configured bound; 100 payments do not prove scale.

Stop if native limits cannot accommodate the design, soundness depends on an
unverified host assertion, a safety control accepts, or Bob needs new private
proof work. Keep native consensus, policy estimates and actual TN10 relay/payout
evidence separate. Future work includes admission, partial withdrawals, anchor
privacy, fee repricing, reorgs and independent review.

Observed decision: keep compact public settlement for further direct-L1 research.
The trial confirmed 204 native transactions, zero additional proofs for Bob and
zero remaining liabilities/reserve. At payments 1, 10 and 100, transaction size
and compute mass were unchanged. Local public reconstruction still grew to
352 ms and RPC discovery took another 11.4 seconds; smaller state does not imply
constant wallet catch-up work, lower fees or improved old-anchor privacy.

Stage 2's subsequent [privacy audit](../../poc/shared-pool/PRIVACY.md) uniquely
identifies the source transaction of the retained H6 first exit from its old
anchor and public spentness constraints. Preserve the H6 liveness result, but
do not present frozen-proof waiting as privacy growth.
[ADR-0021](../adr/0021-separate-exit-fallback-and-privacy-policy.md) and
[RFC-0009](0009-compact-anchor-privacy.md) separate a private exit fallback from
the proposed fresh-authorization privacy path; no relation changed in this audit.
