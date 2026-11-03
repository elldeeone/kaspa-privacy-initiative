# ADR-0057 design disposition

**ACK for the bounded matched-proof/recovery/measurement prototype.**

Reviewed the complete proposed
[ADR-0057](../../../../docs/adr/0057-matched-batch-proofs-and-portable-recovery.md)
at SHA256 `6cc64e6a49d607da7cf4e16a42ff2df4c3287f6b92eb26bf4e6297375ad4c280`
and [PLAN](../PLAN.md). A Status-only change to Accepted does not alter this
reviewed decision. The preliminary [design obligations](DESIGN-REVIEW-01.md)
remain requirements rather than completed implementation tests.

No blocking design defect was found. The decision preserves the full existing
relation obligations, shared positioned real NFs across compact/wide/REVEAL,
native current-context/NF/tree/output checks, fixed per-role matrices, explicit
integer conservation and one-owner exit independence. The fresh public D
independently matches SHA256(tag || genesis || nonce); old instances stay separate.

The scope is correctly bounded: CM126/NF67 does not qualify saturated-pool
private exits;32 output slots do not establish32 humans or live demand; retained
public material does not establish currentness, independent providers or honest
setup. Exact minimum terminal fee/refund does not alter the useful-payment
principal denominator or overwrite the earlier conservative fee projection.

The privacy study must still freeze its precise attacker, corpus, thresholds and
query/UNKNOWN handling before generating results. One-real-input policy is a
conditional wallet/model assumption because the cryptographic relation supports
two real inputs. Capsule integrity needs an externally pinned authority root and
fresh accepted-history/current-UTXO reconciliation.

This design ACK permits implementation once the separate primary-source gate is
satisfied. It does not review unwritten code, authorize an old PK for the new
relation, establish setup/readiness, fund a profile, or qualify privacy/fees.
Implementation, finalized matrix controls, real proofs/native effects and final
publication boundaries require subsequent evidence and adversarial review.

No build, setup, private input, PK blob, proof, native runtime or network mutation
was used for this design review.
