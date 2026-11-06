# ADR-0111: Reuse fixed withdrawal consent across unrelated accepted updates

Status: accepted for the owner's 6 November 2026 offline experiment; no production
architecture or consensus change. Supersedes ADR-0110's exact-transaction consent
only in the new explicit optional intent branch. Old branches/evidence remain.

The owner requested pushing the completed work, keeping the optional payout
privacy improvement, and fixing repeated approvals during busy periods. The
previous experiment safely rejected old approvals after an unrelated payment:
the owners had approved an exact native outpoint, reserve shape and state root.

In an isolated new application image, wallets may instead authorize one fixed
withdrawal intent: protocol domain, pool identity, wallet verifier, historical
reference anchor, random round nonce, full sorted cohort nullifier set, full
independently sorted equal-value payout-script set, denomination, maximum native
fee and immutable refund-key hash. A wallet checks its own full payout and claim
membership before proving. No nullifier-to-payout-position association is added.
Use the existing complete wallet relation's destination commitment for this
domain-separated intent hash; do not change the circuit or trusted setup.

The fresh transition kernel requires exact cohort/payout equality, the committed
fee bound, current unspentness and accepted historical anchor. It derives the
current remaining reserve, continuation/terminal shape and allowance refund.
All existing native-effect, value, immutable successor and current-state checks
remain. Old exact-effect/solo/named/refund branches stay available.

## I-6 applies to the final state-transition proof

This explicitly separates conditional owner consent from a state-transition
receipt. The wallet proof remains bound to its fixed reference anchor, pool and
complete intent. It is not a receipt claiming a transition from an old root.
Every final RISC Zero/native receipt still binds the exact current old/new roots,
actual outpoint/value, all actual outputs and canonical packet. Reusing a final
receipt at another state/outpoint/pool must fail. Accepted historical membership
plus current nullifier checks already exists in the Ledger. No invariant text or
interpretation permitting replay of state transitions is adopted.

An accepted spend of a cohort note cancels its usability; off-chain cancellation
and a nonce alone do not revoke consent. Changed recipients, amount, cohort,
fee bound, refund policy or accepted-anchor availability require fresh consent.
No administrator can lock the bank to reserve a withdrawal window. This saves
wallet reapproval; it does not eliminate current-state outer proving, serial
UTXO contention, unavailable data or reorg recovery.

Released consent is executable by any holder of the complete approved proof set
while its conditions remain true. It has no wall-clock expiry and no second
owner confirmation of execution timing. This extends the useful authorization
window but also permits delayed or strategically timed cashout. Owners can
invalidate a note through an accepted spend; off-chain cancellation alone cannot.
This optional timing tradeoff is explicit, and timing privacy is unqualified.

Use a fresh synthetic bank/image, real existing wallet proofs, genuine complete
receipts and native Full validation. No existing bank upgrade, real funds,
mainnet, paid allocation, new primitive, Tor expansion or MPC restart.
The [frozen test selection](../../research/reusable-withdrawal-approvals-2026-11-06/SELECTION.md)
defines the positive, negative and privacy-regression gates.
