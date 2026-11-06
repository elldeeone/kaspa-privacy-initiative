# Adversarial second pass

Internal review, not independent cryptography approval. Runtime qualifications
come from the final evidence and verification receipt.

- **Inflation:** preserve the full wallet relation, integer ranges, canonical
  state, exact claim/payout counts, reserve/liability reconciliation and actual
  native values. Group fee cap is aggregate; fees only use the separate allowance.
  No repeated authorization can add principal or pay an extra recipient.
- **Double spend/revocation:** the current Ledger checks/inserts every economic
  nullifier atomically. A historical membership root is not unspentness. Test a
  genuinely paid cohort note while enough other users' backing remains: it must
  fail spentness, not merely insufficient reserve. No nonce-only revocation.
- **Consent:** hash complete independently canonical claim and payout sets,
  denomination, fee cap, reference anchor and immutable profile/pool/config.
  Owner checks full entitlement before proving. All authorizations bind the same
  intent. Changing any approved field requires new consent; an unrelated state
  update changes neither the intent nor the economic notes.
- **I-6:** each wallet proof retains its exact historical anchor and intent.
  Only the separate aggregate/native receipt certifies current state/effects.
  Preserve old/new root, actual predecessor/value, ordered payload/all outputs,
  immutable code and current spentness checks. Transplant a real continuing
  receipt to a changed current state and require native cryptographic refusal.
- **Reserve shape:** unrelated withdrawals can turn a continuing proposal into
  a terminal one. Derive shape from current state and preserve fixed refund
  policy. Do not authorize stale reserve values or let the operator take change.
- **Privacy:** full-set hashes/independent sorting add no per-note payout
  association. Equal-value and honest-cohort assumptions remain. The stable
  intent identifies one group across retries; public note/claim identifiers
  already link those retries. Timing, known owners and later disclosures remain.
  Counterfactual solo controls reveal mappings if combined with shared keys.
- **Execution timing:** anyone holding the complete released approval set can
  execute its fixed payout while conditions hold. There is no wall-clock expiry
  or final client confirmation. This enlarges the authorization window, allows
  delayed/strategically timed cashout, and keeps timing privacy unqualified.
  An accepted note spend revokes it; an off-chain cancellation request does not.
- **Liveness:** no privileged lock, server cancellation or batch-only exit.
  Unrelated changes no longer require wallet reapproval in the selected branch;
  every changed current input still needs a fresh outer proof. A spent cohort
  note, removed anchor, exhausted allowance, fee above cap or changed group can
  halt the round. Original owner-only exit paths remain available.
- **Dependencies/reorg:** fixed parameters/history/software still must exist.
  Restoring keys locally is not all-service-loss recovery. Accepted-anchor
  removal or rollback can require refresh; no live DAG/reorg qualification.
- **Scope:** isolated new synthetic bank/image and native Full checks only.
  Preserve earlier programs and failed results. No invariant, consensus or
  existing bank upgrade is silently changed; no code is described as secure.
