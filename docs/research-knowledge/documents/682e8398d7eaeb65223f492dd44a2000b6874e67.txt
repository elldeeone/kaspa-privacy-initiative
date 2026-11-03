# Adversarial second pass

**Scope:** `wallet-local-private-change-v1` local composition and evidence only.

## Value and authorization

- **Mint/inflation:** both self-transfers use the unchanged constrained TRANSFER
  relation. Runner preflight rejects below-minimum request, below-minimum change
  and sum mismatch before proof construction. The circuit proves u64 input/output
  conservation; ledger backing remained exact and ended at zero.
- **Double spend:** every accepted original transfer and self-split replay was
  rejected atomically by the economic nullifier check.
- **Unauthorized release:** every exit was created from exact-commitment discovery
  by a restored owner backup. A different wallet could not discover the note.
  Wrong payout destination/amount attempts rejected atomically.
- **Stale/wrong state:** wrong-root and wrong-domain mutations rejected. This is a
  local append-only experiment, not reorg evidence.

## Privacy attacks

- Known payout identities reveal the withdrawing `firstRecipient ->
  secondRecipient` relationship even when requested amounts do not reveal P1/P2.
- When both private changes later exit, public conservation reconstructs the
  target P1/P2 exactly in the known-identity view. Without identity mappings, P1
  is still the sum of all four target-phase exits and is exact; P2 retains four
  role-assignment candidates.
- Full drainage identifies both original funders through deposit/change
  arithmetic. Unmapped recipient roles preserve some P2 and relationship
  ambiguity, but not funding-origin privacy.
- Commitment, output-grouping and transfer-position ambiguity remains. It is not
  counted as payment-fact privacy.
- Publishing the two experimental arms together does not model a real observer
  seeing alternative worlds. Exact arm realizations were independently sampled,
  preventing baseline public values from disclosing candidate values.

## Dependency and trust assumptions

- Losing the local prover reduces liveness; it does not create a privileged exit
  or inflation path. Owners still require the existing prover and their backups.
- Fresh setup, host control, local fixture authorization and assumed cryptographic
  opacity remain trust boundaries.
- Same-host independent keys are not independent physical custody or adoption.
- Offline payout fixtures are not native consensus settlement.

## Conclusion

No observed failure requires MPC. The measured leakage is caused by public exit
values, payout identities, the public withdrawal policy and conservation. MPC
would not hide those facts.
