# Scheduled common payouts: adversarial second pass

Author review of H18, separate from implementation; not an independent audit.
The [frozen specification](SCHEDULED-PAYOUT-SPEC.md) controls the decision.

- **Inflation/backing:** the protocol is unchanged. The arithmetic generator
  checks every debit, fee, private remainder and final payout with integer
  sompi. All original positive claims must be spent and the reserve empty.
  A sub-floor split becomes an ordinary full exit; no replenishment is invented.
- **Replay/authorization:** no circuit, key, covenant or native settlement
  implementation changes. The local optional schedule does not restrict the
  existing full exit. The immediate control uses saved anchors in both arms.
  New genuine/native claims require the conditional calibration, not these
  arithmetic controls. Earlier H17 mutual-exclusion checks remain prior evidence.
- **Dependency failure:** each timer is local. Other participants supply no
  signature, secret, request schedule or operator state. Stored change exits
  and authenticated history remain necessary; the model is not a new recovery
  or malicious-RPC result.
- **Timing inference:** common change must fully exit under the modeled normal
  policy, so an observer can reject impossible elapsed-time relationships.
  Queue work is allowed instead of assuming acceptance exactly at the timer.
  Constraints are necessary, not a complete likelihood of hidden arrivals.
  The maximum-score graph uses a timing score and deterministic public tie
  breaker, not a calibrated posterior or optimal-attack claim.
- **Amount inference:** every tail remains public; collapse common change back
  to its original creating transaction in each candidate graph. Multiple legs
  offer multiple chances to guess; one correct leg counts against the policy.
  Do not create apparent privacy merely by counting additional notes.
- **Small/known workloads:** new seeds and amounts do not create new economic
  topologies or empirical users. Both request distributions and service time
  are synthetic assumptions. Sparse and singleton conditions may leave no
  plausible mixing opportunity. Do not repair a negative result by adding
  people, changing the delay or selecting different seeds.
- **Solver soundness:** exact integer search has no timeout-as-ambiguity.
  Entailed amount bounds only aid search; every positive graph is certified
  against the unchanged integer relation. A separate direct graph check
  validates timing. Tiny exhaustive integer/ownership enumeration checks
  source candidates and the complete maximum-score objective independently.
- **Statistical scoring:** all fixed attack accuracies are retained. The family
  comparison takes the largest aggregate per arm, not the best guess per
  hidden target. Bootstrap whole paired ledgers; overlapping participant views
  are not independent samples. Twelve pairs per regime can be inconclusive.
- **Blinding:** observer namespaces have public bytes and at most one
  participant record. No host paths, `/proc`, nested namespace access, private
  seed, generator, request times or other views. Source/input hashes precede
  observation. The full matrix is checked before any truth-based scoring.
- **Fees/availability:** 0.4 tKAS is a selected debit under the pinned v6
  implementation. A two-minute service allowance is a model, not relay or
  network latency evidence. The conditional TN10 stage must reconcile actual
  allocation/genesis/funding-reuse fees and preserve accepted bodies.

No new trust authority, cryptographic primitive, consensus rule or real asset
is introduced. All private fixtures, records and unused exit capabilities stay
outside Git. Public export omits user request times and participant-owned
prediction targets. Source candidates are transactions, not people or odds.
