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
- **Observable time:** `minute` is a modeled chain-time proxy. No universal
  precise transaction-acceptance wall clock is claimed as an L1 payload field.
  Common clock, timestamp resolution and queue/service assumptions are explicit;
  clock skew and real chain-time variation are not qualified by the offline
  arithmetic. RPC logs are not supplied to the chain-only observer.

Review clarification during the blinded run: the frozen immediate workload
opts out before a partial. A user can also cancel the optional wait after a
partial. A separate tiny escape control verifies that the unchanged integer
exit relation accepts immediate change withdrawal while the normal-timer
observer rejects it as out of model. Thus timed singletons are conditional on
following the normal policy, not universally forced by chain data. No live
delay lock is introduced. This extra control uses no primary case or truth;
the primary policy, workload and observer bytes remain unchanged.

The inherited-model ablation removes both the normal no-re-splitting rule and
elapsed-time compatibility. Do not attribute their combined effect solely to
timestamps. The maximum-score objective's hash component can still have exact
ties; it does not prove a unique chosen graph or calibrated odds. Retain the
actual guesses and all fixed attack-family results, without choosing favorable
solver reruns.

Completed review: the frozen gate fails because the strongest fixed attack has
the same success in both arms in all four comparisons. Fees and latency pass;
neither overrides the privacy failure. All 504 original-graph checks and
2,304 scored narrowing checks pass, with no new unique original-payment source.
The post-score pairing audit finds a sole correct remainder for all 48 sparse
common payouts, but does not establish universally exact source inference.
The inherited untimed model already retains the same unique-claim totals;
the result cannot be attributed only to the timing addition.

One two-worker search exhausted memory before producing predictions. The
other 251 complete outputs were retained unchanged. A captured identical query
solves with one worker; the sole missing observation completes under that
setting. The wrapper changes only `num_search_workers`, preserving constraints,
objectives, exact certificates and complete enumeration. Nine controls,
including exhaustive source/objective oracles, pass under both settings.
The original failure, terminated diagnostic replay and final successful replay
are recorded. Diagnostic ten-second cutoffs never supply a privacy result.
Primary truth is not scored until the whole 252-output matrix is present.
The search-setting difference is explicit in the recovery receipt; source
hashes alone must not be misread as evidence of identical solver scheduling.

The post-score audit is descriptive and does not modify the predeclared gate.
Public evidence includes scores and latency/accounting aggregates derived from
truth after observation; it excludes raw private views, seed, requests, keys
and unused capabilities. The final export sanitizes the failed subprocess's
host-path argument dump while retaining its original private receipt hash.
No native validation, funding or live exit is newly claimed by H18; the
failed gate stops that conditional continuation.

No new trust authority, cryptographic primitive, consensus rule or real asset
is introduced. All private fixtures, records and unused exit capabilities stay
outside Git. Public export omits user request times and participant-owned
prediction targets. Source candidates are transactions, not people or odds.
