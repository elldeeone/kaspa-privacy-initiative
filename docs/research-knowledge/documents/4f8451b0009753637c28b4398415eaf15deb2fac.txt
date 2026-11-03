# Next task: identify and fix a demonstrated payment-privacy leak

Luke authorizes analysis of the actual completed transaction evidence, selection
of its largest demonstrated privacy leak, and the smallest justified local fix.
Keep MPC paused. No forced delays, withdrawal locks, privileged withdrawal
signatures or requirement for anyone to leave user funds in the pool.

## Start from the corrected result

Read `CORRECTION.md`, `score_live_correction.py` and
`run/live-correction-v2/{PREDICTIONS,VALIDATION,CHECKS,MANIFEST}.json` in this
directory before relying on the original stronger-observer claim.

The native run completed at:
`/var/tmp/kpi-tn10-full-drainage-live-20261102-attempt-06`.

Its original `public-result` manifest SHA-256 is
`1259c42cb7cde08fac0b9da29176e46cc20dddc963682c680a19958eefd5b88c`.
All five payouts completed and user principal/liabilities are zero in that run.
One test KAS remains as separate state rent. Preserve every original artifact,
the correction and the earlier failed trials unchanged.

The live run executed A-to-M, A-to-S and B-to-M. The old stronger view assumed
M-to-S and selected the wrong history. The corrected assessment rejects that
as successful reconstruction. A new, explicitly post-hoc sensitivity shows that
truthful knowledge of A-to-S selects the actual history within the retained
small model. Do not describe that sensitivity as the original frozen attack.

## Required work

1. Analyse the retained actual transaction bodies, amounts, fee-funding and
   sponsor relationships, UTXO/permission/settlement structure, operation shape,
   ordering, timing and genuinely available service evidence. Separate facts
   the observer sees from experimental orchestration labels and assumptions.
   Missing network/IP observations stay unmeasured; do not invent them. Logging
   metadata does not count as testing whether it distinguishes payment histories.

2. Implement the smallest auditable observer that uses the relevant real fields.
   State the attacker and hypothesis before selecting or tuning the attack.
   Keep a chain-only view, known-owner view and truthful participant-knowledge
   view. A participant knowing its own payment should not be silently given
   other users' private facts. Measure inference about OTHER people's payments,
   funding origins and amounts separately from public withdrawal facts. Use
   held-back execution truth to score complete compatible histories; seal
   predictions before truth validation. Preserve false-evidence and unique-wrong
   controls from the correction. Report failures and counterexamples unchanged.

3. Identify the biggest demonstrated leak and its exact cause. State whether it
   is direct protocol disclosure, wallet policy, fee/sponsor linkage, participant
   knowledge or a public-balance constraint. Do not rank leaks by a fabricated
   universal anonymity number. A larger pool or extra candidate labels is not
   automatically better privacy.

4. Select and implement one minimal local mitigation only if its mechanism can
   address that cause. Reuse established designs and existing components. Note
   merging is a candidate, not a selected solution: do not build it just because
   it was proposed. Document significant architecture/security changes in the
   required RFC/ADR and perform adversarial review before calling a fix ready.

5. Compare baseline and candidate under the same declared attack and knowledge.
   Any changed workload, public transcript field or extra assumption must be
   visible. If existing data cannot test a counterfactual, label a local model
   or synthetic replay honestly. Demonstrate improvement in actual payment
   facts, not only commitment/event ambiguity, while retaining immediate owner
   exits and the terminal case where every user withdraws every claim. Include
   sparse controls. If public balances already determine a payment, report that
   limit rather than manufacturing cover activity or promising it away.

## Boundaries and closeout

- Work offline first using existing evidence and available local CPU/GPU. No
  new funded trial, broadcast, paid compute, server framework, token, mainnet,
  public posting or push is part of this next task.
- Keep the paused MPC continuation checkout untouched. Never weaken proof,
  authorization, root/nullifier, integer conservation or reserve/payout checks.
- Inspect and inventory balances/recovery status of earlier funded failed
  attempts without changing them. Do not imply successful attempt 06 accounts
  for those separate trials. No wallet/sponsor keys or private truth in Git.
- Checkpoint only a finite reviewed allowlist of code and publishable evidence;
  retain excluded private evidence locally. Do not use `git add -A`.
- Stop after one measured mitigation or a precise evidence-backed blocker.
  Do not expand into another infrastructure stream.

Deliver a plain-English report: what the strongest real attack reconstructs,
what survives all withdrawals, what changed and improved, what did not improve,
and the smallest remaining step. Passing settlement/proof tests is not evidence
of production privacy or cryptographic correctness.
