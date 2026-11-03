# Privacy and independent-recovery adversarial gates

Status: prospective source/design review at baseline `63f49405`, not a runtime
or protocol approval. No node, seed, proving key, proof, native validator or funds
were accessed by this lane. Closed prior packets and the completed trial remain
unchanged. Each implementation needs its exact contract/source review.

## Private native exit

1. Bind the exact prior outpoint, domain/state/counts, actual reserve, fee,
   payout amount and canonical destination SPK, ciphertexts, successor state and
   reserve into the proof statement and executing native context. A payout
   amount without its destination is an unauthorized reserve-release path.
2. Prove bounded integer conservation, `sum(inputs)=sum(private outputs)+P+f`,
   and enforce `R'=R-P-f` without field-wrap interpretation. Count every positive
   liability. Require the continuing reserve floor or an actual terminal branch;
   no dust liability, hidden subsidy or unpaid remainder is discarded.
3. Preserve independent ownership and NF credentials, original positioned real
   NFs, distinct dummy-NF domain, canonical padding and current indexed-tree
   exclusion. Wrong secrets, numeric/non-Boolean selectors, copied credentials,
   duplicated real inputs, existing NFs, stale roots and cross-instance context
   must reject. A valid private proof does not replace native current spentness.
4. Terminal private exit cannot inherit the old requirement for a positive
   private output. Decide its CM append semantics explicitly. If terminal n is
   unchanged, `m+=2, U-=r` preserves the ghost bound because `2-2r<=0` for r>=1.
   Check both NF insert capacity limits. No spare-CM requirement should be
   introduced accidentally by appending economically empty terminal notes.
5. Fix branch, VK, domain and all immutable policy bytes. Mutated payout/state/
   reserve/fee, extra outputs, weak signatures on the revealing branch, invalid
   SPK versions and replacement policy/VK must not pass. Genuine proof positives
   and context-rebound negatives must be distinguished from reused-proof tests.
6. Keep the revealing fallback owner-controlled and available without a prover.
   Its disclosure must be explicit; do not silently route ordinary withdrawals
   into it or make a hosted service's disappearance authorize reserve release.

## Independent receiver recovery

1. A minimal public descriptor pins a user-selected canonical founding outpoint.
   Domain/policy/VK coherence does not select among separately funded copies of
   a public D. Descriptor identity authority and transport trust are distinct.
2. Derive a coherent base from the actual founding Note168/output: note value
   equals reserve, n=m=1, raw-CM singleton root and sentinel NF root. Output
   creation alone does not execute its future covenant or establish R=L.
3. Reconstruct arbitrary admitted/private/revealing transitions from fetched
   accepted raw bodies and populated UTXO contexts. Never import operator
   snapshots, expected recipient amounts, actor labels, six known transaction
   IDs, private controller exports or a declaration of terminal zero.
4. Follow exact reserve outpoint/value/SPK links and immutable code. Reject
   gaps, duplicated/conflicting spends, missing delivery bytes, wrong roots,
   reordered updates, omitted suffixes and unavailable required history. Empty
   address queries and pruning are not zero balance.
5. Check the accepted/current chain view with explicit confirmation/removal
   policy. A fetched history, two agreeing RPCs and self-consistent roots do not
   by themselves prove independent consensus, completeness or immutable finality.
   Name the validating-node/availability assumptions and preserve disagreements.
6. Give the receiver process only its seed-only backup, selected descriptor,
   independently fetched public records and pinned software. Exclude payer and
   other recipients, prover/PK and precomputed exits. Derive owned values and
   current witnesses rather than validating an operator amount map.
7. A live lost-service exit must use a fresh trial/identity after the entire
   local terminal path passes. This lane does not fund, submit or replay the
   completed trial. Ambiguous submissions are reconciled read-only.

## Privacy evidence

1. The completed known six-body pilot is a descriptive exposure canary. Public
   REVEAL CM/value/native key maps to a historical PRIVATE output CM, but actor
   identities and the semantic designation of a direct payment are separate
   declared observer inputs or hidden truth.
2. Freeze C/C+P/C+P+A and directory/interaction permissions, eligibility,
   workload, attacker inputs, hidden truth, attacks, tie rules and metrics before
   new scoring. Do not let filenames, labels, seeds or expected amounts enter
   the chain-only attacker sandbox.
3. Keep the prior `21103/100025 = 21.09772557%` amount floor and unchanged 20%
   gate. A workload prior above an absolute gate is a retained information
   limit, not permission to remove its cases or silently select a nicer workload.
4. Private EXIT still publishes P, fee, timing, funding and full-drain totals.
   Hidden CM/k alone does not establish amount or identity privacy. Include
   individual cashouts, complete drainage and retained orphan/pending fallback
   disclosures. Never erase a disclosure by rolling back state.
5. Retain every user's funding/admission/payment/change/exit/retry/tail cost.
   One recipient plus change is one useful payment. Distinguish source arithmetic,
   synthetic ledgers, genuine relation proofs and actual accepted chain evidence.
   Population/uncertainty gates are not inherited from the small known pilot.

## Required review closure

Record exact source/fixture identity and review outcomes before each prospective
runtime. Concrete failures get narrow fixes and retained evidence, not ceremonial
requalification of unrelated unchanged code. Passing tests is implementation
evidence, not a cryptographic audit, privacy theorem or production-safety claim.
