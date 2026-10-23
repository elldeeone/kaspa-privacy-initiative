# Independent payments: execution checkpoint

**In progress.** The new full-tree private cashout and the cold HTTPS recovery
route have genuine proof/native results. Scheduled shared settlement is under
implementation. Financial privacy and separately administered retention remain
open; the four-track product milestone is not complete.

Baseline: `5aaf99532d8714e510d421102df719f60f54d073`. The
[execution plan](PLAN.md), [RFC-0024](../../../docs/rfc/0024-independent-private-payment-settlement-and-recovery.md),
[ADR-0058](../../../docs/adr/0058-private-full-note-exits-without-commitment-appends.md)
and [ADR-0059](../../../docs/adr/0059-scheduled-private-actions-with-public-settlement-proofs.md)
keep the implementation and qualification gates distinct. Existing experiments,
funded identities, failed studies and private material remain unchanged.

## Private exits at capacity

The [closed capacity packet](exits/RESULTS.md) uses a new domain, new compact/wide
parameters and a no-append full-note private cashout. Two genuine withdrawals
keep the CM cursor at 65,535, advance NF counts 131,067 -> 131,069 -> 131,071
and drain reserve 2,000,000,000 -> 1,000,000,000 -> 0 sompi. Native Full and every
input engine accept both; payouts total 1,960,000,000 and fees total 40,000,000
sompi. A fresh current-state private proof for an already consumed original NF
is rejected at the authenticated absence guard before G16, at 54,317 units.
Ten coherent native body/state tamper cases reject.

The new relation's three compact modes have one identical finalized matrix.
Direct CS controls distinguish 17 actual UNSAT cases from two deliberately SAT
native-owned obligations. Independent source, branch-induction, exact
parameter/proof/native byte joins and the complete 232-path publication inventory
have been reviewed. The valid-history invariant m+2U<=2n+1 reserves the two NF
slots needed by each remaining full-note exit without publishing an owner map
or deleting old spentness.

The prior 65,533 spends are constructed, not a replay of accepted history. This
closes the tested append-capacity obstruction, not full-tree private change,
arbitrary future fee spikes, fair inclusion, new-instance original-backup
recovery or production soundness.

## Public distribution and cold recovery

The [published research release](https://github.com/elldeeone/kaspa-privacy-initiative/releases/tag/native-kas-recovery-2026-10-23)
contains 19 exact assets: the earlier selected 1,307,894,256-byte compact PK in
two chunks, public manifests/known-unsafe synthetic GN history, transport code
and a 66,501,581-byte software archive. The software archive has 6,636 exact
regular members, including 6,633 typed software files and all 148 locked
dependency packages. All remote asset sizes/digests match the reviewed local
bytes. The [root asset audit](recovery-transport/ROOT-ASSET-AUDIT-01.json) also
checks every archive member and retained main private literals/identifiers,
without publishing private patterns or their hashes.

The third clean offline build reproduces selected prover
`1662fcd9a5b90b8658e07aed2250a4c9c11d2390e80d7addae717090d63fb94d`
byte for byte. Empty Cargo home/target and absent original source/cache are
observed. Two earlier mismatched binaries and a missing-vendored-dependency
failure remain retained; matching original registry paths and optional
toolchain-component visibility resolves the binary difference. The compiler
and OS are independently selected existing dependencies, not bundled software.

A fresh source-only client retrieves the exact full PK, four small capsule
objects, software archive and member inventory over verified HTTPS, with the
original repository/PK/cache/controller paths absent. The full transport takes
125.689 seconds; a separate strict unpack/typed restore authenticates every
software member. A network-off owner then uses only downloaded software/data/PK,
one original deliberately known-public backup and externally selected authority
to generate a genuine private terminal proof and exact Native Full withdrawal.
Whole-PK/VK authentication precedes backup-byte access. All seven requested
original paths are absent.

Exact canary closure is:

```text
1,000,217,300 source sompi
= 981,281,800 native payout
+     217,300 ordinary entry fee
+  18,718,200 private terminal fee
+           0 reserve
```

This is an unfunded known-unsafe canary with supplied UTXO contexts. No actual
accepted backing, current spend authorization, broadcast or confirmed payout
is inferred. The gross 10-KAS claim is not a net 10-KAS useful-payment fee
denominator. GitHub release/raw/CDN endpoints share administration; an offline
copy on the same host is not a separately controlled provider. Independent
operator/retention evidence is still pending owner-supplied access.

Use [published metadata 02](recovery-transport/PUBLISHED-RELEASE-02.json): it
refreshes final-tag browser URLs while retaining metadata 01's draft URLs as a
historical snapshot. No asset bytes changed or were reuploaded by that fix.

## Settlement and fees

The public two-action checker actually verifies owner G16 predicates and
derives public NF/CM/state/reserve/native effects. Ordered positives pass;
conflicting successors and fresh private-valid/native-invalid cases reject.
Independent review found and reproduced four missing native-header checks in
the initial checker; corrected coherent-ID regression controls preserve the
genuine proof while rejecting the invalid body. This is semantic equivalence
work, not an aggregate receipt, accepted settlement or fee reduction.

Three earlier genuine public canaries pass compute budget 1,500 and reject
1,475. Their reference-100 fee quotes each fall by 1,000,000 sompi. Those
canaries are deliberately underpaid, and these sample checks do not qualify a
changed complete financial route or a universal budget for new code.

ADR-0059 selects a fresh scheduled two-P0-action wrapper with owner-local private
proofs, complete public settlement semantics, exact allocated fees and private
fallback. Its 424-byte journal and child-only payload avoid own-proof/body/image
hash cycles. Host/guest/native equivalence and a genuine outer receipt/Full
body are still implementation gates. Even ideal N2 cooperative verification
plus independent private exits costs 2.25% of two useful 10-KAS payments at
reference rate100 before overhead. Low-demand fees remain an architectural
limitation, not something additional proving CPU erases.

## Financial privacy

The old frozen 96-view study and all 35 incomplete views remain unchanged.
Ordinary aggregation preserves individually published output partitions.
One invoice plus sender change is the existing serial baseline, not a new
anonymity protocol: participant knowledge can propagate through a forced sparse
change chain. Cashout before a second genuine funding source can still expose
singleton ancestry. The original common-price prior also exceeds the absolute
20% amount target. Larger repeated-view counts cannot repair those facts.

The new [prospective control plan](privacy/CONTROLS-PLAN-01.md) separates these
claims and includes one/two-real inputs, partial/full payouts, public no-append
behavior, legitimate invoices/NFs, change propagation, malformed certificates
and UNKNOWN. No new heldout draw is selected while the analytic gates fail.
An established MWEB aggregation component is being evaluated separately as a
design precedent; it is not a native-KAS integration or privacy qualification.

## Remaining completion gates

- Genuine scheduled shared-settlement proof/native body, full fee accounting
  and privately unilateral fallback, including operator loss and low demand.
- A changed, implemented privacy design that survives the full declared
  observer and original qualification gates; component aggregation is not enough.
- Separately controlled public recovery copies with stated retention and
  repeated loss/retrieval evidence, plus accepted-head/reorg reconciliation.
- A fresh selected testnet profile and complete rehearsal through confirmed
  terminal payouts before any claim of live readiness.
