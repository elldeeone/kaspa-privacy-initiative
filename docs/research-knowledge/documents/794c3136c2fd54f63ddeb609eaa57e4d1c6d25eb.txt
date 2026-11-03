# Independent payments: execution checkpoint

**Local settlement and private drainage now pass.** Two original backups recover
their incoming payments and change, generate genuine two-real-input private
exits using downloaded software/parameters and finish at zero reserve. Full-tree
private exits also pass. Financial privacy, low-demand fees, accepted-chain
readiness and separately administered retention remain open; the four-track
product milestone is not complete.

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

The current capacity-profile prover also rebuilds all 3,898,832 bytes exactly
from 19 current source files and 148 locked dependency packages in 32.212 seconds,
with empty Cargo home/target, original host paths absent and networking disabled.
See [current cold build](current-profile-coldbuild/RESULTS.md). A separate
[current runtime release addendum](current-wrapper-runtime/PUBLISHED-ADDON-01.json)
publishes an explicit 64-file/67-member wallet/runtime archive. A clean namespace
actually downloads all four additive assets over verified HTTPS and strictly
restores them in 6.846 seconds, with no imported downloaded code, PK or backup
access during transport. The original 32 distribution assets stay unchanged.
These are one-provider byte/source availability results, not independent
administration, setup honesty or accepted-state authority.

## Settlement and fees

The public two-action checker actually verifies owner G16 predicates and
derives public NF/CM/state/reserve/native effects. Ordered positives pass;
conflicting successors and fresh private-valid/native-invalid cases reject.
Independent review found and reproduced four missing native-header checks in
the initial checker; corrected coherent-ID regression controls preserve the
genuine proof while rejecting the invalid body. These controls establish the
public semantic contract used by the separately proved wrapper below; they do
not establish accepted-chain settlement.

Three earlier genuine public canaries pass compute budget 1,500 and reject
1,475. Their reference-100 fee quotes each fall by 1,000,000 sompi. Those
canaries are deliberately underpaid, and these sample checks do not qualify a
changed complete financial route or a universal budget for new code.

ADR-0059 selects a fresh scheduled two-P0-action wrapper with owner-local private
proofs, complete public settlement semantics, exact allocated fees and private
fallback. Its 424-byte journal and child-only payload avoid own-proof/body/image
hash cycles. The selected guest now executes both genuine owner-local proofs
in 107,317,810 user cycles. A real CUDA Succinct receipt takes 408.730 seconds;
same-claim Groth16 compression takes 4.436 seconds. Independent CPU verification
and the actual immutable W native Full/all-engine transaction pass. The
transaction charges 18,508,000 sompi and changes reserve 4,000,000,000 ->
3,981,492,000. Each owner sends a net 10-KAS invoice to the other and retains
private change. Five coherent unchanged-proof body mutants reject. See
[actual native results](settlement/genuine-native-01/RESULTS.json) and
[fee/prover evidence](fees/RESULTS.md).

The first native proof converter rejected genuine SDK G2 bytes because it
treated raw SDK coordinates as Arkworks affine serialization flags. The
retained failure and corrected strict canonical-field/curve/subgroup checks
are independently reviewed; the guest/image/receipt did not change.

A reviewed whole-private-input source bound is 14,957,286 units, including the
P2SH prelude/hash/dispatch. It supports selecting budget 1500 for fresh private
fallback quotes/authorizations/proofs; aggregate budget stays 1600. This saves
1,000,000 sompi per private exit at reference 100. Historical direct transactions
may use any canonical protocol u16 budget and must pass fresh native Full;
an optimizer preference must not reject another owner's valid history.
Both cold owners now recover two current claims from their own original
backup and make a genuine same-profile two-real-input no-append exit. Final
recognition-only restores use no PK or proof-generation worker; public
verification software remains required. Each original backup recognizes
three historical claims, all three spent, zero remaining claims and its exact
seed-controlled native payout, with zero unresolved payout groups. Each
proof-generation run uses the exact 64-file runtime restored over HTTPS plus
the current 1.308 GB PK,
with original source/runtime/PK/controller paths absent. The initial public
case/prestate match downloaded bytes; the second owner also receives the first
new exit as supplied local public history. Neither uses the other backup,
a saved owner map, a coordinator prover or outer proving assets. Continued
public-history availability remains an assumption.

The first native Full/all-engine exit pays 1,973,722,800 sompi, charges 17,023,200
and preserves 1,990,746,000 reserve. The second pays 1,973,765,100, charges 16,980,900
and reaches zero reserve. Actual native meters are 14,892,683 and 14,827,573
units, both below the selected 15,009,999 allowance. All four current claims are
consumed. The [independent ordered public join](settlement/exit-continuity-01/RESULTS.json)
rechecks both current-key proofs, physical continuity, NF counts 5 -> 7 -> 9,
unchanged CM cursor 6, nine rejecting typed controls and exact closure:

```text
4,000,000,000 constructed source reserve
= 3,947,487,900 native payouts
+    18,508,000 shared-settlement fee
+    17,023,200 first private-exit fee
+    16,980,900 terminal private-exit fee
+             0 remaining reserve
```

This is 2.625605% of the two declared net 10-KAS payments, before unperformed
entry costs. The two actors cross-pay in a synthetic workload; this is not
independent economic demand, a 2% qualification or confirmed testnet payout.

Even ideal N2 cooperative verification
plus independent private exits costs 2.25% of two useful 10-KAS payments at
reference rate 100 before overhead. Low-demand fees remain an architectural
limitation, not something additional proving CPU erases.

Larger-N estimates do not price arbitrary independent transfers. The actual
cross-payment pattern lets each actor combine its own incoming payment and
sender change in one private exit. Disjoint payer/recipient sets with the
current positive-change policy can require 2N private exits for N payments.
Their independent-exit verification alone has the existing 2.95% lower bound
per 10 KAS at reference 100, before any aggregate/entry cost. Leaving sender
change unwithdrawn is not complete closure. See the corrected, explicitly
conditional [larger-batch sizing addendum](fees/LARGER-BATCH-SIZING-ADDENDUM-01.json)
for selected-testnet transient-mass normalization and ownership assumptions;
no N8/N16 profile or qualification is implemented.
The existing relation permits zero-valued dummy output, while the current
payment client requires positive sender change. A separately selected
zero-change wallet/funding arm could remove that extra liability when inputs
exactly cover the payment and fees. It still needs exact quote/funding closure,
backup recovery and deposit-linkage review; this arm has not been implemented
or proved and does not resolve the privacy failure.

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
Eight new public observer control groups and eleven integer/certificate cases
retain those failures. Review also found a missing outgoing-invoice recipient
fact in the new observer. Its frozen RED source/result and corrected GREEN
source/result are both published; the old 96-view study remains unchanged.
Actual new child bytes preserve output/cipher partitions. The synthetic
two-actor cross-payment case supplies no unknown third-party privacy score.

An established Litecoin MWEB component now executes two independent senders,
public-only aggregation, production transaction validation, two independently
held recipient keys, receive/spend recovery and exact public parent-output
joins. Duplicate/drop-output/bad-proof/bad-signature controls reject. This is
an upstream component experiment, not native-KAS integration. Preaggregation
knowledge and public spent-output IDs remain explicit privacy differences.

## Remaining completion gates

- A complete fee route meeting the original 2% target under independent
  demand, including entry and unilateral exits; the currentN2 route fails.
- A changed, implemented privacy design that survives the full declared
  observer and original qualification gates; component aggregation is not enough.
- Separately controlled public recovery copies with stated retention and
  repeated loss/retrieval evidence, plus accepted-head/reorg reconciliation.
- A fresh fundable testnet profile, strict two-owner GN2 bootstrap, owner-local
  ordinary funding signatures and accepted-W history/current-head reconciliation,
  followed by rehearsal through every confirmed terminal payout. The public
  canary remains DO NOT FUND. See the source-reviewed
  [testnet readiness design](testnet-next/DESIGN-READINESS.md). Routine failed
  trials use a fresh one-command identity on the reviewed financial profile;
  failure alone does not require a new setup.

The source-reviewed [privacy decision](privacy-next/DECISION-NEXT.md) selects
owner-private construction/binding feasibility as the next pre-code test.
Neither a larger heldout draw nor removing public partitions only from the
chain observer can meet the declared strong observer while participant
transcripts still reveal them.
