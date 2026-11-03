# ADR-0057: Matched batch proofs and portable public recovery material

**Status:** Accepted for the bounded unfunded proof/native, linkage and recovery experiments; independent design review completed.
**Date:** 2026-10-23 UTC. Base `a6fcdf1edd904dbe1bb395285230649b6c40d44c`.

## Problem and sources

ADR0055 confirms private change/repeated spending/original-backup recovery and
native test payouts, but fails the fee/privacy targets. ADR0056's whole native
screen projects1.949145625% complete costs for32 net10-KAS payments; it has no
matched financial circuit. Public parameter/history availability remains assumed.
The owner now explicitly requests genuine batch proofs, stronger linkage tests
and recovery availability. This decision extends that native-only experiment.

Reuse the exact [reviewed relation obligations](../../research/next-session/private-change/fees/CIRCUIT-OBLIGATIONS-01.md)
and [new primary-source refresh](../../research/next-session/compact-batch/SOURCES.md):
Kaspa/Toccata/vProgs/research, Orchard, Aztec, RAILGUN, Monero and MWEB. Reuse
SHA256/HMAC, BN254 Groth16, V2 key/receipt derivation and SalsaBox. No new
primitive/token/admin withdrawal/mainnet/real funds are selected.

## Relation and native decision

1. Use only the new initially unfunded [public instance](../../research/next-session/compact-batch/PUBLIC-INSTANCE-01.json),
   SHA `b3a97af8c9caea15bc793175d934e96c3f4c6f7937b7e8b25bc8c82e10bc327f`,
   D `35ee940cae12aec848a773738de04feaef80c17798a686f1d5aa808179584fd6`.
   Retain KPX4AU01/KPX2ST01 and exact ADR0056 layout. Replace only the native
   domain and actual two VK operands; preserve all old sources/instances/PKs.
2. Implement separate fixed relations compact2 (modes0/2, two output witnesses)
   and wide32 (mode32/P0,32 witnesses). Both bind complete SHA256(Auth528) as two
   exact LE128 field inputs. Installed software/manifest selects role before
   private input; no witness role field. Compact modes share one fixed matrix;
   wide has a distinct matrix/PK/VK. Compact owners never require the wide PK.
3. Enforce every memo obligation: ordered CM-array SHA, strict mode/reserved
   bytes, bounded integer alignment/cursor, all496 wide CM inequalities, current
   membership/authority, bounded input/output/aggregate values, checked u128 host
   sums, sumIn<=MAX/reserve, exact conservation and native payout/SPK/fee binding.
   Mode0 iff R'=0 zeros ALL private outputs includingrho, carries CM root/count,
   binds zero metadata and SHA256(528 zero ciphertext bytes). No private-mode host
   branch may change the matrix or disable unrelated constraints.
4. Keep original positioned real NF and actual-slot dummy HMAC unchanged across
   compact/wide/retained REVEAL. Native still checks actual outpoint/state/reserve,
   immutable continuation, both sequential NF insertions and all public tree/
   cipher/fee/payout effects. Two real input slots remain supported by relation;
   bounded wallet experiment uses one real plusdummy, no other-owner witnesses.
5. Measure finalized matrices, official FFTdomain and constraint positives/
   negatives before setup. Independently review implementation before fresh
   per-role development setups. Authenticate exact full owned PK bytes, role,
   VK and dimensions BEFORE backup/witness read. Source build identity excludes
   selected pin bytes to avoid circularity; separate compiled manifests bind them.
6. Rehearse supplied synthetic native funding/entry ->onewide32payment ->32
   original-backup compactowner exits ->R0. Every exact body needs genuine proof,
   native Full/allengines, predecessor/DAA/sparse-position links and complete fees.
   Syntheticcontexts are NOT accepted backing, confirmed payout,32humans or
   market demand. A live claim requires fresh identity/funding/ownerproofs and
   confirmed terminal testnet payout. No broadcast follows automatically.
7. Preserve32*1B useful-payment denominator, allentry/change/storage/exit costs,
   floors and exact requests. Use actual minimum official quote fee; refund any
   last-owner exit-credit surplus, never donate/clip change or count refunds as
   useful demand. Preserve old conservative149500terminaloverpay projection;
   separately measure new minfee/refund (prospective1.9486784375%, notqualified).

## Recovery decision and trust boundaries

Public-only content-addressed capsules carry descriptor/bothroleVK/manifest
identities, sparse accepted-body/context history and optional compactPK bytes.
Executable identities and independently authenticated static instance/program/
VK/role pins remain external; a capsule cannot self-authenticate authority.
A caller-pinned capsuleSHA may be an explicit bounded experiment dependency.

Preserve physical start+i and CMcursor; gaps remain CM_EMPTY, never renumbered
receipts. Replay with selected software; reconcile history with fresh selected
validating-node acceptance/currentUTXOs before spending or claiming current
balance. Timestamp/snapshot/hash is not currentness/independent consensus/finality.
Without trustworthy currentness fail closed/report incomplete, no admin rescue.

Test original operator/source/cache UNMOUNTED from fresh namespaces, original
ownbackup plus mirrored public bytes only; authrole/length/hash/VK before seed,
backup symlink/hardlink metadata guard BEFORE public hashing. Faults: missing/
truncated/corrupt/wrongrole/domain/VK, missing/reorderedhistory, stalehead/reorg.
Separate localpaths/sandboxes demonstrate portability, NOT independent providers,
long-term retention, setup honesty or independent consensus. Seeds cannot recreate
pruned encrypted receipts or the identical randomized Groth16 parameter artifact.

## Privacy measurement

Freeze observer/workload/hidden truth/thresholds/baselines/stop rules BEFORE new
corpus generation/scoring. Measure complete ingress-to-cashout source lineage,
CM-to-payout matching and value inference separately. Compare overlapping
independent payers, simultaneous/staggered demand, full independent drainage and
participant side-information; include public amounts/timing/fees/mode/framing.
A single32batch can hide permutations while exposing onepayer lineage. Arithmetic
SAT does not prove owner ambiguity/cryptographic feasibility. No fabricated
useful demand, oldcorpus rescoring, post-resultretuning or unknown-as-pass.

## Bounds, publication and resources

Selected native lifecycle is bounded CM126/NF67. Full-capacity permissionless
private exits and noappend full exits with R'>0 remain OPEN/unselected. Retain
ADMIT/REVEAL, original NFs and canonical-empty-suffix induction. Recheck actual
matched-key native lengths/masses and valid-path sourcebound; no smallerbudget
credit without bound. Safety before liveness; invariants unchanged.

Backups/private witnesses or their hashes, owner/index maps, discarded quotes/
Auth/NF alternatives stay outside Git. Main synthetic private chains default to
sanitized selected hashes/outcomes; raw publicly synthetic fixtures must be
explicit DO_NOT_FUND, note/NF-disjoint from main, and never promoted to funding.
Blind corpus truth stays separate from attacker inputs until frozen scoring.

Heavy synthesis/setup/proving serialized: up to14CPU, initially20GiB, swap0 on
24GiBhost. Other jobs use only measured remainingcapacity. Generous operational
caps/timeouts are not safety/economic qualification gates; retain/fix resource
failure without weakening relations. No paid GPU/infrastructure selected.

Independent design/source review precedes crypto implementation; second review
precedes setup. Final adversarial review covers inflation/double-spend/unauthorized
release/privacy/dependencyloss/stale/reorg/hidden trust. Tests and genuine proofs
remain implementation evidence, not soundness/production/privacy qualification.
