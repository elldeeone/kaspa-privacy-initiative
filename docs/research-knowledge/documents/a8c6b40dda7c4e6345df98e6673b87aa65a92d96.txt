# ADR-0065: Private input admission and authorization through the existing MPC

**Date:** 2026-10-25 UTC. **Status:** Accepted for a research prototype and fresh
TN10 rehearsal; financial privacy is not qualified.

**Baseline:** `2e56d8a10fde5c998dde3bac3c7070c9d36f6827`.
**RFC:** [0028](../rfc/0028-sender-private-native-kas.md).
**Sources:** [current primary-source review](../../research/next-session/sender-private-lifecycle/SOURCES.md).

## Problem

ADR-0064 completed backing, repeated payments, original-seed recovery and nine
confirmed native exits. Its output mixer does not hide input ownership.
`READY` associates a persistent participant label with NF/CV; public assembly
keeps that roster order, and finalization receives owner-associated proof files.
The ordinary funding helper also emits the participant label. Removing that
marker or rearranging inputs after the coordinator sees them is insufficient.

## Decision

Amend the **off-chain client/construction protocol**, retaining the exact
existing financial domain, relation, proving/verifying keys, guest, native tail
and financial state/effects checks. Use a fresh trial, pool, seeds, sessions and
construction-program version. Existing terminal pools, backups and evidence are
unchanged. This is not a new cryptographic domain or a reinterpretation of old
proofs. Same-domain replay separation relies on the existing verified binding
to current reserve outpoint, complete effects, session and state.

Select two uses of the existing stock malicious-secure MASCOT implementation
and random-key oblivious Batcher sorting construction:

1. Each owner privately inputs its **96-byte NF/CV**, two complete 520-byte
   output tuples and blinding aggregate. Joint computation independently
   permutes the three inputs and six outputs, opening only both complete lists
   and the aggregate. No participant-to-NF/CV `READY` enters public assembly.
2. Owners validate the identical final projection against their own checked
   MPC result and exact approved effects. Each locates its unique NF/CV
   privately and proves the existing Spend statement.
3. Each privately inputs **224 bytes: NF/CV plus its 128-byte Spend proof** to a
   second independent MPC permutation. Public finalization receives three
   shuffled authorization rows, matches a strict NF/CV bijection to the frozen
   projection, derives each exact statement and verifies every proof. It never
   receives a proof in an owner-labelled slot.

Both phases compile one selected `kpx9_admission.mpc` source with stage
`admit|authorize`. The existing session `program_source_sha256` is that actual
source hash, not a bundle hash. Prepared closure binds source, codec, stage and
session; admission uses zero effects, authorization the exact final effects
digest. Do not introduce a new financial session schema for this amendment.

Reuse the canonical 31-byte limb encoding and the selected field Q. The first
private input has 39 limbs (3,003 fixed-width decimal bytes); the second has
eight limbs (616 bytes). Reject nonzero padding, malformed encodings, duplicate
rows, missing rows, inconsistent projections and incomplete/MAC-failed engine
runs. Random keys and permutations are independent between each list and phase;
key collisions abort without opening a partial result. Do not silently switch
to a different shuffle API or weaken the selected MPC checks.

Public session rosters contain fresh round aliases rather than backup
participant labels. Reuse the pinned recipient HMAC derivation with alias
domain `SHA256(KPX9AL01 || financial_domain || public_round_id)`, separate
eight-byte role `ROUNDAL\0` and index zero. The public round ID precedes the
session hash; no spend/nullifier/native secret is exported or reused as an
alias. Honest scheduling supplies fresh round IDs. Repeating one repeats that
owner's alias, so this is not protection against active retry coordination.
The funding harness omits the old participant marker. Private invoice exchange
uses the current local alias/party context. Seed recovery uses the existing
domain-stable delivery key to decrypt each complete output, then checks receipt
indices against **all public candidate PAYMENT/CHANGE invoice indices** for
each recorded session. It needs neither a saved alias-to-owner map nor rewritten
backup. No new key-derivation primitive is selected.

## Assumptions and claim boundary

- The coordinator may record public chain data, all public session/assembly
  packets, party endpoints, completion signals, sizes and timing. It knows
  cohort membership. A participant may also disclose its own private data.
- Input-attribution ambiguity requires **at least two honest eligible owners**.
  In a three-owner round, coordinator plus one colluder leaves two honest
  candidates. Two colluders identify the final owner by elimination even with
  ideal MPC. No stronger claim is selected.
- The existing MASCOT assumptions, correct selected software, checked output,
  wallet custody and financial proof/setup assumptions remain. Same-host
  namespaces do not protect against the host administrator. Independent
  physical/operator custody is a separate availability/administration gate.
- No anonymity against a global traffic observer, active endpoint correlation,
  amount/fee arithmetic, sparse ancestry, repeated-use intersection or selective
  abort is inferred from removing direct labels. Measure these separately.

**Known unresolved active attack:** phase one opens stable nullifiers before
settlement. A coordinator/colluder can abort and retry an overlapping cohort,
then intersect nullifier sets with known endpoint membership to attribute an
honest owner. Fresh aliases do not hide membership from that coordinator.
Two honest owners in each individual round do not prevent this cross-round
attack. An unpublished attempt lock is not a seed-recoverable remedy. Initial
positive claims are therefore limited to the frozen passive/honest-scheduling
observer, with active abort/retry intersection retained as an expected failure.
The [completed bounded MPC wire diagnostic](../../research/next-session/sender-private-lifecycle/review/ACTIVE-RETRY-EXPERIMENT-RECORD.md)
reports 3/3 owner-verified unique predictions after a changed known cohort and
0/2 after a same-cohort retry. This confirms the admission-channel failure in
that fixture; no mitigation or financial privacy qualification follows.

## Alternatives

| Candidate | Decision and reason |
| --- | --- |
| Existing MPC for inputs and authorization | Select first: reuses the existing engine and financial relation and addresses both direct disclosure stages. The new composition still requires review and measurement. |
| WabiSabi-style anonymous credential admission | Defer: established credential techniques can separate registrations, but require an additional issuance/presentation protocol, anti-replay accounting and network model. They do not automatically hide this KAS input from its submitting endpoint. |
| Anonymous transport alone | Insufficient for the selected defect: an explicit participant/NF/CV packet or fixed owner proof slot discloses linkage through any transport. Transport remains a separate observer/operational requirement. |
| Remove only funding marker or publicly shuffle READY | Reject as a privacy fix: persistent public ordering and coordinator knowledge survive. |
| New financial relation/domain or vProgs migration | Not required by the inspected off-chain change. Reconsider only if a demonstrated state, binding or cost requirement cannot be met; no general conclusion about future vProgs usefulness follows. |

## Safety and completion

Preserve all `SECURITY-INVARIANTS.md` invariants. In particular, changing input
order must not change input membership, output inclusion, integer conservation,
nullifier uniqueness, state roots, native reserve/successor policy or withdrawal
authorization. Proofs authorize the entire exact effect projection, not merely a
mixed list. Failure or censorship may abort a round; it cannot release funds or
remove the existing independent-exit path.

Acceptance requires an adversarial second pass, genuine MPC/proof execution,
the prospectively frozen observer study in RFC-0028, repeated received-note and
change spending, original-seed recovery, loss of original services, all actual
TN10 payouts confirmed, zero terminal reserve and honest all-in fee accounting.
Operational checks alone do not qualify privacy. A negative privacy or fee
result remains a negative result; do not retune the old trial or relabel it.
