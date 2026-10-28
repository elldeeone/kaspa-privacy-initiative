# ADR-0077: One unresolved private attempt and permanent release history

Date: 2026-10-28 UTC.

Status: **Accepted for the bounded research design; implementation and
qualification pending.** Root accepted the design and existing-epoch minimum
policy interpretation after independent adversarial design review on
2026-10-28. This selects no financial profile or readiness result. Native
funding and broadcast remain held until the complete financial path is rehearsed.

## Problem and source boundary

[ADR-0074](0074-private-batch-construction.md) requires durable disclosure
history, private overlap admission, exact-effects preparation, and independent
Exit. The existing [SQLite release model](../../poc/local-private-payment/private_batch/release_policy.py)
uses clear synthetic member tokens; it is not a financial MPC gate. Neither
[the public trace gate](../../poc/local-private-payment/mpc-prover/trace/trace_gate_main.cpp)
nor [the current prover](../../poc/local-private-payment/mpc-prover/auth_groth16.cpp)
has durable private-history admission. Persisting old authenticated shares and
restoring them under a new MAC context would not solve that gap.

This proposal substitutes a conservative global exclusion barrier for the
unimplemented persistent secret-membership journal. Unknown exposure blocks
**every new private attempt** in that pool/service epoch. Once raw NFs have
been opened, their already-public bytes become permanent tombstones, including
after rejection, orphaning or reorg. Later candidate NFs are compared privately
against those public tombstones before disclosure. No old AuthShares, MAC-key
shares or owner witness are persisted or copied into a new protocol context.

The [same-day source review](../../research/next-session/local-private-payment/privacy-next/PRIVATE-BATCH-SOURCE-REFRESH-2026-10-28.md)
already inspects pinned Kaspa/Toccata, vProgs, Kaspa research, Orchard, Aztec,
RAILGUN, Monero and MWEB sources. Reuse their separation of authorization,
spent markers, confidential conservation and public accepted state. None of
those inspected interfaces supplies this service's unaccepted-disclosure
history. This proposal adds no cryptographic primitive or consensus rule.
It reuses SHA256, authenticated peer agreement and durable append records.

## Policy and identity decision

The existing [descriptor](../../research/next-session/local-private-payment/private-batch-2026-10-28/PROFILE-DESCRIPTOR.json)
pins service policy `ce821210834e870b6eebe3851b0b003b1b33cf343b1a17a996987f35dda514b5`
and epoch `1719a11d82194639da551cd7302ad3ea94e42a0e424962ac40719f5634d38b94`.
Its minimum restriction is `refuse-overlapping-changed-cohort-or-effects`;
its history requires persistent authenticated service state and a trusted
latest checkpoint. The proposal never permits a transition that this minimum
forbids: it additionally refuses disjoint work while an attempt is unresolved,
and refuses every previously released NF even with identical effects.

**Accepted interpretation:** this is a stricter implementation/liveness policy
within that existing epoch, with unchanged D/ProfileID, owner authorization,
financial relation and service-policy descriptor bytes. The implementation
policy/version and source closure become separately agreed job identities.
Root and independent review explicitly accepted this interpretation; the
descriptor is not edited or rehashed retroactively. If later review finds the
existing epoch promises a different permitted behavior, allocate a new
service-policy/profile identity before another financial authorization. Existing
notes or signed intents must not be relabelled as belonging to a new epoch.

This deliberately amends ADR-0074's proposed *storage mechanism*: a durable
global lock precedes owner intake and the first allowed effects-digest opening;
the exact public effects digest is then durably prepared before reactive
prover openings. It does not claim that secret membership was already stored,
or that a final proof/whole-CASE hash was known before that artifact existed.
The stronger global exclusion is what covers that otherwise unknown interval.

## Assumptions and invariant

There are exactly three authenticated servers with at most one corrupt. Each
honest server retains its own journal and authenticates an independently
maintained latest checkpoint. Three matching durable acknowledgements are
required; there is no two-party fallback. A corrupt server can halt progress
but cannot roll back the two honest histories. The checkpoint's freshness and
retention are explicit trust assumptions, not properties of a local hash chain.

The history key binds chain, pool lineage, D, ProfileID, service-policy ID and
epoch. Each attempt binds a fresh attempt ID; complete owner-job/cohort
approval; exact accepted head, roots, counts and integer reserve; model, source,
dependency, matrix, trace, layout, input-map and prefix-recipe identities;
validation policy; and the prior checkpoint plus public seen-NF-set digest.
An attempt is not identified merely by its head transaction ID.

For one history key, the invariant is:

```text
active unresolved attempts <= 1
begin new attempt => no unresolved attempt at every honest server
released NF set is monotonically increasing
candidate NF in released set => one private aggregate refusal before disclosure
resolve attempt => exact pinned candidate independently observed accepted
```

Private progress is not a prerequisite for independent cryptographic Exit.
There is no history reset, timeout release, administrator unlock, Exit-based
unlock, deposit-based unlock, changed-head unlock or reorg-based unlock.

## Phases and exposure barriers

| Durable event / state | Required transition and permitted next action |
| --- | --- |
| `READY` | Complete journal equals the authenticated latest checkpoint; all three agree the history and seen-set digest. Only a new `LOCK` may start work. |
| `LOCK` / unresolved | Every honest server appends and synchronizes the same public attempt binding, updates its external checkpoint, then acknowledges. All three matching acknowledgements precede **any owner intake**. A partial lock blocks further attempts. |
| Private intake and construction | Use fresh MASCOT/context generation. Derive the full assignment and exact NF bytes through the selected trace. Privately check all three NFs against every public tombstone. Join this result with trace checks and complete same-assignment relation/prefix validity; disclose only the selected aggregate validity result. A refusal leaves the lock unresolved. |
| `PREPARED` / unresolved | Under the already durable lock, derive/open only the allowed aggregate effects digest from the validated immutable assignment. All three durably pin that digest and the exact binding before any reactive prover group opening. Mint the sealed prepared capability only after this barrier. |
| Aggregate proof construction | Consume that exact capability once in the same MAC/context epoch and validation generation. Perform every required field/group check and independently verify the canonical aggregate proof. No raw NF/core has yet been released to a coordinator or public prover. |
| `EGRESS` / unresolved | Open the complete core to the three servers under the lock. This opening itself counts as disclosure. Parse the actual three NFs and persist them permanently together with core/effects hash, aggregate-proof hash, exact 10,685-byte projection hash, cohort/binding and attempt ID. All three durable acknowledgements precede coordinator/R0 handoff. |
| `FINAL-CANDIDATE` / unresolved | After the mandatory genuine R0 wrapper and native Full checks, durably pin one exact complete CASE, including witness, budget, entries, selected policy/image and projection. All three matching records precede submission. There is no alternate-candidate overwrite within an attempt. |
| `SETTLED` / resolved | Independently acquire and replay fresh accepted history for the exact pinned CASE under the selected node assumptions. After all three verify and durably agree that record, the next disjoint attempt may begin. All earlier NF tombstones remain. |

The final CASE hash cannot exist at `PREPARED` or the initial NF opening: the
mandatory R0 receipt/native witness is produced later using the public core.
`EGRESS` therefore pins the exact core/aggregate/projection artifact that
already exists. `FINAL-CANDIDATE` separately binds the later whole CASE. Neither
hash is substituted for the other. A transaction ID does not bind all witness
or supplied-context bytes and cannot replace either record.

MASCOT's established masked-input/multiplication traffic and ADR-0076 public
coin procedure remain their separately reviewed protocols. “Before disclosure”
here prohibits raw NF/core, secret-derived prefix and reactive prover release
outside the indicated barriers; it is not a claim that MPC performs no masked
protocol openings. No per-owner equality, residual, index, fee, delta, intent
hash or owner-to-wire correspondence is exported on refusal.

## Actual C++ capability boundary

The financial driver must not obtain permission from a JSON Boolean, Python
object, caller assertion, copied public control ticket or serialized share.
Use implementation-private constructors and immutable one-use capabilities:

1. A locked-attempt capability is constructed only after local durable `LOCK`
   and three authenticated matching acknowledgements. Owner intake requires it.
2. The selected financial construction capability owns the same immutable
   authenticated assignment, actual secret core bytes, derived prefix and NF
   mapping. The history check uses those bytes, not caller-selected NF wires.
   Compare canonical NF32 as all 256 bits (for example two range-constrained
   128-bit limbs), not an ambiguous reduction modulo Fr.
3. `PreparedEpochTicket` can be minted only by the qualified financial
   construction/history path after unseen-NF validity and `PREPARED` durability.
   Bind all attempt identities above, exact effects digest, history/seen-set,
   context address/generation/MAC epoch and validated check counter.
4. The financial proof entry consumes both the matching validated assignment
   and prepared ticket once, immediately before the first masked A/B1 release.
   No public constructor, `already_validated`/`prepared` flag or deserialization
   path can mint either capability. Abort invalidates volatile capabilities;
   it does not resolve durable history. Fresh contexts do not resurrect them.

[Trace agreement](../../poc/local-private-payment/mpc-prover/trace/trace_witness.hpp)
already precedes owner intake, and [ValidatedAssignment](../../poc/local-private-payment/mpc-prover/batched_assignment.hpp)
already binds an immutable context/model/assignment. These are integration
seams, not existing financial-history enforcement. The public-prefix SHA/toy
gates must remain explicitly nonfinancial and unable to admit a financial model
through an unticketed proof entry. The runtime/trace owners implement that
cross-module binding; `mpc-prover/history/` owns the durable history API.

## Exact settlement authority, not a success flag

The existing [native controls](../../poc/local-private-payment/private-batch-public/native/run_native_controls.py)
and [native validation adapter](../../poc/owner-private-lifecycle/integration/validation.py)
explicitly establish supplied-context Native Full/ScriptEngine results only.
Their `accepted` fields cannot resolve a lock, even when genuinely executed.

The existing [chain confirmation path](../../poc/local-private-payment/chain/confirm_pool_json.py)
compares the expected whole CASE with an acquired confirmed accepted prefix,
including witness/budget/context, and then replays the pool. Its old-profile
codec/selection cannot be applied unchanged to this new profile. No completed
new-profile chain-settlement adapter currently exists.

The required new adapter must directly run selected authenticated acquisition
and independent replay/verification over fresh public data. It must bind the
pool/service/attempt, exact prepared effects and `EGRESS` artifact, exact
`FINAL-CANDIDATE` CASE bytes/hash, all input entries and witnesses, final guest
image/journal/receipt/native policy, and observed accepted transaction/current
state. Its source/tool/node/selection and returned public-data identities are
agreed by all three servers. Imported `accepted:true`, txid-only records,
unrelated valid witnesses, cached component reports and offline Full passes
are insufficient. A generic callback returning `bool` is not this adapter.

Until that actual adapter is implemented and independently reviewed, the real
history implementation exposes **no successful financial resolve path**.
Model-only settlement fixtures must be separately named, unavailable to the
financial build and labelled as model evidence. This missing integration does
not justify an acceptance override to demonstrate sequential rounds.

## Durability, concurrency and recovery

Use one owned append-only canonical journal per history key. Every event
contains version/type, sequence, previous checkpoint, full binding/payload and
SHA256 checkpoint. Replay validates the entire state machine and seen set.
An OS advisory lock serializes concurrent local writers, but is not the durable
attempt lock: closing descriptors releases the OS lock. [Linux flock documentation](https://man7.org/linux/man-pages/man2/flock.2.html).
Append all bytes, check every write, synchronize the journal, update the trusted
checkpoint and only then acknowledge. Creation also synchronizes the parent
directory; syncing only the file does not establish directory-entry durability.
[Linux fsync documentation](https://man7.org/linux/man-pages/man2/fsync.2.html).

The small first implementation may safely refuse on a torn tail, bad sequence,
hash mismatch, synchronization error, missing anchor, path/inode substitution,
or disagreement. It must not truncate, recreate, rotate away, forget tombstones
or automatically mark an unknown attempt clean. Use canonical owned nonsymlink
paths, regular single-link files, stable open descriptors and local exclusive
writer locking. A crash between journal and external-checkpoint updates is
conservatively unavailable; it is not permission to use an older prefix.

Initialization is only for an explicitly authenticated fresh **unfunded** pool
history key. Absence of a file is not proof of freshness. Existing-epoch reopen
requires its registered history and trusted latest anchor. Recovery can restore
public journal bytes from retained replicas only after verifying the full chain
against that anchor and three-party agreement. It restores no secret/MAC state.
Loss of the required history or latest anchor refuses private progress; losing
both does not make a new empty journal authoritative. A local hash chain cannot
detect a coordinated rollback of all history and trusted freshness authority.

## Crash, race and reorg cases

| Event | Required outcome |
| --- | --- |
| Crash before any server locks | No owner intake occurred; a fresh attempt can acquire an untouched epoch. |
| One/two servers lock, then abort or disagree | No owner intake without three matching barriers. Persisted partial lock still blocks new work; no timeout/reset. |
| Crash during input, validation, digest, masked A/B1 or before core opening | Unresolved global lock survives. No old shares/context or new-attempt retry. Independent Exit remains available. |
| NF/core opens, then crash before all `EGRESS` records | Exposure is unknown/partial, so unresolved lock blocks all new private work. Missing public history is never assumed empty. |
| All `EGRESS` records persist but coordinator receives nothing | NFs remain tombstoned and lock unresolved. Callback failure does not undo exposure. |
| Native Full succeeds but submission fails or is orphaned | No accepted whole-CASE settlement; lock remains unresolved. |
| Exact candidate accepted, one server crashes before settlement agreement | No new attempt until the missing server can recover against the latest anchor and all three agree. |
| Independent Exit, deposit or another payment changes the head | Cannot resolve the old attempt. Stale financial intent fails its existing exact-head rules; new private work stays blocked. |
| Reorg before settlement observation | Refuse resolution unless the exact candidate meets the selected fresh accepted-prefix policy. |
| Reorg after genuine settlement was durably observed | Keep its historical settlement record and every released NF forever. Old notes may become financially unspent, but may only use independent Exit; no private reuse of those NFs. New attempts still require their own current exact head. No irreversible-finality claim is made. |
| Two local/coordinator attempts race or one corrupt peer equivocates | Local replay/locking plus all-three agreement admits at most one; unmatched bindings or histories halt. |
| Caller supplies a different witness with the same txid | Whole-CASE/hash mismatch refuses resolution. |

Proof obligation: before a complete released NF set is durable, any uncertainty
leaves the global lock unresolved. After it is durable, every later admission
privately rejects those NFs forever. Therefore an honest server never admits a
changed retry of a previously disclosed NF, even if its transaction is rejected
or reorged. This is a service-bound argument under the stated honest-history
assumptions, not unrestricted O-active anonymity or a SNARK-enforced property.

## Implementation and acceptance plan

Implement a small C++ durable journal/capability
library under `poc/local-private-payment/mpc-prover/history/`; do not expand the
old synthetic SQLite model into financial authority. Keep real settlement
resolution disabled until its exact new-profile adapter exists. Coordinate the
financial intake/validated-assignment/prover boundary with the runtime owner.

Required checks cover actual fsync/write failures and process crashes at every
barrier; concurrent acquisition; restart/replay; missing/rolled-back journal or
checkpoint; one corrupt peer; malformed/duplicate/noncanonical NF encodings;
private overlap/no-overlap against **the actual derived** NFs; changed model,
trace/layout/cohort/head/attempt/MAC epoch; one-use capability and bypass entry
points; torn records; fake offline acceptance; same txid/different whole CASE;
and reorg retention. Two sequential real rounds require exact accepted
settlement of round one before new disjoint admission, with all prior NFs still
privately refused. No source/unit/model test can replace that final observation.

Root must synchronize RFC-0030, architecture, open questions and threat-model
wording if this proposal is accepted. The proposal changes no invariant, native
authorization, backing, fee arithmetic, token, mainnet code or Exit condition.
Global exclusion can permanently lose private liveness. Cross-service bypass,
all-server collusion and loss/rollback of every trusted history anchor remain
privacy failures/unqualified controls; they are not solved by this journal.
