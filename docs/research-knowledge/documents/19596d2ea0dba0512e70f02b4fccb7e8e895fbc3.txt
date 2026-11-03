# RFC-0013: One current-version native-KAS payment lifecycle

**Status:** Accepted — bounded offline integration scope implemented and tested;
not protocol adoption or live-wallet qualification. Decisions:
[ADR-0028](../adr/0028-public-funding-replay.md) and
[ADR-0029](../adr/0029-own-key-admission-and-recovery.md), with the bounded
key-separation follow-up in [ADR-0030](../adr/0030-separate-funding-and-exit-keys.md).

**Date:** 2026-10-20

**Requirements:** [RFC-0012](0012-useful-privacy-requirements.md).
Starting code/evidence checkpoint: `a869d16`.

## Problem and scope

The current v6 relation supports admission, two-input spending, private change and
native withdrawal. Its live experiment creates four wallets together, fixes their
funding inputs in a public descriptor and settles precomputed exit authorizations.
Older compact recovery discovers payments from a pre-payment backup, but is not
v6 recovery. Combining their reports is not one working lifecycle.

Milestone 2 must integrate one version's identity, public history, local keys,
receipt acceptance, proving and settlement. A previously unknown participant
must join, receive, spend and exit without editing the pool's participant list
or receiving private controller state. No protocol, backing or privacy guarantee
is inferred from these integration changes.

The [source/reuse review](../../research/shielded-kas-lifecycle-integration-2026-10-20.md)
compares current upstream wallet work with local H7/v6. Reuse contracts and checks,
not another relation's proofs, parameter identities or backup formats. The
[mature-protocol review](../../research/shielded-kas-privacy-requirements-2026-10-20.md)
remains applicable to recipient spendability, historical roots and query leakage.

## Candidate lifecycle and ownership of each obligation

### Native key separation follow-up

The [address-reuse finding](../../poc/shared-pool/ADDRESS-REUSE.md) warrants a
wallet-only change: fresh v2 backups use `KPI/funding-key/v1` for funding and
retain `KPI/payout-key/v2` for exits. Explicit v1 backups preserve both historical
paths without migration. The original backup must recover incoming notes and
both key purposes; no extra secret or index sidecar is required. Unsupported
version/profile pairs and v2 funding from its exit-purpose script reject.
The [frozen offline retest](../../poc/shared-pool/ADDRESS-KEY-SEPARATION.md) passes
ten genuine proofs across two fresh-v2 cases and one genuine old-CLI-created v1
case. All restore the original backup, exit and spend the native payout. V2
removes the script-equality link and its conditional disclosure in the unchanged
observer; v1 remains recoverable and retains the leak. Earlier results continue
to describe their original candidate. This does not close the broader privacy gate.

### Lifecycle obligations

This table records the starting gaps. The outcome below identifies those tested
by the bounded offline integration; broader obligations remain open.

| Boundary | Candidate interface and data | Starting integration gap |
| --- | --- | --- |
| Pool identity | Authenticated descriptor: TN10/genesis, domain, exact VK identity, initial commitment/value and founding transaction identity. | Current descriptor also lists all four funding sources. Separate pool identity from participant discovery. |
| User identity | Existing local `Wallet` spending/viewing/native secrets and public `Receive` data. | General v6 local-key/backup/address interface, overwrite protection and authenticated recipient exchange. |
| Accepted history | Independently acquired reserve lineage plus actual public funding-parent transactions; exact state reconstruction. | General funding resolution, source availability outside the discovery window and current-head authentication. |
| Admission | User chooses its own unspent native P2PK funding input and proves the existing ADMIT statement. | A new funding outpoint needs a new proof/signature under the same relation, not researcher preparation or a new setup. |
| Receipt | Local decryption, canonical commitment/domain/ownership/range checks, accepted membership and current spentness. | General v6 scanning and deterministic rejection before displaying spendable value. A ciphertext hash does not prove correct encryption. |
| Payment/change | Locally selected real notes, authenticated membership paths, existing private relation and locally verified proof. | Extract user-oriented proving from the scripted harness; preserve exact amount/fee semantics and real/padded distinctions. |
| Settlement/exit | Current reserve lineage and nullifier state, exact authorized fee/payout, native script validation and accepted payout reconciliation. | Retry, fee repricing and rollback; a saved proof is an optional private capability, not the only recovery entitlement. |
| Restore | Backup predating receipt plus authenticated public descriptor/parameters/history/ciphertexts. | Current-version first discovery and proof after service loss. Initial-note randomness must remain in the initial depositor's documented backup where needed. |

Public replay returns public state and validated transaction/ciphertext records.
It does not receive private notes, keys or proving parameters. Private proving
consumes authenticated public data locally. Broadcast and chain acceptance remain
distinct from local validity.

The founding output alone is not admission-ready: the initial owner must complete
the singleton bootstrap once before ADMIT is permitted. An unavailable or malformed
initial opening prevents opening that pool to others. After valid bootstrap, later
participants must not require further founder cooperation.

## Invariant and enforcement map

This map locates obligations; it is not a proof that all implementations meet them.

| Invariant | Existing enforcement/reference | Integration or review obligation |
| --- | --- | --- |
| I-1 Backing | [Circuit](../../poc/shared-pool/src/two_input/circuit.rs), [covenant](../../poc/shared-pool/src/two_input/covenant.rs), actual native inputs/outputs and singleton bootstrap. | Validate actual founding/admission inputs and all state successors; account for unpaid claims until accepted payout. |
| I-2 Conservation | Integer ranges and private input/output/payout/fee equality in the relation; native checked arithmetic in [settle](../../poc/shared-pool/src/two_input/mod.rs). | Keep sompi canonical at every API; replay must not synthesize funding values from proof declarations. |
| I-3 Authorization | Input ownership secret, positioned nullifiers and funding signature. | Local key custody and authenticated receive/payout destinations; public commitments never confer spending authority. |
| I-4 Single spend | Current nullifier insertions in [tree](../../poc/shared-pool/src/two_input/tree.rs)/covenant and native outpoint consumption. | Track external funding outpoints, including the founding input, independently of any participant roster. Saved/fresh capabilities consume the same claim. |
| I-5 Proof soundness | Native verifier plus statement/VK binding. | Preserve exact relation/VK identity; single-party setup and independent cryptographic review remain open. |
| I-6 State binding | Domain, allowed historical root and current settlement lineage. | Authenticate pool identity/current accepted view and reject wrong roots, pool, version, broken lineage and replay. |
| I-7 Withdrawal safety | Authorized native debit/payout script, successor reconstruction and native validation. | Payout observation/reconciliation, including terminal exit. No public replay summary alone authorizes release. |
| I-8 No privileged confiscation | No privileged reserve-spending key in the candidate. | Replaceable providers; no descriptor-edit/signature dependency for later participants or exits. |
| I-9 Safety before liveness | Reject malformed/missing/unverifiable state. | Missing data must not substitute guessed witnesses or erase liabilities. Safe rejection is not successful recovery. |
| I-10 Recoverability | [Older recovery contract](../../poc/shared-pool/src/compact/recovery.rs). | Port obligations to v6; prove recovery from a pre-payment backup with independent public data. Old evidence is not inherited. |
| I-11 Reproducibility | Exact public state/transaction reconstruction and native replay. | Deterministic accepted-lineage interpretation; canonical body IDs; independent sources/implementations remain separate evidence. |
| I-12 Reserve isolation | Funding/payout accounting and covenant-controlled reserve. | Keep developer assets, service subsidies and reserve liabilities separate. |
| I-13 Upgrade authority | Existing instances are immutable and version-bound. | New public transport format is not proof/pool migration or an admin upgrade path. |
| I-14 Recipient spendability | [Wallet decryption/ownership checks](../../poc/shared-pool/src/protocol.rs), valid relation and accepted state. | Scanning must validate all necessary spend conditions before credit; malformed or withheld delivery is rejected. |
| I-15 Deterministic rejection | Strict encodings, native execution, root/nullifier checks. | Malformed parent, altered context, duplicate funding, missing history and unsupported metadata reject explicitly. |
| I-16 Scoped privacy claims | [Accepted requirements](0012-useful-privacy-requirements.md), [threat model](../../THREAT-MODEL.md). | Preserve full public transcript and infrastructure observations; more accepted depositors are not anonymity evidence. |

### Backing argument to preserve

Start from the actual native reserve and the singleton bootstrap checks that bind
the first consumed note's value to it. For ADMIT, only the value of the actual
signed external input may create new private liabilities, less explicit fees.
For SPEND/DRAIN, the relation conserves private input value into new notes, public
payout and authorized fee; the covenant binds that statement to the actual native
successor/payout. Current nullifiers prevent consuming a private liability twice.

A saved exit is another authorization for an existing claim, not an additional
liability. A submitted but unaccepted transaction does not settle the accounting.
Replay/reorg handling must restore the matching accepted state. Final drainage
depends on authorized value, not padded note/nullifier counts. This is a conditional
argument requiring correct bootstrap, cryptographic soundness and native validation;
the integration tests are not an independent proof of it.

## First bounded slice: public funding discovery and replay

Implement an additive offline replay path for the unchanged v6 relation:

1. A versioned public descriptor has no participant list. Pin network/genesis,
   domain, VK identity, initial commitment/value and founding transaction identity.
   Users must authenticate the descriptor; its format is not its trust source.
2. Supply the ordered pool lineage and separately obtained actual public
   funding-parent bodies. Resolve each consumed founding/admission outpoint from
   those bodies. Verify canonical IDs, indices, exact values/scripts and supported
   metadata; never substitute an authorization's self-declared UTXO.
3. Track consumed external outpoints and validate native scripts/signatures of
   the founding and pool-lineage transactions using resolved contexts, along with
   successor reconstruction, reserve/nullifier state and terminal behavior.
   Return public state, reserve, fees/accounting and validated public records.
4. Replay retained genuine v6 traces using only public data, with later admission
   inputs absent from the descriptor. Preserve original artifacts byte-for-byte.

A matching parent body does not establish its chain acceptance, current
spendability or the absence of a spend elsewhere. This first offline component
assumes an externally authenticated accepted-chain view. A caller cannot turn a
JSON `accepted` flag or a self-computed hash into that evidence. New-admission
construction still needs an independently established current spendable UTXO.
This component does not recursively validate the funding parents' input ancestry;
their acceptance remains part of the external chain-view assumption.

Initially support the existing strict ordinary native funding-parent envelope;
reject unsupported versions/subnetworks, coinbase or covenant-bearing parents
rather than relabeling their outputs ordinary. Broader parent support requires
explicit parsing/metadata tests. A parent older than the live discovery window
must be available from retained authenticated data; absence fails, and general
pruned-node retrieval is not claimed.

Do not change the old live runner, saved capability/descriptor hashes, circuit,
covenant, parameters or historical evidence in this slice. It produces no new
proof and broadcasts nothing. It establishes a component needed for arbitrary
admission, not a newly funded participant or complete wallet.

## Alternatives and decision criteria

- **Extend the four-person fixture:** cheap, but repeats researcher-preallocated
  participation and does not close the M2 gate.
- **Generalize public replay first:** selected first slice. Removes the descriptor
  dependency while retaining native funding evidence and a narrow test surface.
- **Import another wallet/runtime wholesale:** mature upstream contracts are useful,
  but their different relation/state/permission assumptions do not transfer to v6.
- **Redesign the relation or batch now:** M1's fee target warrants investigation,
  but does not require that decision before exposing integration obligations.

Success for this slice is unchanged genuine proofs and identical reconstructed
state/accounting through terminal payout with a roster-free descriptor. Negative
cases must reject missing/altered funding, wrong output index/value/script,
duplicate funding use, coinbase/covenant disguise, damaged funding signature,
wrong VK/pool and broken lineage. Irrelevant parent bodies must not change state.
Record which checks are isolated controls versus complete accepted-chain replay.

Any accepted unsupported funding, bypassed native validation or requirement for
another party's secret fails the slice. Unsupported valid parent formats are
coverage gaps, not evidence that native KAS itself forbids admission.

## Milestone 2 exit gate and later work

### Second slice: own-key admission and recovery

[ADR-0029](../adr/0029-own-key-admission-and-recovery.md) scopes the authorized
offline continuation after `fa1dcf1`. A versioned private backup pins the public
pool and exact proving parameters and retains the wallet's three existing keys.
Only the founder needs its initial note opening. Later notes must be recoverable
from public encrypted ADMIT/SPEND outputs and position-bound spentness.

The wallet must rebuild validated public history against a separately supplied
expected endpoint before scanning or proving. An expected endpoint is an external
trust input, not chain acceptance established by this offline component. Admission
uses an actual supported funding parent and the participant's native signature;
payment/change and exit use locally recovered owned unspent notes.

The decisive local trace creates a new participant after bootstrap, seals its
backup before admission, admits funds, receives while offline, restores, spends
two recovered inputs into payment/change, and restores again to withdraw the
change through terminal drainage. Six fresh proofs use the existing v6 parameters;
synthetic funding ancestry and no new chain acceptance are explicit. The ADR
defines exact amounts, accounting and negative controls before execution.

### Full integration gate

After this first slice, connect current-version local key/backup, new ADMIT proving,
recipient scanning, ordinary spend/change and independent exit to the same public
state interface. The decisive integrated trace is an unknown participant joining
after creation and valid bootstrap, receiving while offline, restoring from a prior
backup, spending recovered value and fully withdrawing after the original
controller disappears.

No participant-list edit, exported plaintext note or saved exit may be required.
That trace, invariant mapping and explicit trust boundaries close milestone 2's
integration gate. Privacy, independent cryptographic review, broad recovery,
fee/contention qualification and performance remain separate milestones. Any live
trial requires its own scope and complete rehearsal through terminal payout.

## Outcome

The first offline slice passes its bounded checks: both retained genuine histories
replay exactly without a descriptor participant roster, all 15 focused tests pass,
and both CLI modes reproduce state/accounting through drainage. The
[result and reproduction commands](../../poc/shared-pool/PUBLIC-REPLAY.md) separate
historical replay from isolated rejection controls and record the external
chain-view assumption. No new proofs or funded transactions were used.

The [own-key lifecycle result](../../poc/shared-pool/WALLET-LIFECYCLE.md) now closes
milestone 2's bounded offline integration gate. A wallet initialized after valid
bootstrap admits with its own funding key, receives offline, restores from its
original backup, spends two recovered notes into payment/change, restores again,
and generates a fresh terminal exit. No descriptor edit, plaintext-note export
or saved exit is required. Six positive proofs reconcile 32 = 29.6 native payouts
plus 2.4 pool fees plus zero reserve. The restored native key also signs a locally
valid spend of the terminal payout using the known derivation index.

Fourteen wallet tests, fifteen replay tests and nine integration controls pass.
A seventh genuine proof on a separate fork demonstrates that an unusable delivery
neither credits value nor prevents preparation of an existing valid claim.
The executed source/binary identities and both public lineages are retained.

These are native-validated synthetic histories with a driver-supplied expected
head and same-host isolation. Live arbitrary admission, authenticated current
accepted history, independently surviving public data, general/native coin
discovery, cryptographic assurance and privacy remain open. Observed fees and
proving/load times do not satisfy all adopted targets. This outcome closes an
integration gate, not those separate qualification gates.
