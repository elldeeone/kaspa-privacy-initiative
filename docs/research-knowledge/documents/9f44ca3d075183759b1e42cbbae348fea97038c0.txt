# Closed-outbox accounting delta (synthetic, offline)

Frozen before model execution, 2026-10-26 UTC. No native architecture is selected.
No wallet, key, private input, network, proof, GPU, native Script or live profile
is used or changed.

## Scope decision and reuse

ADR-0039 already authorizes finite ideal-oracle liability/service-loss models,
independent accounting, exhaustive exploration, reorgs and negative mutants.
This experiment is within that scope. It does not create a new protocol
subsystem or select the Outbox proposal. No new architecture ADR is needed for
this abstract comparison; native ticket creation, new consent/profile/codecs,
or covenant implementation would require the separate proposed/reviewed ADR.

The existing model and its closed report already explored 128 configurations,
shared/native-output delivery, transfers, fee rises, stable identities, service
loss and rollback. Those results are retained and are not rerun here. Reuse its
ideal authenticated-acceptance premise and independent per-origin ledger idea.
The new delta is **explicit private reserve versus separately funded outbox**,
one atomic two-owner conversion with per-owner settlement fees, and an unchanged
third private note that retains an independent direct-exit obligation. The old
model kept shared-entitlement backing in one reserve and used abstract units.
This model uses exclusively synthetic integer sompi, without economic claims.

Source memos inspected: RFC-0019; ADR-0039; Outbox, asynchronous batching and native
verification-cost memos; existing model README/model/oracle and closed report.
Their pinned established-design comparison is reused. No new crypto, note
format, key derivation, wallet scanner, proof relation or native exit is built.
Exact read identities will be recorded in SOURCE-PINS-01.json.

## Frozen finite domain

- Exactly three public synthetic full notes: NF0 owned by A, value 3 sompi;
  NF1 owned by B, value 5; NF2 owned by A, value 7. These tiny values deliberately
  expose boundary failures; they are not viable native transaction amounts.
- Eight initial cases: each conversion settlement fee independently 0 or 1;
  both ticket claims have an exact owner-approved fee of either 1 or 2.
  The separate direct-exit fee is exactly 2 for every note. No external input,
  subsidy, rent credit, resident balance or fee discretion exists.
- One checkpoint consumes NF0 and NF1 atomically, and no others, creating a
  closed immutable two-ticket batch. Gross ticket_i = note_i - settlement_fee_i.
  Tickets are nontransferable, bound to the original owner/destination. NF2
  remains private until its separately authorized direct exit.
- Stable economic IDs are (synthetic chain, pool, NF). They do not depend on
  batch ordering, entitlement-root identity, paid root, outpoint or reorg.
  Immutable entitlement root authenticates both complete records; each claim
  changes the current paid-state root and current outbox point. Old ticket
  membership does not authorize historical paid state. Foreign/remapped roots
  and orphan checkpoint references reject. No root extension is adopted.
- Four availability bits: checkpoint service, public current data, retained
  current witnesses, independent direct prover. Keys are ideal and retained.
  Data means public OR retained. The modeled minimum fee for claim/direct
  redemption is 1, 2 or 3, monotone in real time. Thus exactly 48 environment
  products per financial state. Checkpoint fees are accounting allocations;
  checkpoint fee admission is deliberately not modeled. Zero settlement fee is
  an accounting boundary, without a native fee-admissibility implication.
- At most one rollback to any proper accepted financial ancestor, including
  before conversion or after the first claim. Restore private reserve, escrow,
  NF, entitlements, paid state, fees and native payout observations together.
  Previously observed conversion, disappearing services/data/prover and raised
  fee quotes persist. Replacement branch points are distinct even at equal
  balances/height. Orphan artifacts supply no accepted authority.
- All amounts and arithmetic use exact integers, 0..2^64-1, with checked sums,
  subtraction and strictly positive payout. Boolean, negative, oversized,
  noninteger amounts and overflow reject. Boundary probes include 0, MAX and
  MAX+1; MAX is a valid model uint rejected as the wrong principal, rather than
  a malformed uint. MAX is not a selected Kaspa monetary-supply limit.

## Accounting and ideal authority

Conversion separately requires each owner's exact original NF, gross amount,
destination and settlement fee consent, then consumes both current NFs and the
real current private point. A duplicate NF, prior direct Exit or stale point
rejects the whole conversion. A pending proposal changes nothing.

For conversion: private reserve decreases by both complete note values;
escrow increases by both gross tickets; only settlement fees leave total user
backing. For a claim: escrow and unpaid gross liabilities decrease by the same
gross amount; owner payout plus exact claim fee equals gross. A direct Exit
decreases private reserve by its complete note value and consumes the same NF
that conversion would use. It requires ideal owner authorization and an
independent prover/data, even when the checkpoint service has disappeared.

An independent origin ledger records private/ticket/paid rights, owner payouts
and the three fee categories. Candidate guards never read that ledger. It must
agree with exact private backing, funded escrow, every unpaid ticket and owner
destination; totals must conserve the initial 15 sompi. A terminal private
reserve of zero does not retire or release an unpaid outbox.

Proof validity, native accepted lineage, signatures, membership, checkpoint
consent and public witness reconstruction are explicit ideal predicates. This
model does not demonstrate any of them for a concrete implementation.
In particular, retained CURRENT witnesses at each evaluated state are an
availability oracle. Environment-product enumeration does not prove physically
reachable witness-refresh histories: B cannot be inferred able to refresh after
A claims while all update data is unavailable. Missing current data/witnesses
remains a liveness failure, even if an old static path was retained.

## Expected results, frozen before execution

Correct model: no conservation, authorization, NF-exclusion, identity or backing
violation in a fully exhausted graph. Both A-then-B and B-then-A claims complete
when exact fees cover the environment quote and payout is positive, even with
service/prover absent; the other leaf, paid marker and backing survive.
NF2 remains backed after conversion and can direct-exit before or after claims.
Direct Exit versus conversion accepts at most one use of each original NF.

Expected liveness failures remain failures: preconversion service loss creates
no cheap ticket; direct fallback still needs independent prover/data and its
fee. Missing all current data strands a shared claim. An exact claim fee below
the new minimum, or gross equal to its fee, leaves a fully backed unpaid
liability. Service loss alone does not strand an accepted viable ticket.
Rollback restores unpaid rights and their backing; knowledge/losses/quotes do
not roll back. There is no unconditional liveness or cheap-fallback claim.

Required unsafe mutants and independent expected discriminator:

| Mutation | Required counterexample |
| --- | --- |
| omit conversion NF | Direct Exit and conversion reuse one origin |
| omit funded escrow | Unpaid entitlement lacks its backing |
| drop one ticket record | Independent unpaid right remains unrepresented |
| charge settlement fee twice | Private reserve/total conservation mismatch |
| global-only owner fee sum | Same sum redistributes fees without owner consent |
| omit paid marker | Accepted claim remains redeemable |
| root-local paid identity | Paid-root change resets the same economic ticket |
| historical paid state | Old unspent view repays a paid ticket |
| overwrite paid state | Second claim erases the first owner's paid marker |
| wrong destination | Owner's native proceeds redirected |
| wrong gross amount | Claim withdraws a different principal |
| service-dependent claim | Viable accepted right stranded by service loss |

The run must also directly exercise malformed amounts, duplicate conversion NF,
wrong signer/domain/role, stale private/outbox points, changed owner fee, wrong
root, paid replay, orphan references and unrelated original-note replay.

## Search and stop rules

Explore every reachable financial state, including the one-rollback branch,
without depth, state-count, time or sampling truncation. For every state evaluate
all 48 environments. This factorization is exact: environment losses only
disable actions, and every product state is reachable by applying losses after
its fully available financial prefix. Quote changes never alter an existing
owner fee. Rollback leaves the selected environment unchanged. The correct
graph has finitely many accepted financial events: at most four before and
four after its sole rollback; malformed/rejected proposals create no state.

Stop a correct run immediately on any independent safety/authorization mismatch
and preserve the trace. Stop each mutant at its first discriminating safety or
liveness counterexample; never label mutant search exhaustive. An interrupted
or resource-limited correct search is incomplete, with no pass claim. Do not
adjust amounts, expectations or guard rules after results to rescue a case.
Perform Root's small independent source review before execution and retain its
findings, exact source freeze and command. No historical result is relabeled.

Passing this model cannot establish proof soundness, valid checkpoint creation,
native Script/Full/relay/testnet acceptance, recovery from a real backup, fee
savings, financial privacy, production safety or the frozen 2% target.
