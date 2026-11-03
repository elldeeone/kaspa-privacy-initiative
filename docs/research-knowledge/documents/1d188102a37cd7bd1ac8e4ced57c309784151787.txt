# Finite exit-liability model (DO_NOT_FUND)

ADR-0039 authorizes this isolated symbolic experiment. It is not a wallet,
transaction builder, proof verifier or implementation of a revealing exit.
All code uses the Python standard library. No native/proof/wallet modules are
imported. Abstract units are not sompi or a measured fee quote.

## Frozen state/action schema

There are exactly128 initial configurations: three origin notes each with
value2/3 and ownerA/B, in native-P2PK or shared-root mode. Note positions are
six fixed IDs (origin0 revisions0/1, then origin1, origin2). Real positions,
commitments and nullifiers are collision-free symbols, not actual hashes.
Each original note can privately transfer once to revision1, with recipientA/B
and authorized fee0/1. Each note's NF is the SAME symbol across private spend,
accepted ticket creation and conditional reveal. No ghost phase/status can
override candidate NF checks. One accepted batch consumes1..3 resources and
creates one entitlement per source. Only normal exclusion implies at most
three entitlements; mutants are not stopped by a three-claim/phase guard.

Claims bind sourceNF,recipient,principal. A root is an injective base8 encoding
of six immutable records: absent digit0, present digit=principal+4*recipient
(principal1..3, recipient0/1). Accepted snapshots are cumulative sets sorted by
NF. Extension can move an old entitlement's leaf index, while its canonical
spent ID stays its sourceNF. Claim calls bind exact amount, recipient, root,
current predecessor and fresh paid-state. The predecessor/authority checks are
ideal symbolic predicates: native serialization, actual signatures, Merkle
hashing and proof soundness are NOT verified here. Equal-CM/different-position
notes remain distinct IDs; `(owner,value)` may coincide, but positioned NFs do
not. Malformed root/amount/recipient/context proposals are explicit.

Native-P2PK acceptance transfers principal out of the pool immediately into
owner-controlled native output escrow E. It is a completed pool withdrawal.
Later ordinary spending of E still pays a fee. Shared-root acceptance instead
keeps pending principal backed by R. The independent origin ledger checks both
representations against initial native principal: R+E+paid+fees is conserved,
and outstanding shared liabilities cannot exceed R. Fee0 is a boundary control,
not a real free native operation. Quote starts1 and may rise once to2; payout
must remain positive. Fee exhaustion and unavailable witnesses remain recorded
liveness FAILURES, even if accounting stays safe.

`RetireEmpty` changes the pool to retired with reserve0. Normal rules require
zero live-private and zero pending shared liabilities. The deliberately broken
pending guard abandons remaining backing; it is not an authorized admin payout.
An owner-controlled P2PK output does not prevent retiring an empty pool.

## Exact exploration and assumptions

Financial BFS uses no depth, state-count or sampling cutoff. Under correct
exclusion, at most three private hops, three acceptance steps and three claims
can change money. Mutants stop at their FIRST independent counterexample; these
are not reported as exhaustive safe searches. One separately labeled directed
root/index-shift trace continues past its first backing violation to expose the
second accepted model payout. No admission guard imposes one
terminal action per origin on a broken model.

The financial graph is explored at maximal availability, then **all eight**
combinations of service/public-data/retained-witness availability are evaluated
for each financial state/action. This is an exact product factorization:
availability losses only disable candidate transitions; every unavailable
product state can be reached by applying those losses AFTER its available
financial prefix. The three Boolean loss dimensions give12 environment edges
per financial state. Quote1/2 is inside financial BFS, not sampled. Source code
counts all accepted product edges and loss edges. Owner keys are assumed
retained. There is no owner-key-loss experiment.

Public/retained flags mean sufficient CURRENT accepted data/witness capability,
including accepted deltas needed to refresh witnesses. They do not mean that
an old static Merkle path is magically current. This ideal availability premise
is not a scanner implementation or proof that real data can be recovered.
Both unavailable is explicitly a shared-claim data-liveness failure. Acceptance
serviceOFF does not delete independently available data. Feasible accepted
claims must remain directly owner-claimable with serviceOFF and data available;
base unaccepted notes remain stranded without a resolved independent route.

Base and conditional-reveal graphs run separately. Current-format reveal is
UNRESOLVED and disabled in base. Conditional reveal assumes perfect future
ownership/original-NF binding and charges its abstract fee; it proves no safe
opening, signature format, secrecy or native cost. Reusable private-credential
publication is a SEPARATE negative control, not part of that ideal future
oracle: an unaccepted publication suffices for an attacker private-spend race.

Reorg closure restores a complete financial ancestor snapshot (including
payments, fees, NF and claim roots), while service/data flags and adversary
knowledge persist. Ancestor financial states and their monotone loss products
are already explored; no new financial reachability is created by rollback.
Controls explicitly restore a checkpoint for all8availability×4knowledge
products and reject its orphaned entitlement. Arbitrary DAA/consensus/reorg
validation and opaque hash/outpoint bytes are outside the model. Stale/fork
predecessor identities are distinct ideal atoms; they are never inferred just
from equal height or equal reserve. There is no rollback of public knowledge.

## Freeze and run

`configurations.json` records all128 inputs before search. `run.py --freeze NEW`
creates a hash selection without executing exploration. After independent
source review, use `--selection FREEZE --out NEW --mode base|conditional|both
--workers 1..8`; optional `--config 127` is a separately labeled smoke only.
`--mode controls` runs ten must-detect broken models plus copied-credential,
reorg and P2PK-delivery controls. Source/config files are snapshotted and hashed
before/after each job. Every configuration keeps exact state/edge counts,
completion status, liveness-failure witnesses and shortest discovered broken
model counterexample. Worker CPU/RSS are cumulative diagnostics; use the owned
job cgroup for aggregate CPU/peak RAM. No result is a protocol-liveness pass.

Ghost ledger code independently removes/reassigns origin rights and checks
consent/recipient/principal. Candidate acceptance never reads the ghost. The
ledger does not call candidate reserve/NF update arithmetic. A secondary check
of candidate-offered claims asks whether candidate guards still offer a paid
right; primary reserve expectations derive only from ghost live/claim balances.
Required mutants: omitted source NF, missing backing, missing paid marker,
root-local identity, historical paid-state, service-dependent accepted claim,
recipient/amount substitution, fee exhaustion and retiring pending liabilities.
