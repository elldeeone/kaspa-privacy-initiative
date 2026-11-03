# Cross-component compact batch contract

Authority: accepted ADR0057 and PUBLIC-INSTANCE-01, with the unchanged exact
ADR0056 wire/relation obligations. This contract is unfunded research. It does
not close privacy/fee targets, full-capacity exits or durable availability.

## Trust and representations

Amounts are integer sompi, bounded by2,870,000,000,000,000,000. Python uses
explicit integers; Rust host aggregates use checkedu128; private Note values and
Auth amounts use exactu64 little-endian. JSON decimal strings exist only at
lossless SDK/context boundaries and are converted before comparisons.

Trusted CLI/installed software selects compact2 or wide32 before private bytes.
A witness cannot select its role/key/software. Each role has a separately
selected strict public manifest, full PK hash/length and extracted VK/query/shape
checks. Authenticate owned bytes before seed/witness read. Matching dimensions
or a key supplied by the mirror is insufficient authority.

Auth528 and the state/D/magic/metadata offsets are exact, not extensibleJSON.
Both public circuit field inputs are the exact LE128 halves of SHA256(Auth528).
Private witness format is kpx4-private-batch-action-witness/v1: no role field,
two strict input objects and exactly2 or32 output objects. No private witness
serialization/logging/hashing in the consumer; parser errors contain fixed codes.

## Roles and spentness

Compact2 accepts mode2 (two outputCMs) and mode0 (terminal zero outputs).
Wide32 accepts mode32/P0 only. Circuit shape depends on trusted role, never
private mode/value. Compact terminal and continuing finalized matrices must
match. All positive outputs meet60Mfloor; P iszero or>=10M. R' iszero or>=60M.
Terminal mode0 iff R'=0: all private output fields/rhos zero, canonicalzero
metadata/digest, CMroot/cursor carry and SHA256(528zero ciphertextbytes).

Continuing digest is SHA256(CM0||...||CMN-1), exactslot order. All continuingCMs
are pairwise distinct, including dummy slots. Every note is constrained, with
exact input/output/fee/payout balance and aggregate<=reserve/MAX. Dummy rho is
randomized while other zero-note fields are canonical. Newclient delivery uses
established genuine sealed frames; encryption correctness/recipient possession
is not proved by the circuit/native hash and must be recipient-validated.

Original positioned real NF is identical across compact/wide/REVEAL inthisD.
Native checks both sequential indexedNF insertions/currentabsence and actual
consumed reserve/program/outpoint, immutable continuation and all exact outputs/
fees. The relation supports two real inputs, but boundedclientusesone+dummy and
never mounts another owner's private witness/backup.

## Physical sparse state

For arityN, start=ceil(oldcursor/N)*N and nextcursor=start+N. Skipped leaves are
canonical CM_EMPTY under the existing root induction. A delivery's position is
start+i; do not compact positions, count gaps as receipts, or derive originalNF
from arrayordinal. Initialn1 ->wide start32/n64 ->31 continuingexits/n126 ->
terminalcarry n126, NF67. This boundedpath does not solve sustainedcapacity.

Public history kpx4-compact-batch-history/v1 contains ordered exactnative bodies
and supplied inputcontexts. Replay derives modes, arrays, positions, roots and
spentness; it cannot trust capsule-supplied owner/append/expectedvalue maps.
Synthetic suppliedcontexts must stay labelled. Publichistory hash/nativeFull
alone is not accepted-chain backing or currentness.

## Cashout and economic evidence

One payer's32 net10KAS useful payments are prospective synthetic obligations,
not32humans or observed market demand. Count all entry/change/storage/private
transfer/independentcashout costs. Refund finalunusedexitcredit rather than
clipping/donating/subfloorchange or changing intent. Refunds/dummies/change never
increase usefulpaymentcount. Preserve old conservative1.949145625% projection;
new exactquotes/proofs mayproduce a different separately reported actualcost.

First execute localgenuineproof/nativecomplete drainage. A live rehearsal, if
funded, uses a freshD/params/ownerkeys and actual freshnodecontexts through
confirmed terminalnativepayout; no old synthetic Note/Proof/PK is promoted.

## Capsule and currentness

Portable CAS roots authenticate only bytes against independently selected
staticD/program/roleVK/manifest/software authority. Capsule index cannot select
executables or manufacture trust. Recognition works withoutPK; compact spend
material requires onlycompactPK. Statownbackupinodealiases before any public
hash/read, then ownreadonlycopies and full loaderauthentication beforebackup.

Immutable history and freshcurrent-state evidence are separate. Reconcile with
fresh selectedvalidating-node acceptance/ancestry/UTXO data before any spend or
currentbalance claim. Missing/currentness failure means incomplete/safehalt,
never emptybalance, newsetup substitution or privilegedwithdrawal. Original
operator/source/cache are unmounted for portable restore; localmirrors do not
establish independent providers, durable retention or independent consensus.

## Experimental and publication boundaries

Newlinkage study freezes model/source/truth-separation/baselines/stoprules before
heldout generation. Arithmeticcounterexamples do not prove ownership ambiguity;
UNKNOWN/unsupported/full-drain failures are not privacy passes. Preserve old
failed price/identity/fee gates. Participant legitimate counterparty facts must
not be silently withheld.

Main rawunbroadcast Auth/NF/body/quote alternatives/privatewitnesses remain
private, including their privateinputhashes/maps/backups. A selectedopaque
Auth/proofhash is allowed; independently public DO_NOT_FUND canaries use disjoint
notes/NFs/fakepoints and never enter funding. Development controls are separated
from heldoutdata and actualnative/chain claims. Keep failures without retuning.
