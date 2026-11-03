# ADR-0019: Compact state with public settlement witnesses

Accepted for the owner-authorized offline 100-payment experiment and conditional
TN10 run, 2026-10-19. Preserve the preceding variants and evidence. No mainnet,
consensus change, privileged signer, push or upstream posting.

## Decision

H6: after 100 unrelated two-output private payments, Bob can settle the exact
authorization/proof prepared before those payments using public data alone.
Native transaction size and execution work must depend on configured tree depth,
not the number of preceding payments. All claims must remain backed and drain.

Replace the 24-entry arrays with three depth-16 SHA-256 Merkle trees: append-only
note commitments, an indexed nullifier set, and append-only accepted note-root
history. Keep counts and three roots in the reserve script. Public transaction
payloads carry authentication/update paths, output commitments and ciphertexts.
The complete public history still grows; compact on-chain state does not remove
data availability, wallet scanning or retention requirements. Capacity is bounded
at 65,536 leaves, not unlimited. History has one entry initially and one per
transfer; exits do not append an anchor.

Adapt Aztec's indexed nullifier insertion: authenticate the predecessor leaf,
require a strict gap around the new nullifier, update the predecessor, then prove
the fresh append index empty and insert a leaf retaining the predecessor's old
successor. Reject a stale path against the current root. Keep full 256-bit keys;
do not truncate nullifiers to fit a small sparse tree. Comparisons use explicit
unsigned limbs. The sentinel is zero and cannot be an economic nullifier.

Authenticate historical roots through the current history-tree root; append only
the exact new commitment root. Bob's private proof binds membership, ownership,
value conservation, domain, historical count/root, nullifier, recipient, fee and
ciphertexts. Current spentness, public tree updates and exact backing remain
native covenant checks. No second proof is introduced.

Each economic note is identified by its commitment AND private tree position.
Adapt Sapling's positioned-note model: the existing HMAC-SHA256 nullifier includes
the constrained private position under a new domain-separation tag. Repeated note
commitments at distinct positions therefore represent separately funded claims;
no linear search or fourth uniqueness tree is needed. This is not Sapling's
cryptography or a claim of its security review. Membership and position bounds
must be constrained together. Existing ciphertext/note encoding is retained.

Bootstrap must authenticate canonical empty nullifier state, single-note history
and exact native backing. Successor code/VK/domain remain immutable. Current
UTXO consumption plus authenticated tree transitions enforce I-6; stale full
state-transition proofs in prior variants remain invalid. All amounts are u64
integer sompi with the existing MAX_SOMPI bound and native payout floors.

## Alternatives and boundaries

Reject simply enlarging arrays: it retains linear size and private membership
work. A 256-level sparse nullifier tree avoids predecessor logic but substantially
increases native witness/check work. Indexed trees are the candidate to measure.
A second settlement prover would obscure whether cheap public updates work.
No vProgs, sharding, expiry window or consensus modification is required by the
hypothesis. Single-party Groth16 setup, unreviewed application relation, serial
reserve contention, stable accepted history and a correct node view remain
explicit assumptions. Privacy and sustained fairness are separate questions.

## Gates

Before funding: boundary/malformed/replay/wrong-root/cross-domain controls,
native Full validation, resource/default relay-policy checks, exact SDK transport,
100 real proofs/payments and full drain. Bob's public-only process receives no
wallet or proving key; preserve byte equality of his authorization and proof.
Then complete a short funded rehearsal including terminal payout, followed by a
fresh 100-payment TN10 trial. Record exact fees, proof/rebuild work, chain bodies,
source/binary/VK hashes and failed trials. Never weaken safety checks for a demo.

Sources and reuse decisions: [source review](../../research/compact-state-source-review-2026-10-19.md).

## Observed outcome

The full offline gate, complete two-payment TN10 rehearsal and fresh 100-payment
TN10 trial passed. Bob's authorization/proof remained byte-identical as current
commitment count advanced from 3 to 203. Both original provers stopped before
his public-only rebuilder discovered the updates and settled his payout. All
204 measured native transactions were confirmed and all claims/reserve drained.

Keep this separation and compact representation for further bounded research.
State is 105 bytes, but public history still grows and the native exit fee is
about 2.75% higher than the preceding anchored variant. This does not select a
production protocol or establish privacy, fairness or unbounded scalability.
[Exact measurements and evidence](../../poc/shared-pool/COMPACT.md).
