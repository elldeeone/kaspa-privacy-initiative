# ADR-0018: Reuse private authorization across unrelated pool updates

Accepted for the owner-authorized offline experiment and conditional TN10
rehearsal/trial, 2026-10-19. No mainnet, consensus changes, push or upstream post.
The version-3 implementation and evidence remain unchanged.

## Decision and hypothesis

H5: after Bob proves a full withdrawal, Alice can make an unrelated private
payment and a process with only public data can rebuild Bob's native transaction
with byte-identical authorization/proof, no additional proof, and a confirmed
payout. Current nullifiers, backing, recipient and fee binding must still hold.

Use a fresh experimental domain, verification key and reserve. Separate the
private authorization from native settlement. Reuse SHA-256 commitments,
HMAC-SHA256 economic nullifiers, sealed-box note delivery, BN254 Groth16 and the
existing 24-slot append-only state codec. This is an application relation and
covenant change, not reuse of a stale version-3 transition proof.

The authorization proves ownership and membership in an earlier commitment
snapshot; it fixes the pool domain, snapshot count/hash, economic nullifier,
output commitments, transfer/full-exit mode, payout recipient/value, miner fee,
bootstrap value and ciphertext digest. Its two public field elements encode
the two halves of SHA-256 of that fixed authorization. No reserve outpoint,
current nullifier set or successor state is in this private statement.

For this bounded append-only array, authenticate the earlier snapshot as the
prefix of the CURRENT commitments, padded with zeros to 24 entries and hashed
with its count. No arbitrary root supplied by a wallet is trusted. This is a
small-array adaptation of historical membership anchors, not a new primitive
or a scalable replacement for a commitment tree.
The native rule authenticates any nonempty current commitment prefix; it does
not maintain a registry proving that the chosen count was once a complete pool
state or a block-boundary root. The wallet/test uses the full accepted count at
authorization time. Smaller prefixes remain safe for membership/current
spentness, but can unnecessarily narrow the user's candidate set. Historical
block-boundary/expiry semantics would require an additional design.

The executed P2SH covenant independently enforces the current settlement:

- Check canonical envelope, single reserve input and immutable rules/VK/domain.
- Authenticate the authorization's snapshot against current commitments.
- Reject its nullifier if already present; append it exactly once.
- Retain every old commitment/nullifier, append only authorized commitments,
  reject duplicate new commitments, preserve zero padding and enforce capacity.
- Check actual reserve/payout/fee arithmetic, payout script, floors and exact
  output count. Omit the reserve only when no private claims remain.
- Propagate immutable covenant bytes and verification key in the successor.
- Bind ciphertext bytes and verify the actual Groth16 authorization.

Bootstrap retains the prior backing rule: before other holders can accept
claims, the first private spend proves the sole initial note equals the native
reserve. The public bootstrap value is zero on every subsequent authorization.
Only two-output transfers and whole-note exits are implemented for this test;
deposits and partial exits remain in the preserved version-3 experiment.

I-6 is enforced by the composition: the authorization remains bound to its
intended historical commitment snapshot and domain; native settlement consumes
the exact current UTXO and checks its entire retained state. Replaying a full
state-transition proof against another state is still forbidden. This does not
authorize deleting the old nullifier set or relaxing any security invariant.

Every amount is integer sompi. Start with a conservative 40,000,000-sompi note
floor and 10,000,000-sompi payout floor; native measurement must establish that
the final fixed exit fee fits their difference. Full-exit authorizations fix
the SAME fee/payout whether continuing or terminal, so output-shape changes do
not themselves demand a new proof. Fee repricing still requires authorization.

## Alternatives and sources

Keep exact-state private proofs as the control. A second public settlement
proof would avoid giving its prover secrets but could retain the expensive
retry bottleneck; reject it for this smallest test. A root-history list adds
state and expiry rules unnecessarily while all commitments are retained.
Batching/sharding and vProgs are deferred; none is needed to test this layout.

Source review: [current pins and prior analogous designs](../../research/shared-pool-four-wallet-source-review-2026-10-19.md),
[dust/recovery analysis](../../research/shared-pool-dust-contention-source-review-2026-10-19.md),
[new source review](../../research/reusable-authorization-source-review-2026-10-19.md).
Adapt Orchard/RAILGUN historical membership plus current spentness; retain
Aztec's append-only note/nullifier separation. Do not import their runtime,
setup/security claims or admin powers. Monero/MWEB inform explicit public fees
and confidential-value conservation, not this shared-reserve state machine.

## Boundaries

Single-party experimental setup, retained public artifacts, one correct full-node
view and stable accepted history remain assumptions. Prefix/count choice reveals
a proof's membership horizon; it does not reveal the selected commitment by
itself. Public nullifiers/output commitments, fees, exits, timing and chain
ancestry remain visible. RPC/network access is separate. No real-world anonymity,
arbitrary-reorg recovery, fairness, unbounded state or production-security claim.

The fresh pool must fully drain. Offline controls precede funding; a complete
funded rehearsal precedes a fresh measured trial. Each transaction is submitted
once; unexpected failures retain their identity/evidence and use a fresh retry.

## Observed outcome

The [offline and funded TN10 experiment](../../poc/shared-pool/ANCHORED.md) passed.
In a complete rehearsal and fresh measured trial Bob's stopped prover was not
needed after Alice's payment; his exact authorization/proof settled with about
21 ms of public transaction rebuilding and no second proof. Both pools drained;
80 hostile native cases rejected offline. Retain this separation for continued
research, with its higher fee and prefix-choice privacy cost explicit. This is
not a production architecture decision or general liveness result.
