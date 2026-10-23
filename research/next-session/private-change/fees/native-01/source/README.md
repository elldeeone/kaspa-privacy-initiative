# Public compact commitment-append screen

DO_NOT_FUND. These scripts prove only a synthetic public Merkle-tree update.
They omit note ownership, value conservation, nullifiers and Groth16. Their
outputs are public synthetic commitments, never usable payment policies.

`kernel.py` emits the existing sequential empty-leaf checks and an authenticated
subtree update for exactly the same old/new roots, positions and CM leaves.
`harness.py` computes56 fixture IDs using the pinned official SDK, then checks
8 positive and48 malformed/occupied controls using the existing native2.1
validator. Source/pins/runtime must be reviewed before that bounded execution.

Only the new package and public runtime/SDK/native executable are needed. It
never imports another trial, proof, setup, private backup, PK, seed or RPC.
The native test budget512 is intentionally generous; it is not a selected
payment-policy budget. Measurements at one aligned start index do not bound
every legitimate path or a whole policy's execution.

See [the proposal](../../research/next-session/private-change/fees/COMPACT-APPEND-PROPOSAL-01.md)
for alignment, skipped-empty induction, capacity, independent-exit and full
lifecycle cost obligations. An occupied target block is rejected; arbitrary
occupied skipped gaps are not independently authenticated by this component.
Native nullifier, private ownership/conservation, framing, policy routing/VK,
all byte/entry/change/tail and storage costs must remain in any whole-policy
comparison. Old fee evidence remains sealed.
