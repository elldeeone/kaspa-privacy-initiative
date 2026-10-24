# Genuine-proof native binding controls

`genuine_native_smoke.py` requires an externally selected public case and actual
128-byte outer proof, the selected new image/component identities, and pinned
single-link native/codec/control executables. It runs only in a closed namespace
with `/home` and `/var` absent. Host staging must first apply all eight original
backup inode/directory exclusions and all three new whole-party exclusions.

The first case must pass the actual native077 Full validator and its input
ScriptEngine. Twelve mutations retain exactly the same outer proof and redeem.
Changed opaque CF or Spend-proof bytes must reach `ZkIntegrity`; changed native
point/state/reserve/SPK/fee/payout/sequence/header/output-count and a correctly
populated genesis covenant must fail the actual script before ZK dispatch.
The test-only Rust helper uses the pinned upstream transaction methods to
recompute storage mass and transaction ID for every mutant. It performs no
financial validation and is not part of the production covenant or codec.

The genesis control uses `populate_genesis_covenants(input0, output0)`, preserving
amount and SPK. The production script's authorizing-input check distinguishes
actual `None` from every `Some(u16, id)` binding; ordinary-input genesis is
otherwise allowed by consensus. Input `None` versus `Some(ZERO_HASH)` remains
an explicit admission/history premise, as documented in
`COVENANT-BINDING-01.json`.

These experiments are unfunded supplied-context validation. Success does not
establish accepted backing, chain currentness, a withdrawal path, cryptographic
correctness, production security, or financial privacy. The pinned new R0 guest
and its genuine component verification are separate required evidence. No old
financial profile or source packet is changed by this additive test harness.
