# ADR0063 native P0 adapter

This package emits the **new unfunded** owner-private P0 covenant and canonical
native body projection. It never imports the funded profile-41c template, owner
keys/backups, parameter secrets, network or submission. Its reports do not
execute a native VM, verify G16 proofs, or establish accepted backing/currentness.
The new component profile and genuine R0 image must be externally selected and
pinned before its emitted bytes can participate in a native acceptance claim.

The parent [wire contract](../DESIGN.md) is authoritative: one native reserve
input, one same-template successor, three Spend proofs, six mixed Output tuples,
Body10780, FX prefix193/full projection10973 and journal104. Native payouts are
strictly zero. No exit or alternate authorization branch is implemented.

## Operations

The binary reads one JSON request on stdin. Objects reject unknown/missing or
recursive duplicate keys; integer fields reject booleans, strings and floats.
All public hex is lowercase canonical encoding.

* `{"operation":"emit","state_hex112":...,"outer_image_hex32":...,
  "component_profile_sha256":...}` returns `redeem_hex`,
  `immutable_tail_hex`, `script_public_key`, `zero_proof_witness_hex` and hashes.
  The zero proof is an invalid construction placeholder, never acceptance.
* `{"operation":"normalize","case":...,"outer_image_hex32":...,
  "component_profile_sha256":...}` recomputes canonical tx ID/storage mass and
  returns the canonical case, projection, journal and native mass metrics.
* The same request with `operation="body"` requires the supplied ID and storage
  mass already be canonical. Both operations require exact template/context,
  point/header/native effects/successor checks, but neither verifies a receipt
  or the component statements. The new guest supplies that cryptographic gate.

Image and component-profile parameters are trusted application selection inputs,
not fields that supplied transaction data may select as authority. Emission is a
code-generation utility and is not a substitute for authenticating the selected
financial/program profile. No output JSON validity flag is financial authority.

`../native_case.py` exposes `NativeCodec(executable,sha256)`, `emit`, `project`,
`make_case` and `replace_outer_proof`. It authenticates the executable with stable
opened-file metadata and the caller's external SHA. `make_case` creates supplied
UTXO context only, and defaults to an explicitly invalid all-zero outer proof.
`replace_outer_proof` requires that changing the outer witness leave the exact
financial projection and journal unchanged. The caller separately verifies the
genuine receipt before using its native proof bytes.

## Native policy

The canonical witness is `4c80 | proof128 | 4d | redeemLength_u16LE | redeem`:
133 prefix bytes, one proof on the execution stack, no unused signature slot.
The script checks exact frame/stack depth, version1, input/output count1,
transaction input index0, maximum sequence, zero locktime/gas/native subnetwork,
noncoinbase context, absent covenant, input/output SPK width37 and Body10780.
It binds actual previous point, current state/reserve, exact zero payout and
positive bounded fee, successor reserve and counts, and the P2SH hash of the
same immutable tail with the successor state. The whole actual native projection
is reconstructed through introspection, then SHA256-hashed into the journal.

The input covenant-ID opcode uses zero as the None sentinel; admission/accepted
history must establish the ordinary no-covenant initial context, as in the old
P0 policy. This unfunded codec accepts only explicit JSON `covenantId=null` and
`covenant=null`. Supplied context is never labelled accepted-chain state.

The new R0 guest must verify all nine genuine component proofs, curve/scalar
encodings, direct balance and public NF/CM transition witnesses. Its selected
image binds that new predicate. Native receipt checking uses the standard
R0 Groth16 claim, halted-zero/no-assumption tags, standard424-byte VK and generic
Kaspa `OpZkPrecompile`; there is no diagnostic hash oracle or old fallback.

## Exact upstream reuse and dependency boundary

The R0 opcode fragment comes from pinned rusty-kaspa
`01b532e8b553523216471682649693af92f0fd16`,
`crypto/txscript/zk-sdk/src/zk_to_script/fragments/groth16.rs`, source SHA
`4cf063a5e50c1c73bc472d301bc3b5b823418bb8e8cce1160460857bf8493628`.
Its standalone SDK requires R0 3.0.4 and cannot resolve alongside the selected
genuine R0 3.0.3 closure. `src/r0_fragment.rs` therefore adapts the exact verifier
functions/constants into this package, changing crate imports/result type and
omitting unrelated builder APIs. The standard opcode sequence is unchanged;
verifier parameters come from the selected 3.0.3 library. The original ISC notice
is retained in `NOTICE`. There is no new pairing or field arithmetic.

A unit control decodes/re-encodes the standard compressed VK and compares its
uncompressed bytes with `risc0_groth16::verifying_key()` from the pinned genuine
closure. Successful verification of the forthcoming genuine new receipt through
the actual native077 Full engine remains the decisive compatibility experiment.

## Current evidence

`CODEC-CONTROLS-01.json` covers canonical emission/projection/mass, outer-witness
projection invariance, 24 malformed header/state/frame/effect cases and two
changed parameter cases. Its artificial roots, CVs and all-zero component/outer
proofs are deliberately invalid. Shared public state validation rejects those
artificial roots. Rust unit controls cover recursive duplicate fields, numeric
aliases, old domain/zero identities, canonical witness metadata and standard VK
roundtrip. None is a native acceptance or proof-soundness claim.

The test fixture's compute budget3000 and quoted mass are codec inputs, not a
selected minimal budget or a measured requirement. A valid new receipt/native
run must determine actual cost and satisfy an independently selected budget.
