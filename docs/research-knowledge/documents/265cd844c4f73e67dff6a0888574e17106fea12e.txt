# Outer-verifier source selection: RISC Zero 3.0.3

**Decision: DEFER.** The reviewed code supplies BN254 verification components
and earlier zkVM guests, but does not supply the requested implemented guest
relation over two current v6 bundles with a bound aggregate public statement.
No heavy experiment or conditional rehearsal is ready from this selection pass.
This is a missing implementation prerequisite, not evidence that the route is
impossible or that a different backend should be tried.

## Ownership and bounded scope

| Item | Recorded identity |
| --- | --- |
| Owner | Existing batching source reviewer, `/root/next_direction_sources`; root orchestrator owns scheduling |
| Authorized start | 2026-10-22 10:06:39 UTC / 21:06:39 AEDT |
| Deadline | 2026-10-22 10:36:39 UTC / 21:36:39 AEDT |
| Source-selection stop | 2026-10-22 10:08:39 UTC / 21:08:39 AEDT; remaining work only records already read evidence and source pins |
| Documentation HEAD | `c1e0f25aa1c305bfd29c61398e757b4c1f2d913d`, branch `docs/kpi-orchestration-2026-10-22` |
| Scientific source HEAD | `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`, branch `shielded-kas-research`, `/home/luke/projects/kaspa-privacy-shared-pool` |
| One assessed route | RISC Zero SDK/r0vm **3.0.3** guest verifies two existing v6 BN254 Groth16 bundles; its succinct receipt would target Kaspa's R0Succinct verifier |

Only committed public source/document bytes were read. No build, experimental
module import, proof, test, setup, installation, benchmark, GPU job or private
evaluation was performed. No parked `attack_design` or recovery implementation
wrapper was inspected or accessed. No other backend/version was selected.
The first decisive prerequisite failure ends this route selection; downstream
fields below remain explicitly unqualified.

## Decisive source evidence

1. **The implemented accelerated classifier proves an earlier statement.**
   Its [guest entry point][classifier] parses proxy operations, authenticates
   their ordered native-ID root, calls `Verifier::pinned()` at line 39 and
   `classify(op)` at line 49, then commits root, initial balance, count, and
   per-operation ID/verdict/balance (lines 44–70). The
   [verifier constructor][backend] pins the PR37
   `groth16-comparison/pins/pvk-uncompressed.bin` and matching `vk.bin`
   (lines 66–84). Its [reference relation][reference] maps a 96-byte proxy
   journal to public fields (lines 23–25). This is not a v6 Bundle parser or
   a v6 aggregate relation.
2. **Current v6 has a different exact binding.**
   [Authorization][v6-auth] is 377 bytes, including domain, anchor/count,
   two nullifiers, two commitments, native monetary/destination fields and a
   ciphertext digest. `Authorization::inputs()` returns exactly **two** BN254
   scalars from the two 16-byte halves of its authorization hash (lines 89–91).
   The [circuit][v6-circuit] constrains those same two digest limbs to its public
   inputs (lines 275–278). Reusing proof length or the BN254 curve is not an
   implementation of this binding inside the selected outer guest.
3. **A reusable library function is present; the requested guest is missing.**
   The [backend][backend] exposes `from_validated_program_key` and
   `verify_inputs` (lines 87–118), with a 128-byte proof/arity check and checked
   canonical decoding. This is a useful existing component, not evidence that
   it has been composed into the required two-v6-bundle guest. The existing
   private-note/native route delegates to the
   [private-note-chain verifier][chain-verifier], which pins
   `gamma_abc_g1.len() == 15` (lines 36 and 54): **14** public inputs, not v6's
   two. Its caller verifies `Operation.statement.inputs()` (lines 64–67).
   Neither inspected caller provides the requested v6 input and journal contract.
   This arity mismatch describes those callers, not an inherent two-input
   limitation of the generic verifier or RISC Zero.

**Inference:** the earlier guests and generic helper do not satisfy the
implementation-selection gate in the
[batching feasibility review](../architecture/BATCHING-NATIVE-FEASIBILITY-REVIEW.md#only-the-next-smallest-genuine-gate).
No reviewed implementation binds a fixed v6 VK/domain and both exact
authorizations/ciphertext pairs to the intended aggregate output while hiding
the internal grouping. Searching another backend, building a guest, or treating
an older receipt as the missing v6 implementation would exceed this assignment.

## Required selection fields and their status

| Required field | What this source pass establishes |
| --- | --- |
| Source/dependency pins | Project commit above. Classifier guest pins `risc0-zkvm = 3.0.3`. Backend pins `substrate-bn` source `22108fe8c6ea1ebc1358fc4fd6854a6bf46e3509`; its lock resolves `risc0-bigint2 1.4.14`. Backend Arkworks types are 0.5.0; current v6 dependencies are 0.6.0. No cross-version v6 serialization/interoperability result is implied. See [guest manifest][guest-manifest], [lock][guest-lock], [backend manifest][backend-manifest] and [v6 manifest][v6-manifest]. |
| SDK/r0vm source identity | Existing [upstream record][upstream] pins RISC Zero v3.0.3 to `14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6`. This records the existing route; it is not a newly qualified build or a release/head refresh. |
| Actual inner relation | Earlier proxy classifier and older 14-input private-note relation exist. Requested two-v6-bundle relation is **not selected/implemented by the inspected entry points**. |
| Aggregate/public-input binding | Existing classifier publishes its own ordered-ID/outcome/balance journal. A v6 aggregate digest, field encoding, hidden partition/CM/ciphertext binding and expected outer journal are **missing** for this route. Pairing verification alone does not supply those bindings. |
| Final receipt/tag/claim/image mapping | **Unqualified; not assessed after the decisive source stop.** No v6 guest image or expected journal was selected. The requested R0Succinct target is a planning input, not a demonstrated native receipt mapping. No proof-tag source was reached in this pass. |
| Setup assumptions | The proposed scope would verify retained v6 proofs with their exact existing VK, without wallet keys, note openings or a new inner setup. No v6 outer guest, independently expected image, setup/parameter inventory or native claim binding was selected. No setup was generated. |
| Existing build route | [accelerated-bn254/build.sh][build] builds the **older classifier**, validates its PR37 static key and uses the custom `kpi-risc0` toolchain, `RISC0_FEATURE_bigint2=1`, a locked guest build, wrapping and image pinning. It is not a build route for an implemented two-v6 guest. Nothing was executed. |
| Future CPU/RAM/wall estimate | **Unavailable for the requested route.** No implemented v6 guest/image/cycle profile exists in the reviewed route. Older classifier observations cannot establish a defensible Forge budget for it. |

The existing [full-classifier report][full-results] records a complete succinct
receipt for image `397bcdca688462b9573a4b55e3516e1a2511140512c53337eb54da0849a93716`,
with 117,473,222 user cycles and a roughly 256-second L40S worker run. That image
and journal belong to the older proxy classifier above. They are **not** a v6
expected image, CPU timing, RAM ceiling or proof/native-acceptance result for
the requested composition. No CPU/GPU extrapolation is made.

## Consequence for the roadmap

Keep genuine batching deferred. Retain existing direct-L1 mechanics and the
conditional architecture observation; do not schedule a proof, benchmark or
new pool from this note. This source pass neither adopts batching as a privacy
fix nor authorizes implementation of the missing relation.

Any later design still has to preserve native KAS backing, per-owner secret
control and independent exits. Verifying two current inner proofs does not by
itself enforce current nullifier spentness, reserve settlement, correct delivery
or a new pool's exit path. This deferral changes no invariant, accepted privacy
target, past failure, current pool or parked-job status.

## Exact source pins

SHA-256 values below were calculated from `git show ec6aa15d586bcc8a90f7232b433fd48d8c73d509:<path>`.
The clickable source links point to the reviewed local primary files; the
commit and hashes fix their identities independently of later checkout edits.

| Source path under the scientific repository | SHA-256 |
| --- | --- |
| `poc/accelerated-bn254/classifier-guest/src/main.rs` | `5ad2d43b1264bd428f1e03330fa1655ad0d987e0dbdebcd164387a303b3109e4` |
| `poc/accelerated-bn254/classifier-guest/Cargo.toml` | `1c9c5aee0b9915b42bd929a9a48161b75c91cb8f99966de65c4668b00db6f4e2` |
| `poc/accelerated-bn254/classifier-guest/Cargo.lock` | `4e85f6e675336c6c0ae14ccfc239c43a8820013d976af82da215138102a479fd` |
| `poc/accelerated-bn254/common/src/lib.rs` | `ff8ef9d2ea1ef93440cadcfaac086ebafad33b2ae505ba3880b596b34660041e` |
| `poc/accelerated-bn254/common/Cargo.toml` | `fe44804b55e4432784f60507b079986eb2f9c71f7bdfd99744b953340cef8833` |
| `poc/groth16-comparison/common/src/lib.rs` | `d41e58eb2a2ec9efcd0e750055689beea07e45162843f47a8b2c341d02f97ce3` |
| `poc/private-note-chain/common/src/lib.rs` | `f640acf4771227ea33812108b95ff0a1355cd996ec600f9b7ad833f53ef1158c` |
| `poc/shared-pool/src/two_input/mod.rs` | `255f8e908fcb1c4a76dcc8ebe0ca5f4e9ddbadc8ba46f63036cb413298bc8150` |
| `poc/shared-pool/src/two_input/circuit.rs` | `59071901c3abc25daab68c982ef065f8755c09abbb2ce30e6010d821813dd2a7` |
| `poc/shared-pool/Cargo.toml` | `cfdc8e104c93e4575b1f2cf5d9b441566674b7b801856d18fc7aeb5ba50234f3` |
| `poc/remote-cuda/UPSTREAM.md` | `5ebd69a4cdd54b9067020e0f9e1f69fa094b1d7cd0a9a660aeab7084ecfd535b` |
| `poc/accelerated-bn254/build.sh` | `96840451a4a93c65c9d577f479c89eee3081204ea33e09be5514f1bbd6ff6652` |
| `poc/remote-cuda/FULL-RESULTS.md` | `400e143d2c7fcf545399111c533edd96dcf8e166798a7d041aee3d4a6d10d377` |

[classifier]: /home/luke/projects/kaspa-privacy-shared-pool/poc/accelerated-bn254/classifier-guest/src/main.rs:39
[backend]: /home/luke/projects/kaspa-privacy-shared-pool/poc/accelerated-bn254/common/src/lib.rs:66
[reference]: /home/luke/projects/kaspa-privacy-shared-pool/poc/groth16-comparison/common/src/lib.rs:23
[v6-auth]: /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/two_input/mod.rs:89
[v6-circuit]: /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/two_input/circuit.rs:275
[chain-verifier]: /home/luke/projects/kaspa-privacy-shared-pool/poc/private-note-chain/common/src/lib.rs:28
[guest-manifest]: /home/luke/projects/kaspa-privacy-shared-pool/poc/accelerated-bn254/classifier-guest/Cargo.toml
[guest-lock]: /home/luke/projects/kaspa-privacy-shared-pool/poc/accelerated-bn254/classifier-guest/Cargo.lock
[backend-manifest]: /home/luke/projects/kaspa-privacy-shared-pool/poc/accelerated-bn254/common/Cargo.toml
[v6-manifest]: /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/Cargo.toml
[upstream]: /home/luke/projects/kaspa-privacy-shared-pool/poc/remote-cuda/UPSTREAM.md
[build]: /home/luke/projects/kaspa-privacy-shared-pool/poc/accelerated-bn254/build.sh
[full-results]: /home/luke/projects/kaspa-privacy-shared-pool/poc/remote-cuda/FULL-RESULTS.md
