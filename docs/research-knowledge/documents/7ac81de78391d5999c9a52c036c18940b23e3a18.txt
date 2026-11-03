# P1 preparation result, 2026-10-18

**The selected Orchard primitive works in the proving VM and produces a real
GPU receipt on the existing RTX 3070.** Candidate public intent bytes match
between Python and Rust. This is P1 preparation, not a full private wallet,
independent cryptographic review, real-private R13 or confirmed R16 payouts.

Subsequent status: the owner-selected [separate-agent review](REVIEW-RESULTS.md)
now permits unfunded offline wallet implementation after four reviewed design
fixes. External audit and actual full wallet/outer/native qualification remain
open. The primitive measurements and sealed archive below are unchanged. No
wallet top-up is needed; zero native transactions and no trial wallet.

## What was checked

| Check | Measured result |
| --- | --- |
| Published key/note/nullifier vectors | 10 match the pinned Orchard APIs |
| Full incoming encryption/decryption | 20 vectors across two published corpora; 140 negative cases reject |
| Note value boundaries | 30 constructions at zero, one and u64 maximum |
| Tree | 33 published empty roots, 256 published depth-4 paths, three independently generated depth-32 paths |
| Malformed encodings / depth-32 mutations | Seven malformed encoding cases and six path mutations reject |
| Candidate public intent | Nine frozen golden intents match Python/Rust bytes and Python decoder round trips |
| Codec rejection | All 15,559 truncations, trailing bytes, 32 malformed cases, duplicate JSON fields and two unknown option flags reject |
| Additional positive codec boundaries | Maximum 10,000-byte script, maximum u16 script version, one-byte script and maximum u32 deposit index match both encoders |
| Frozen experiment identities | Changed program/input/journal and wrong predeclared image reject before execution |
| Evidence reuse controls | Probe preparation, GPU runner and node preflight reject existing output directories without changing prior bytes |

The two official encryption corpora differ in rho and derived ciphertexts.
Both complete sets are checked; they are not asserted to contain identical
inputs. The first attempted corpus comparison and corrected handling are
retained. Structural golden intents combine unrelated published crypto fields
and synthetic IDs and are **not valid private payments**.

## Actual primitive GPU proof

Runtime input is exactly 115 public bytes: published spending key, value, rho,
seed and diversifier. The guest derives keys/address, constructs a V2 note and
computes its commitment/nullifier. Expected outputs come from the published
vector, frozen before execution. No membership, balance, intent, encryption,
spentness or native payment relation is implemented by this guest.

| Measurement | Actual result |
| --- | --- |
| VM user cycles | 101,574,765 |
| Proven segments / total trace cycles | 235 at po2=19 / 123,207,680 |
| Execution profile API / whole phase | 1.675s / 1.887s; execution only |
| Full succinct proof API / whole phase | 412.445s / 412.691s, about 6m53s |
| Sampled peak matching prover VRAM | 6096MiB, about 5.95GiB |
| Sampled peak summed host RSS | 620,961,792 bytes, about 0.578GiB |
| Saved receipt | 223,424 bytes |
| Separate CPU verification API / whole phase | 0.060s / 0.218s |
| Matching-prover GPU SM activity | Observed; no CPU fallback counted |

The genuine succinct receipt verifies against the exact image and complete
journal, with successful exit, no unresolved assumptions and development mode
disabled. A separate CPU process reloads its retained bytes and repeats seal,
wrong-image and journal-mutation rejection. It shares the SDK; it is not an
independent audit or independently implemented verifier.

The proof uses the unchanged qualified sm86 CUDA binary
`3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7`,
four compute threads and CPU affinity 0–3. No GPU power/clock/driver settings
changed. The native client/guest Cargo locks align the RISC Zero transitive
versions with the previously tested host. An initial guest build using newer
transitive patches was not executed or proved; its original lock is retained.
Formatting and rebuilding the final guest produced byte-identical program data.
These measurements do not predict the full payment circuit's performance.

| Identity | Value |
| --- | --- |
| Diagnostic primitive image, **never a wallet verifier** | `3a1adac4403b65acff144d7eb76296fab3504c010a89cd32fcd1f4533b15683e` |
| Program SHA-256 | `a1b3cdc43086e35c20ba14510ef1075caf9caf7793e000c683b82037e818a58d` |
| Public input SHA-256 | `578f731eadaf380bfddde187e4a5c3af809bdf504fcd46e1b3230b9e46560678` |
| Expected journal SHA-256 | `6e908fdf93b0346e3a0dce094e283d49942379c562f45da9d19ccd13873f030e` |
| Saved receipt SHA-256 | `7f02abee168a13960877d6b4f0bffea7a3e148ebb3995bacf0bf5b08a07b1002` |

## Owner's node

Read-only observation at `2026-10-18T09:13:47.630Z`, endpoint
`ws://10.0.3.26:18210`: reported server `2.0.0`, Testnet-10, synced, UTXO index
enabled. Ordinary information/block/fee RPCs respond. Full virtual-chain history
returns four added chain blocks/groups with 18 accepted transactions.
`getSeqCommitLaneProof` fails with a WebSocket error. A fresh post-probe
connection still reports the same network, synced/indexed state.

Initial shared-socket probes misreported later RPC availability after the
lane-proof operation closed its connection. The corrected tool gives each
method its own socket; Full works. Both early attempts and corrected raw
responses are retained. These are capability observations, not header/body/lane
proof verification or a claim about the node's consensus capabilities. Diagnose
the required lane-witness endpoint before native integration. No SSH or node
configuration change occurred.

## Next dependencies

1. The bounded [AI design review](REVIEW-RESULTS.md) is complete. Finish actual
   proof/code qualification and exact native descriptor/recovery-key-to-outpoint
   binding. Full P1 remains open; the offline design gate is cleared.
2. Implement and qualify the full P2 wallet relation using synthetic fixtures;
   generate real reviewed wallet/outer/control identities. Produce the actual
   full-private valid-invalid-valid R13 outer receipt.
3. Qualify required node witness capabilities and complete the private native
   deposit/transfer/exit/terminal-payout rehearsal. Calculate the test-KAS budget
   from those actual transaction shapes; then create/fund a fresh trial.
4. Run independent restored-user R16 with actual full proofs, confirmed exact
   native payouts, duplicate rejection and final principal-reserve drain.

The [candidate manifest](suite-candidate.json) keeps unavailable payment IDs,
native bindings and external review explicit. No P1–P5 completion follows from
the successful primitive proof. All native-KAS/security invariants remain in
force; no new token or admin withdrawal path is introduced.

## Retained evidence

[Manifest](evidence/2026-10-18-review-preparation.json) indexes the
[public evidence archive](evidence/2026-10-18-review-preparation.tar.gz), including
source/lock identities, public vectors/program/input/expected journal, raw
node/proof/resource records, genuine saved receipt, CPU verification, negative
controls and the review package. Host executables, compiler archives, CUDA
caches and private/funded wallet keys are excluded. The manifest hashes every
member and the archive; this is not a complete future private-recovery bundle.

Validation: locked native/guest builds, both Cargo formatting checks, Python
syntax, Node syntax, vector/codec/identity/reuse controls, real GPU proof and
separate saved-receipt CPU verification. Repository documentation and whitespace
checks are recorded in the manifest. Existing unchanged model tests were not
rerun as evidence for this new cryptographic composition.
