# Public native observation with regenerated witnesses

This additive component closes a concrete gap in the earlier observation work:
it independently regenerates the complete **4,368-byte public settlement witness**
from preceding public commitments, indexed nullifiers and anchor history, then
compares every byte. It also recomputes the old/successor public state roots.
Reading or hashing supplied witness paths alone did not establish this property.

The implementation changes no protocol, circuit, covenant, wallet, frozen
observer, privacy workload, threshold or scientific result. Its baseline is
`ec6aa15d586bcc8a90f7232b433fd48d8c73d509`; the native dependency remains
rusty-kaspa `01b532e8b553523216471682649693af92f0fd16`.

## Implemented path

1. Load only the three named, hash-pinned public rehearsal files under
   `evidence/2026-10-20-two-input-tn10/`: rehearsal `descriptor.json`, rehearsal
   `chain-confirmed.json`, and `verification-key.json`. Extract declared public
   descriptor fields and native bodies; exclude the old participant roster and
   receipt headers. No directory traversal or evaluation input is used.
2. Select an explicit prefix **before** inspecting later transaction bodies.
   Resolve exactly its consumed public funding parents, preserve the founding
   commitment at position zero, decode authorization/ciphertexts and enforce
   public byte, ancestry, amount, output and script consistency.
3. Rebuild the depth-16 commitment/history trees and depth-17 indexed-nullifier
   tree using the existing SHA-256 construction. Recompute all witness bytes,
   old state roots and successor roots without using supplied witness siblings.
4. Emit canonical decimal sompi strings, source pointers and byte-region hashes.
   Native transaction IDs, proof validity and canonical covenant code remain
   explicitly unverified in the standalone Python projection.
5. The separate native control executable and integration wrapper validate the
   same selected bytes through the unchanged Rust replay, compare independent
   public roots/accounting and retained transaction IDs/full hashes, and exercise
   canonical mutations that reach the intended proof/covenant checks.

The Python library requires an independently supplied expected descriptor digest.
The named rehearsal's canonical descriptor digest is
`d02c36cd87db7bfd43f6f85a425539a90f8f39224a20ac5ef860ae0f54be3a8b`.
The caller must authenticate that expectation's source. Computing a new expected
digest from an untrusted descriptor would not authenticate a pool.

## Checks and current evidence

The new Python control suite passes **20 tests**. It checks all 14 prefix cuts,
future-byte independence, all 91 raw byte references, eleven public-witness
mutation locations, wrong roots/anchors, replayed nullifiers, repeated funding
sources, descriptor/VK identity, malformed integer types/ranges, duplicate JSON
keys, missing parents, injected output claims and changed authorization/ciphertext/script/value fields.

The retained public trace supplies 3 ADMIT, 4 SPEND and 6 DRAIN operations,
including a partial payout and historical anchors. All 13 witnesses regenerate
exactly. Native reserve arithmetic is 2,000,000,000 initial + 3,600,000,000
admitted = 5,080,000,000 paid + 520,000,000 fees + zero remaining sompi.
This is a field/state reconstruction result until the separate native run is
recorded. It is not a privacy experiment or cryptographic audit.

The [native integration](evidence/2026-10-22-public-native-observation/attempt-01/validation.json)
**passed**: all 14 retained pool transaction IDs/full hashes, thirteen independent
witnesses, three native prefix cuts, twenty Python controls and eight native
controls agree. Canonically rehashed proof and rebound-ciphertext mutations
reach native proof rejection; witness, authorization and successor-script
mutations reject at exact public reconstruction. The changed-parent-signature
limitation remains explicit. The [manifest](evidence/2026-10-22-public-native-observation/attempt-01/MANIFEST.json)
pins all sources, inputs, executable and results.

The complete resource-controlled job took 0.829 seconds, 0.854 CPU seconds and
33.6 MiB peak memory, with zero swap. The wrapper's separate `RUSAGE_CHILDREN`
values describe its direct-child accounting and may exclude namespace
descendants; they are not whole-job native CPU measurements. Standalone Python
flags remain false; the separate measured native validation flags are true
only for this retained public trace. Parent-spend and chain-acceptance flags
remain false.

## Commands

From `poc/shared-pool`:

```sh
python3 -B public_native_observation_tests.py
python3 -B public_native_observation.py \
  --prefix-operations 13 \
  --expected-descriptor-sha256 d02c36cd87db7bfd43f6f85a425539a90f8f39224a20ac5ef860ae0f54be3a8b \
  --output /new/output/observation.json
```

The native integration must use a separately built
`kpi-public-native-observation-check` from these exact sources. Its wrapper
requires the expected executable SHA-256 and a new output directory; it starts
no build and permits no network. Run it under the coordinator's assigned
CPU/RAM/deadline cgroup:

```sh
python3 -B verify_public_native_observation.py \
  --native-binary /absolute/path/kpi-public-native-observation-check \
  --expected-native-sha256 EXECUTABLE_SHA256 \
  --output-dir /new/output/native-integration
```

The wrapper mounts only the exact executable, selected public input JSON and
operating-system runtime inside a network namespace. It retains source and
input hashes, stdout/stderr, measured command/exit status and independent
comparison results. The standalone decoder's false native-verification flags
are preserved; measured native results have their own artifact and manifest.

## Limits and adversarial review

- No private note opening, private input membership path, spending key, setup,
  proving parameter, seed, truth, prediction or evaluation archive is read.
- Parent output amounts/scripts and selected outpoints are checked. **Funding
  parents' own input UTXOs are absent**, so their spending signatures remain
  unverified. A changed parent signature can preserve its transaction ID and be
  accepted as unverified funding context. The native runner preserves this as a
  limitation control; it must never mark parent spends as verified.
- Known earlier pool-output dependencies may be reported as exact public edges.
  They establish neither human ownership nor segregated value flow. Future pool
  references, duplicate consumes and unsupported parent-to-parent ancestry reject.
- A proof mutation changes observed proof bytes but the Python extractor cannot
  authenticate it. Native verification is a separate measured obligation.
- Rebuilding a public witness does not establish private ownership, private value
  conservation, correct encryption, delivery, recipient scanning or anonymity.
- The descriptor, accepted-chain view, prefix completeness, freshness/current
  spendability and data availability require external authentication. No chain
  acceptance is claimed; the historical fixture is not current wallet behavior.
- Request times and identities remain absent. Block-header timestamps are not
  silently relabeled as request minutes. No frozen observer is called.

The public-only witness is distinct from a private note-membership path. These
checks preserve the native-KAS backing and independent-exit assumptions; they
introduce no token, privileged path, funded action or mainnet operation.
