# Dummy visibility: additive source check

**No current constant-CM or zero-ciphertext dummy-role leak was established.**
The selected continuing Auth528/change-wallet path randomizes the zero-value
note's rho and uses a genuine sealed-box-shaped ciphertext. This is a source
check, not a new classifier run or proof of indistinguishability. Frozen source,
observer plans/results and all earlier packets remain unchanged.

## Current path and the easily confused cases

| Case | Exact source behavior | Public inference |
| --- | --- | --- |
| Continuing zero-value output | [change_action.py:295](../../../../poc/private-change-wallet/change_action.py) constructs Note168 as72zero bytes, fresh rho32, then64zero bytes; its CM is SHA256(tag,D,Note). The [circuit:377](../../../../poc/private-cashout-prover/src/circuit.rs) forces zero owner/incoming/key/nativePK for a zero-value output, but forces rho zero only for terminal. [Note::dummy_output](../../../../poc/private-cashout-prover/src/lib.rs) also randomizes rho. | It is not the publicly computable commitment of an entirely zero Note. This relies on correct entropy; the circuit does not prove randomness. |
| Continuing dummy ciphertext | [opaque_dummy:112](../../../../poc/private-change-wallet/change_action.py) derives a fresh throwaway delivery public key and genuinely seals random216 plaintext bytes, producing264 bytes. Positive outputs use the same established sealed-box format for their real receipts. | It is not264zero bytes or a wholly uniform random264-byte blob. This removes neither every possible classifier nor external side information. |
| Slot alignment | [public_adapter.py:58](../../../../poc/private-exit-recovery/public_adapter.py) pairs CM slot i with ciphertext slot i. | A reliable ciphertext/CM dummy classifier would undo output-role shuffling. No such all-zero classifier applies to the selected continuing path. |
| Terminal | Entire private output Notes, including rho, are zero; Auth CM fields are zero sentinels, ciphertext528 is zero, and no CM is appended. | Terminal R=0/no-append is already public. Zero Auth sentinels are not appended commitments to zero notes. |
| Canonical-zero input padding | [InputWitness::padding](../../../../poc/private-cashout-prover/src/circuit.rs) uses Note::zero privately; its public dummy NF is generated from separate dummy key/seed and actual slot. | A private canonical-zero input is not a published constant output CM. Constructor names alone do not identify a wire leak. |

If an implementation actually appended
`C0(D)=SHA256(KPX1NOT\0 || D || zero168)`, any chain observer knowingD could
recognize that exact CM under the assumed binding/collision resistance.
Likewise an all-zero continuing ciphertext would publicly label its paired slot.
Those are real design traps, but are not the selected source behavior above.
The older v6 [zero-value output helper](../../../../poc/shared-pool/src/two_input/harness.rs#L23)
also creates fresh receive material; its canonical Note::dummy is used on the
distinct no-output exit path. Do not infer current output behavior from that
older constructor or copy its185-byte exit framing into Auth528.

## Established design and existing coverage

Pinned Orchard [dummy output construction](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L544-L566)
uses a random recipient and fresh note randomness at value0. Its
[encryption path](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L570-L592)
retains a valid ephemeral public key. A separate restricted-mode rule randomizes
only the encrypted-note component for certain fabricated outputs; it is not a
license to replace another protocol's entire structured ciphertext with uniform
bytes. No Orchard security result transfers to this wallet.

The existing [padding result](../../privacy-recovery/observer/PADDING-RESULTS.md)
already records the historical uniform264-byte prefix classifier:129/256 old
pads flagged versus0/256 real and corrected sealed pads. That closes the
specific sampled classifier only. Terminal zeros are expressly outside it.

Frozen integer observer v1 receives opaque CMs and public arithmetic/topology,
not ciphertext bytes or CM preimage classifications. It therefore does not
measure format distinguishers; its conservative arithmetic-only claims stand.
A future heldout threat model must explicitly include any known public
byte-derived facts rather than silently treating distinguishable padding as
opaque. This note changes no frozen observer input or score.

Keep overlapping retry/operator Auth/NF preparations private: cross-version
pair intersections can reveal the stable real NF even when each selected
transaction shuffles slots. Per-attempt changes also need not conceal which
dummy CM stays unchanged. This is an evidence-publication boundary, distinct
from the all-zero hypothesis.

For future compact policy, terminal omission of already-public inactive bytes
does not newly expose a continuing change slot. A continuing full cashout with
an observable no-append form would reveal its zero-private-change shape and,
under one-real-input policy, input valueP+fee. That privacy/fee tradeoff remains
open. The [circuit obligations](../fees/CIRCUIT-OBLIGATIONS-01.md) already preserve
variable continuing dummy rho, terminal canonical zeros and distinct active CMs.

## Exact local source identities inspected

- circuit.rs: `ef8f4fca15bd0f363d50f734d6d751360455b5a52fe35ea6486f01259fa90b64`
- prover lib.rs: `817e71ef4fef3dbfdd47914243347ec3c082b86bfe6f94fd1768f22c5eae638b`
- change_action.py: `babebf8c020e09e408388ff0bfe4cd70ca71a1c8c28bac758d682a3293eff45f`
- public_adapter.py: `be415bef7eb98360a27b92f94343e3392766f950b43804aad2a89528058b35c0`

No implementation, cryptography, witness, PK, seed, RPC, heldout evaluation or
new population/privacy qualification was performed.
