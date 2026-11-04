# Proof, encoding and batching lessons

[Knowledge guide](README.md) · [Costs](costs.md) · [Unfinished reviews](unfinished.md)

The [RFC-0004 crypto review](../../research/rfc0004-cryptographic-profile-review-2026-11-03.md)
now pins the complete repaired Orchard V2 research reference, exact role widths,
two-Action shape and preferred native Halo2/RedPallas verification. The archived
Orchard-derived guest is a different relation, not a complete Halo2 wrapper.
The unchanged circuit proves `u64` values; native monetary bounds need the
explicit backing induction. No existing Kaspa tag accepts the full construction.
Independent specialist approval and native integration remain outstanding.

The next authorized [unfunded interoperability package](../../poc/orchard-interop/README.md)
now supplies real complete Halo2 bundles, both signature roles, an experimental
effects/codec contract and actual proof/signature rejection tests. Public
artifacts reproduce byte for byte; a Python parser cross-checks framing/digests.
Its key fingerprint is a locked Rust Debug diagnostic, not a portable consensus
format. It proves no ordinary funding, accepted native state or privacy target.
The historical guest remains a different relation; the new package does not
retroactively qualify its old proofs or missing parameters.

The [native key specification](../spec/native-shielded/key-identity.md) now pins
actual portable mathematical VK/parameter/constraint bytes and the existing
transcript scalar, not Rust formatting as a new wire format. Upstream currently
derives that scalar from Debug; retain it as fixed compatibility data rather
than replace it with the capsule hash. Read-only export from copied pinned
sources reproduced the capsule and reverified existing proofs. A native
importer/backend and independent soundness review remain unimplemented gates.

The later [native authorization result](../../poc/native-tx-validation/README.md)
uses the proposed v2 bytes and message with fresh complete Halo2, both RedPallas
roles and standard Schnorr/ECDSA signatures. It compares the old encoding vector
without relabeling its original signatures as native authorization. Actual
changed-statement/proof/signature negatives, supplied-context replay checks,
all-prefix rejection and exact regeneration pass. Carry this message-compatibility
evidence; its synthetic view, unpriced mass and upstream key constructor still
provide no accepted backing/state, portable import or recovery qualification.

## Preserve the evidence ladder

Constraint satisfaction, local cryptographic verification, a zkVM segment,
lift/join, a complete outer receipt, native Full validation, accepted chain
settlement and independent user recovery are distinct results. Historical
classifier work passed some layers while timing out or exceeding practical
budgets at later layers. A partial proof cannot be promoted to a complete one.

The 128M one-hour failure, phase diagnostics, L40S qualifications and later
complete receipts coexist in the [source index](sources.md). Their fixed inputs,
images, segment settings and resource profiles differ. [independent RTX 3070 reproduction](documents/b3ed0a758e9200456318a9e26b8342db78d5c327.txt) retained
four receipts with a po2=19 adaptation in 627.3 seconds; that is reproduction
of the selected workload, not accepted native ancestry.

## Checks to preserve during any reuse

| Boundary | Required knowledge |
| --- | --- |
| Encoding and verifier APIs | Complete input consumption, canonical/subgroup-checked points, exact key/input arity and explicit version behavior. Raw Arkworks 0.5/0.6 behavior differs; [strict encoding/arity differential](documents/1849f7b489e307a5b02a1b15182d259c64e8819f.txt) does not establish a native vulnerability. |
| Proof/public-input binding | Keep the real changed-input pairing rejection at `6fdc5fc6`; matching a test fixture's own expected bytes is weaker than verifying a changed statement fails cryptographically. |
| Two-bundle relation | Bind both actual authorizations, exact P/A/Q/C/bijection contract, output multiplicity, current nullifier insertion and history anchors. [paired proof/compression results](documents/832da77252bdfb3f3b56bd920b236442143f8c2e.txt) remains source/profile-specific. |
| Native state context | Bind current input outpoint, authenticated predecessor, reserve amount and full successor. Proving a transition from supplied state does not establish that state was accepted. |
| Negative outcomes | Require the intended error layer. A parse failure, low budget, stale fixture or missing dependency cannot count as proof rejection. [negative-checker follow-up](documents/e4f3a80120580cb93def507a46537a250e411531.txt) gives concrete corrections. |
| Immutable source/package identity | The current [repair record](../../poc/remote-cuda/CONSOLIDATION-REPAIR.md) restores old packages against exact original sources. Current-source drift continues to reject. |

[compression qualification note](documents/4b69b4e8de333d2e96ec10eb2ddc82474a7e4ee6.txt) distinguishes a 581-byte serialized Groth16 receipt,
a 256-byte SDK seal and the 128-byte native compressed proof. The wrapper's
fixed five public inputs and setup trust remain explicit. Native base/key cost
and bare-predicate success are not complete transaction costs or accepted backing.
The J42 assertion cannot be relabelled the proposed state-aware J336 relation.

## Promising improvements remain conditional

[authenticated cache measurement](documents/90a8571364109e2cb5f360b33e966fedd0ca7308.txt) measures authenticated uncompressed loading, while [selected HMAC sizing](documents/7eb487100c8e69f48abe417e7bcd98c681b24e3b.txt) measures
smaller circuit synthesis. Preserve exact parameter/source/circuit identities;
retest the complete qualified relation when changing cryptographic code.
Neither performance result fixes transparent-withdrawal leakage. A new setup
cannot replace an existing instance's missing public parameters.

Keep the one-v6 compatibility/control branches and [orchestration record](documents/44291489bf0e020e23b7bf0ba5e92a329ea5c0d9.txt) as a record
of what was built, what was blocked and what was merely proposed. An unbuilt
adapter or bounded source acceptance is not runtime qualification.
