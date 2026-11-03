> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Public model-to-native observation parity preparation

Status: the small public-fixture check passes. This package establishes a **partial byte-backed observation mapping**, not a valid input bundle for the frozen price observer and not a native/proof/chain validation result.

The pinned historical rehearsal contains 15 serialized transaction JSON bodies: one funding parent, a founding reserve and 13 v6 operations. The check observes 3 ADMIT, 4 SPEND and 6 DRAIN operations, including one partial payout and four historical anchors. These are observations of the named public fixture, not the active 512-history attempt or current wallet behavior.

## Files and use

- [SOURCE-PINS.json](SOURCE-PINS.json): exact Forge checkpoint, source SHA256 identities and the three public fixture identities, sizes, Git blobs and repository paths.
- [field-map.json](field-map.json): the 17-field-category mapping, native counterpart, reduction or omission, source references and future input requirements.
- [observation-parity.schema.json](observation-parity.schema.json): machine-readable contract for the partial projection. Unsupported model fields are null or absent with an explicit reason, never guessed values.
- `native_surface.py`: Python standard-library parser of the pinned public fixture, with byte-framing and consistency checks.
- `check_fixture.py`: tiny positive, malformed-byte and limitation controls. It writes `public-native-surface.json` and [validation.json](validation.json).
- `public-native-surface.json`: partial model field values, retained native-only metadata and 91 lossless references to raw byte regions in the pinned receipt.
- [validation.json](validation.json): measured control outcomes, runtime, peak resident memory and coverage gaps.
- [MANIFEST.json](source-manifest.json): exact package file hashes, excluding the manifest itself.

Run from this directory with `python3 -B check_fixture.py`. There are no third-party dependencies, model imports, proof generation, network calls, builds or installs. Each validation case is constrained to less than one second and process peak RSS below 100 MiB. The final run took **0.0132 seconds total** and **25,231,360 bytes peak RSS** (24.1 MiB). The parser alone was about 0.002 seconds. Timings are local measurements, not native-validation benchmarks.

Amounts are integer sompi. JSON consumers must preserve integer precision; some legal values exceed JavaScript's exact Number range. The parser supports this pinned v6 layout only. A missing fixture, hash mismatch, unsupported layout, missing funding parent or failed consistency check stops the check; it does not substitute guessed bytes or fields.

## What the mapping establishes

| Native observation | Partial model correspondence | Reduction or gap |
|---|---|---|
| Authorization deposit/payout/fee; selected funding value; actual reserve/payout outputs | `deposit`, `payout`, `fee`, `reserve` | Existing fields are decoded and cross-checked. No monetary-field deletion/reconstruction or prediction experiment was run. |
| Reserve outpoints and operation mode | `event`, `event_id`, `mode` | Dependency ordinal is derived; transaction ID strings are retained but not recomputed. Actual native input/output arity remains separate. |
| Exact commitment/nullifier bytes and slots | `commitments`, `new`, `nullifiers` | Native founding adds commitment position 0 before the first operation. Counts are not silently reset to the arithmetic model's empty start. |
| Anchor count/root and old/successor states | `anchor_count`, `count_before` | Counts are representable; roots and history state have no field in the arithmetic event schema. |
| Actual funding and payout script bytes | `destination` can retain the payout script | Fresh synthetic destination labels would discard native script equality. A native script is not a human identity. |
| Raw payload, witness, proof, redeem script and public-input digest limbs | None in the arithmetic event schema | Preserved in native-only metadata or by exact file/pointer/offset/hash references. The model does not represent these bytes. |
| Receipt block-header timestamp | No valid `minute` conversion | A modeled request minute is a different observation; `minute` remains null. Header time is retained verbatim. |
| Funding outpoint and surrounding transaction graph | No automatic `funding_group` or model `bridge` object | They require a declared classification and representation contract. Raw parents and graph references remain available. |
| Experiment roles/adversaries, ownership directory, participant records | No chain-only native counterpart | All are explicit unsupported/missing channels. The legacy descriptor's source information is not converted to a 32-role directory. |

The frozen model creates fresh opaque event/funding/destination/nullifier/commitment labels in `working_balance_model.py:236-256`. Its public event constructor is at lines 239-244. The observer's closed field set is `working_balance_observer.py:24-28`; its input checks require a 32-role universe and initially empty reserve/commitment accounting at lines 65-89. This package does **not** call that observer or claim complete schema parity. The null timing/role fields and retained native bootstrap deliberately expose the missing adaptation contract.

The existing native usage source itself labels its supplied minutes as modeled rather than chain timestamps (`native_usage_surface.py:141-152,239-244`) and makes pinned replay plus funding-bridge validation caller prerequisites. This package preserves those distinctions.

There are **no repeated funding/payout scripts, commitments, proofs, ciphertexts or ciphertext prefixes in the inspected fixture**. Consequently this package confirms that the exact values are observable and would be discarded by the corresponding normalization; it does not measure an address-reuse leak or its effect on linkage/price accuracy. The script grouping covers founding funding, selected admission funding and payout scripts, not every output's script. Complete source bodies remain retained.

## Evidence boundaries and controls

The source checkpoint is `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02` on Forge, with per-file hashes for relevant working-tree sources. Only the three named already-public fixture files were copied. `src/two_input/replay/tests.rs:3-4,19-43` documents these retained public bodies and verification key as offline fixtures; this check did not read its separate result file or execute those Rust tests. Existing commentary in source is provenance context, not proof that a test was run here.

| Evidence tier | What this package has | What remains unestablished |
|---|---|---|
| Arithmetic model | Pinned source, closed-field mapping and partial native projection | An observer run, calibrated privacy outcome, model/native behavioral equivalence |
| Native bytes | Pinned serialized JSON bodies; strict framing; actual values, outpoints, scripts, state continuity and ciphertext digest cross-checks | Kaspa binary-wire encoding parity, transaction ID/full-hash recomputation, generic native validity, public settlement-witness recomputation |
| Proof/covenant | 128-byte proof slots; 377-byte authorization; digest-derived public input limbs; VK identity and P2SH script binding | Cryptographic proof verification, VM/covenant execution, correctness of ciphertext encryption or decryption |
| TN10 | A retained historical receipt and its header fields | Fresh chain acceptance, header/Merkle authentication, current wallet behavior or current testnet state |

All corresponding machine-readable verification flags are false. A deliberately altered proof byte is accepted by the *structural parser* and changes the observed proof hash; this limitation control confirms that the parser is not a proof verifier. The on-disk pinned-file check would reject such a change to the retained fixture. This is not a native acceptance or rejection result for the altered proof.

Other in-memory controls reject a broken ciphertext binding, funding-value binding, reserve outpoint, unknown mode and payout output value. A positive control round-trips all 91 raw byte regions, and checks that unsupported modeled fields stay null while receipt timestamps and the native founding count are retained. These small malformed-fixture controls do not erase public amounts or score guesses against private truth.

Network-origin observations, first-seen time, RPC sessions, IPs, retries, proof-completion time, recipient delivery metadata, private note amounts/openings and input-note membership paths are not available from these fixture bytes. The public settlement witness must not be described as a private note membership path. This legacy rehearsal cannot establish current v2 key rotation, ownership or delivery behavior.

## Deterministic protocol for a future native-backed privacy test

1. Declare the source/dependency checkpoint, observation prefix and adversary profile before capture. Use a separate public development fixture, never the active held-out attempt or its private ledger. Freeze a descriptor with network, genesis, pool domain, founding transaction identity, initial commitment/value and verification-key digest.
2. Retain each complete native transaction body exactly as emitted by the pinned serializer, including payload, all signature scripts, inputs, output indices and scripts. Include the founding transaction and every selected funding parent. A bridge needs all of its consumed UTXOs and exact payout-to-parent-to-funding references, not a balance summary. Hash the original bytes and record JSON pointers/byte offsets; do not replace addresses or scripts before capture.
3. In a separately budgeted offline validation lane, use the pinned native transaction parser, pool replay and native funding-bridge validation. Record recomputed transaction IDs/full hashes, proof/covenant execution, public state/witness validation and the exact validator/dependency hashes. A structural parser pass alone may not set any of those flags true. No fresh proof or live transaction is necessary to validate this existing fixture, but that work was not run here and its cost has not been measured by this package.
4. Produce two retained views from the same validated public bytes: an exact native surface and the declared model projection. Compare direct fields exactly; preserve bootstrap indexing and historical anchors. For opaque identifiers, explicitly choose a stable equality-preserving mapping or declare the equality loss. Retain a machine-readable list of omitted native regions and values. An adaptation that silently discards native initial commitment count or invents request minutes fails parity.
5. Supply external ownership directories and participant records only as separately hashed, provenance-labeled channels. Chain-only output may not inherit them. Tag every timestamp by its source (`modeled_request`, `block_header`, `first_seen`, `submission`, `proof_completion`); absence is not zero, and block time may not be relabeled as request time.
6. Require public coverage of ADMIT, private SPEND, partial payout, DRAIN, founding/bootstrap, historical anchors and any claimed bridge class. This historical fixture covers the first six, but supplies no repeated-script case and no current-v2 wallet behavior evidence. Before claiming that equality is preserved or lost empirically, add a separately published native fixture that actually contains the relevant repeated public script or object. Do not manufacture a repeated value and present it as accepted native evidence.
7. Stop on missing parents, descriptor or VK disagreement, pin drift, unsupported serialization, a failed native verifier, ambiguous observation provenance or an unhandled field. Report `unsupported`/`missing` and its cause. Do not run the frozen observer until all required model fields have a declared, tested source and the bootstrap incompatibility is resolved under a new explicit adapter contract.

The smallest next check is review of this frozen package plus the existing tiny parser controls. A later native-validity pass should reuse these exact public files and separately record its cost. Additional privacy experimentation, proof work, live capture and adaptation of frozen sources require their own bounded assignment; none occurred in this lane.
