> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Native observation parity review

Reviewed 2026-10-22 07:23 UTC on Forge, through SSH alias `forge`.
Repository: `/home/luke/projects/kaspa-privacy-shared-pool`.
Branch: `shielded-kas-research`; HEAD: `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`.
This is source analysis of the listed working files, not an independent check of the active private freeze. The price spec/runner are lead-owned uncommitted files; exact reviewed hashes are below.

## Decision

The price experiment preserves useful public monetary algebra, but its observer is **not a lossless projection of current native transaction bytes or of the current wallet lifecycle**. Its frozen scope already says this explicitly (`poc/shared-pool/PRICE-LEAKAGE-SPEC.md:10-23,35-51`). The findings below do not invalidate its bounded arithmetic question. They block direct extrapolation to native-wallet or chain-only privacy.

1. **Different wallet action:** the model creates mode-1 partial payouts with private change (`working_balance_model.py:218-223`). The v6 relation allows this (`src/two_input/circuit.rs:240-269`), but the current wallet has only Admit, Pay and Exit; Pay sets public payout to zero and Exit pays all selected input value minus its fee (`src/two_input/wallet.rs:225-240,467-525`). “Supported by the relation” and “implemented by the current wallet” must remain separate.
2. **Identity/equality information changes:** genuine funding and payout scripts/outpoints are replaced by fresh, globally unique opaque labels. This suppresses actual script reuse and byte equality, while the experiment adds an explicit initial funding-owner directory. C+D is chain-like arithmetic **plus a declared external directory**, not chain-only identification. The current v2 wallet separates funding/exit derivations; it also explicitly retains v1 behavior (`wallet.rs:173-198`). Random labels cannot test either behavior.
3. **Timing is supplied, not extracted:** modeled minute gaps enter heuristic ranking. Native bytes establish reserve dependency order; neither offline bytes nor these model minutes measure chain inclusion, first-seen, proof completion or network timing.
4. **Cryptographic and delivery surfaces are absent:** the model has no real proofs, ciphertexts, keys, public state roots or settlement witnesses. Some omitted fields are reconstructible public-state redundancy, not new private-note membership information. Others permit equality/framing/delivery observations that the model cannot evaluate. Their mere existence does not establish a leak, and the model cannot establish their absence of leakage.

No active evaluation seeds, truth, predictions or correctness were read. No build, test, proof, experiment, broadcast or service change was run. Only this report and its field table were written outside the active checkout.

## View boundaries

| View | Actual information boundary | Price experiment treatment |
| --- | --- | --- |
| Chain-only / offline public transaction bodies | Native outpoints and scripts, output values, reserve lineage, payload, proof/witness bytes, authorization fields and public state. Accepted-chain status, completeness and freshness are separate assumptions for offline replay. | Arithmetic events and opaque labels approximate a subset; no raw bodies or accepted-chain evidence. |
| C+D | Chain information plus an explicit externally supplied association from initial funding output/group to role. A chain output does not itself identify a human. | This is the public-side evaluation profile. The directory is present in every C+D job. |
| Participant / pooled | Own authored inputs/outputs, own decrypted positive notes and local keys; recipient contact/receive-envelope information when actually exchanged. Incoming note plaintext contains owner/incoming key, value and rho; it does not contain a sender identity field. | Pooled adds eight roles' authored event/input/output mappings and positive receipts. It omits keys/openings/delivery status and does not include every possible participant or social observation. |
| Network / service | Origin/peer/IP observations, RPC/session linkage, query patterns, first-seen/retry/proving latency and off-chain recipient-envelope exchange, if measured by the relevant observer. | Absent. The wallet component is local/offline, and native bytes alone do not supply these observations. This review makes no network privacy claim. |

Sources: `working_balance_model.py:377-413`; `price_leakage_trial.py:140-176,228-232`; `src/two_input/wallet.rs:1-5,76-94,299-355`; `src/protocol.rs:92-106,175-204`; `src/two_input/replay.rs:18-33`. All paths in this report are relative to `poc/shared-pool/` unless a full repository-relative path is shown.

## Concrete field map

The same map is supplied in [field-map.csv](field-map.csv). “Extra native observation” means observable in the native representation, not a demonstrated successful inference.

| Field | Genuine v6 bytes / current wallet | Arithmetic observer | Extrapolation consequence |
| --- | --- | --- | --- |
| Deposit, public payout, reserve | Authorization has exact u64 sompi deposit/payout/fee; actual selected parent value, native outputs and reserve accounting must agree. | Exact integer `deposit,payout,fee,reserve`; same reserve equation. | Core monetary algebra is preserved for modeled operations. Exact transfer is conditional on matching operation policy and funding context. [A,B,C] |
| Private payment and change | Notes commit to owner, incoming key, value, rho and domain. Current Pay puts recipient in slot 0, sender change in slot 1. ADMIT credits self in slot 0, random encrypted zero note in slot 1. Relation alone does not enforce that wallet ownership/order convention. | Same payment/ADMIT output convention; amounts/owners hidden except permitted participant records and inferred ADMIT credit. | Wallet-policy assumptions are public inference assumptions, not cryptographic disclosure of every note value. Zero note value is not a zero ciphertext. [A,D,E] |
| Operation shape | Public mode 0/1/2; native inputs = 2 for ADMIT, otherwise 1 reserve input. Private inputs are one or two real notes behind two nullifier slots. Non-DRAIN appends two commitments; DRAIN appends none. | Mode and appended positions retained; no native input/output arrays. Mode 1 includes payment, merge and partial payout. | Much arity is derivable from retained mode/payout/reserve. “Two nullifiers” does not reveal two real inputs. Partial wallet mismatch remains material. [A,B,D,F] |
| Founding/bootstrap | Founding tx has a funded reserve, ordinary change, one initial commitment at position 0; first spend publicly binds bootstrap value before admission is allowed. Counts are odd. | Starts with zero commitments/reserve and 32 ADMITs; no founding transaction, bootstrap or its fees. Counts are even. | Whole-history native equivalence fails without an explicit startup mapping. Do not silently normalize away bootstrap evidence. [A,G] |
| Native graph | Exact tx IDs, full hashes, input outpoint indices, reserve parent linkage and complete funding-parent bodies. Grouping by parent tx is different from grouping by selected outpoint or owner. | Fresh event/funding labels; payout/bridge/change references and source values retain a simplified graph. | Public ancestry amount links exist in both, but common-parent/output-index associations and complete parent shape are omitted. An ancestry link is not proof of source/destination common ownership. [A,C,H] |
| Address / script bytes | Funding and payout P2PK scripts, state-dependent reserve P2SH scripts; v2 separate funding/exit derivations, v1 compatibility. Caller chooses funding key index; exit index = lowest selected note position. | Fresh unique funding/destination labels; no script equality, address encoding or key-derivation profile. | Cannot measure script reuse or the known v1/v2 difference. Model does not justify an “addresses add nothing” claim. [A,D,H] |
| External owner directory | Descriptor identifies pool/network/domain/VK/founding transaction, not a participant roster. Public script equality can propagate an already supplied association, but does not supply a human name. | 32 role universe plus `initial_funding_owners` supplied explicitly. | Any owner-based advantage is conditional on this external directory and wallet conventions. [A,G,I] |
| Nullifiers | Two nonzero distinct public nullifiers per active spend: keyed real-note nullifier or keyed random padding nullifier; zero slots on ADMIT. Indexed-set update witness is also public. | Same zero/nonzero slot shape, but globally unique independent random labels. | Assumes hiding/uniqueness instead of testing bytes or derivation. Omits public set mechanics; does not expose real-input count. [A,E,F,J] |
| Commitments/equality | Exact hashes; distinct within an output pair. Equal commitment bytes at different positions are supported, with position-bound spentness. | Every label is globally unique, including zero-valued output commitments. | Equality across positions is removed by construction. Normal fresh-wallet randomness may avoid repeats, but the protocol surface permits them. [A,E,J,K] |
| Anchor/root/history | Public authorization exposes selected commitment count/root; historical root accepted. Current helper selects latest root. Successor state exposes cm/nf counts and cm/nf/history roots. | Only `anchor_count` and `count_before`; model always chooses current count for spends. | Removes real root/history selection and representation. Current-helper count policy matches after startup mapping; general historical-anchor behavior is outside model. [A,B,E,J] |
| Public settlement witness | 4,368 bytes: anchor-history path, nullifier predecessor/insertion updates, commitment-append and history-append paths. Reconstructible from public history plus auth. | Omitted. | These are **not** the private spent-note membership paths. No unsupported claim of exposed note positions follows. A parity check should prove reconstruction rather than assuming it. [B,J,K] |
| Proof / public inputs | 128-byte Groth16 proof; 24,576-byte redeem script including domain, old state and VK; two field inputs derived from the two 16-byte halves of SHA-256(public authorization). Authorization itself is public. | No proof, VK, public-input digest, script or validity evidence. | Cannot test proof framing/equality/implementation confidentiality or cryptographic correctness. Digest compression does not hide the public authorization fields. [B,F] |
| Ciphertext / delivery | Two 185-byte sealed-box ciphertext slots; their digest is bound in auth. DRAIN uses 370 zero bytes. Non-DRAIN encrypts real and padding notes. Wallet rejects wrong-domain/commitment/owner/range delivery; binding does not prove correct encryption. | No ciphertexts, ephemeral-prefix bytes, lengths, binding or decryption acceptance. Positive participant receipts are supplied as ideal facts. | Cannot measure ciphertext equality/metadata or whether valid commitments are actually deliverable. Do not convert model receipt availability into a recoverability claim. [D,E,K,L] |
| Fees, size, mass | Current wallet pool fee = 40,000,000 sompi, but relation requires positive bounded fee. Native ordinary funding fee is computed from mass; native tx carries storageMass, budgets and signatures. | Pool fee fixed at same value; bridges fixed at 100,000 sompi; no mass/size/signatures. | Pool-fee arithmetic matches current helper. Funding/change amounts and feasibility need actual native construction; constant bridge fee is not a native fee guarantee. [A,B,F,M] |
| Time / order | Reserve outpoints establish strict dependency order. Raw native envelope has no transaction wall-clock timestamp. Native-usage timing sidecar explicitly declares modeled minutes. | Monotone modeled `minute`, event ordinal; minutes affect support ranking. | Useful model timing evidence, not real network/chain timing. It can change rankings; direction of extrapolation is not established. [A,H,I,N] |
| Transaction envelope | Version 1, native subnetwork, zero gas/locktime, max sequence, 3,000 reserve compute budget; ADMIT signature/budget; canonical IDs and actual output scripts. | Omitted. | Many values are fixed and mode-derived in this candidate, not automatically new identity leakage; implementation/version fingerprints and exact-byte parity remain untested. [B,F,M] |

## Byte layout and source anchors

The native payload is fixed at **5,228 bytes**: framing [0,8), authorization [8,385), ciphertexts [385,755), successor state [755,860), public settlement witness [860,5228). Reserve signatureScript is **24,709 bytes**: 128-byte proof plus 24,576-byte redeem and push framing. These constants cover this implemented v6 candidate, not all native transactions. Native JSON byte length is not binary serialization size or consensus mass.

- **A:** `working_balance_model.py:13-18,72-109,196-304,377-413`; `working_balance_observer.py:24-28,65-145`.
- **B:** `src/two_input/mod.rs:20-111,158-242`.
- **C:** `src/two_input/replay.rs:119-181,229-321`.
- **D:** `src/two_input/wallet.rs:173-198,225-240,426-537,581-614`.
- **E:** `src/two_input/harness.rs:23-42,54-143`; `src/protocol.rs:65-123,175-204`.
- **F:** `src/two_input/circuit.rs:128-218,223-278`; `src/two_input/covenant.rs:200-267,553-634`.
- **G:** `src/two_input/replay.rs:18-58,229-255`; `src/two_input/tree.rs:154-166,218-228`.
- **H:** `early_privacy_surface.py:224-317,334-338`; `native_usage_surface.py:80-138,247-263`.
- **I:** `native_usage_surface.py:118-152,247-304,329-339`.
- **J:** `src/two_input/tree.rs:184-287`.
- **K:** `early_privacy_surface.py:124-167,299-360`; `src/two_input/wallet/tests.rs:702-764` (explicit unproved local fixture, not accepted native evidence).
- **L:** `src/two_input/wallet.rs:299-355,581-614`; `src/protocol.rs:92-106,182-204`.
- **M:** `src/native.rs:263-300,373-411,442-500`.
- **N:** `working_balance_observer.py:405,460-472`; `native_usage_surface.py:141-152,222-244`.

## Smallest decisive later parity check — proposed, not run

Use **one retained public v6 rehearsal trace**, not fresh cryptography or any price-evaluation ledger. The existing replay integration fixture is sourced solely from `evidence/2026-10-20-two-input-tn10/rehearsal/descriptor.json`, `rehearsal/chain-confirmed.json` and `verification-key.json`. Reuse the descriptor/lineage/parent extraction in `src/two_input/replay/tests.rs:19-43`; its retained trace has 14 pool-lineage transactions according to the test assertion at line 82. The test explicitly requires no secret, proving key, fresh proof, setup or RPC (`tests.rs:3-4`). This is a public historical mechanics fixture, not evidence of current-wallet key behavior.

1. With an already built pinned replay binary, replay the public trace once and independently decode it with the existing `early_privacy_surface.project`. Do not build or load a proving key. Read only the named public transaction/descriptor/VK files; omit results, predictions and any participant/truth package.
2. Produce an operation-by-operation projection with two columns: fields available from native bytes versus fields the price schema accepts. For every purportedly retained field, compare exact integer deposit/payout/fee/reserve, public mode, appended positions, nullifier-slot shape and anchor count. Keep founding/bootstrap explicit; report the initial-position offset and any unsupported operation instead of altering the trace to make it pass. Minute and owner-directory values must remain visibly external/unavailable.
3. Independently compare the raw envelope to the derived shape: input/output arity, payout/reserve scripts and values, 5,228-byte payload regions, 128-byte proof, 185-byte ciphertext slots, zero DRAIN padding and public witness reconstruction. Preserve equivalence classes when labels are renamed; fresh-per-occurrence relabeling must not be accepted as equality-preserving.
4. Close the immediate wallet mismatch with a source/schema assertion: `Action` cannot represent a partial payout amount, while Pay's payout is zero and Exit uses the full selected total minus fee. Do not generate a hypothetical partial-wallet trace.

**Pass criteria:** every claimed retained chain field has an exact byte-derived explanation; startup normalization and externally supplied fields are explicit; omitted equality classes and fields are listed; public-witness reconstruction agrees; no secret/private opening appears in the output. Missing requested shape coverage is a documented coverage gap, not a pass. Even a full pass is a projection/mechanics result, not a privacy qualification or equivalence of the price workload to current wallet execution.

**Cost:** one public trace, at most 13 existing-proof verifications plus decoding; one lightweight sequential CPU job, zero fresh proofs and zero GPU/proving-key load. Expected seconds to a few minutes, not benchmarked here. If no pinned binary is available, stop at the decode/source check and record native validation as pending rather than compiling during the active experiment. This check can falsify an incorrect native mapping cheaply; it cannot settle real timing, participant disclosure completeness or privacy of omitted cryptographic bytes.

## Reviewed source identities

```text
104bea66d0798c523de6c5d283861d4d4867632c0e30189f8179c1763bcfa885  PRICE-LEAKAGE-SPEC.md
e1901ff96e13af0dc2bb2f556cf356c9df800a88d2a48d423caea61f084b97d7  price_leakage_trial.py
a1a8c3989d85f2309dcd726cd2d076c77c4ea77e407a7dfbd8c05f975dafbe00  working_balance_model.py
b492d5a2e63836751f51f5151c002c3ec6492c224b518846c45eca23f3ea7495  working_balance_observer.py
95f87feb361f92f25dcbaa08d8a667a3bb809e60b11e857959929c1574a32ff6  early_privacy_surface.py
aa60a0fb1c678b942aecb4c5786b861e0d705a5f1805d76d0063fe372eefed9c  native_usage_surface.py
255f8e908fcb1c4a76dcc8ebe0ca5f4e9ddbadc8ba46f63036cb413298bc8150  src/two_input/mod.rs
3039fe885379aeec3b2378ee4b881a46e01b5bc1d3e6e68d706852c6a39070e5  src/two_input/wallet.rs
59071901c3abc25daab68c982ef065f8755c09abbb2ce30e6010d821813dd2a7  src/two_input/circuit.rs
3b6d73c1ebada11d156f3020b444c881160e2f4d8eb7ae629a23ac267bf0d96d  src/two_input/covenant.rs
1bad02792f96632892487ec6af9aa94aa4fc2f14c6ecab28602f75174286583d  src/two_input/harness.rs
9fc004721ae2a22c6faa26f2a046eefd7bb707e3c83077be01a7913b464891ed  src/two_input/tree.rs
9e2de9ae756e9af65fb3f7c75fff7170e3a06170a8eb85d0b0da05d758b1b66e  src/two_input/replay.rs
97e37e58cedbc6dbf4b4ca4ae9c1e634f7c4b2010275076b2721db2ea20dbb1c  src/two_input/replay/tests.rs
5243cab1b36e0d9cae8bf13e81b7fcdb033c8dc1bc7405daa401c69334cc4ec4  src/protocol.rs
626f96dfcd66ef8dfa2ef1023e985390d25b4573eac01bb5623796799a93435f  src/native.rs
```
