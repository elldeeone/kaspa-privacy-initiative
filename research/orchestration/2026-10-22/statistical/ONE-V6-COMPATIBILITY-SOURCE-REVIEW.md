**BOUNDED SOURCE ACCEPTANCE — no blocking finding in the two added adapters.** This accepts the implementation of the frozen, single retained row-6 comparison for separately owned build qualification. It is not a build, runtime, cryptographic-verification or execution-release result.

Owner: `/root/statistical_review`. Actual start: **2026-10-22 11:13:10 UTC**. Hard deadline: **11:33:10 UTC**. Source decision reached at **11:17:41 UTC**, within the 20-minute bound.

Reviewed checkout: `/home/luke/projects/kpi-one-v6-compatibility-2026-10-22`, clean at commit `acba8b04237e62a5bbc3eb93eb10faa1722a59ea`, with sole parent `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`. The commit adds exactly the two files below; core, manifests and locks are unchanged. The protocol is the frozen document at docs commit `2f65a3e574c528132ca265de7d7cdf7782e94f6d`.

For the source anchors below, **R** is `poc/shared-pool/src/bin/one_v6_reference.rs`; **C** is `poc/takeover/host/src/bin/one_v6_candidate.rs`, both relative to the reviewed checkout.

| Requirement | Source evidence and finding |
| --- | --- |
| Exactly one original public row | R:96–134,160–218 and C:84–122,148–206 accept no arguments, read only the three fixed JSON paths, reject redirected/nonregular paths, hash bytes before parsing, and require the first metadata-qualified row to be index 6. They then use that fixed row, framing, receipt ID and component ranges; there is no proof-driven selection or fallback. The transaction ID is expressly source-supplied, not recomputed (R:253–255; C:241–243). |
| Full authorization and ordered ciphertext binding | R:213–245 and C:201–233 check all pinned component hashes and SHA-256(C0 || C1) against authorization bytes 345–377. The full 377-byte authorization is retained and hashed. Its prefix, domain, count, anchor, nullifiers, commitments, mode, payout, fee, zeroed inactive fields and ciphertext digest are covered. Each adapter derives from original bytes, rather than accepting the other adapter's output. This is not a claim of independently authored parsing implementations. |
| Checked canonical decoding and point policy | R:137–150,268–305 and C:125–138,256–293 use checked compressed decoding, full consumption, validity checking and byte-identical reserialization; require IC length 3; explicitly check every VK/proof point on curve and in subgroup; and reject identity proof A/B/C. VK identity flags are reported without adding a one-sided rejection rule, as the protocol requires for this retained key. |
| Two exact scalar inputs | R:307–337 and C:295–319 hash all authorization bytes, split the digest into two little-endian 128-bit integers, check the frozen decimal strings, and require each canonical scalar encoding to be those 16 bytes followed by 16 zero bytes. The derived scalars undergo checked full-consumption decoding and value round-trip checks. R additionally parses and round-trips the existing Authorization and requires its inputs to match. The existing implementation is `poc/shared-pool/src/two_input/mod.rs:69–112`; its two 16-byte field embeddings agree mathematically with these bounded integers. |
| Exact intended verifier paths | R:338–354 invokes Arkworks 0.6 prepare_verifying_key/verify_proof using the decoded public VK. C:321–344 hashes that same public VK, then calls from_validated_program_key and verify_inputs. The existing helper at `poc/accelerated-bn254/common/src/lib.rs:89–140` accepts those 0.5 types and uses the generic two-input path. Neither adapter invokes the old pinned-key/classification path, a proving function, native execution or a guest. |
| Honest result and failure reporting | R:338–394 and C:321–383 record actual verifier returns/errors, preserve the last attempted stage and a failure class, and return failure unless the specified verification succeeds. Expected source/lock constants are explicitly labelled as such, with actual adapter/executable/toolchain/feature identity delegated to the coordinator (R:365–372; C:354–361). Infrastructure or process failure cannot be counted as a successful cryptographic rejection. |

Source inspection of the locally present Arkworks 0.5/0.6 serialization, affine, field and Groth16 APIs supports these call signatures and checked-decoding semantics. In both versions, deserialize_compressed requests Validate::Yes. The reference's 0.6 public identity constructor and candidate's 0.5 public infinity flag exist; From<u128> and the reference verification API exist. This inspection does **not** qualify the effective dependency graph, compiler, target, enabled features/cfg, offline cache closure or an executable.

The two workspace lock hashes and all six manifest/lock pins listed in the protocol matched on disk. Actual build and executable identities remain unresolved prerequisites. The candidate still inherits its broad host dependency graph. The coordinator must preserve those identities and compare both eventual reports against the protocol and each other. This review does not authorize a build or run.

No Cargo/rustc command, metadata resolution, project script/import, test, verifier, proof, guest or native execution occurred. No fixture was modified. Only the three permitted public JSON files were read for file hashing; no sibling result/trial/seed/proving-key/wallet/participant/private data was read. No old classifier key was inspected.

Even a later complete pass would establish only this retained bundle's host-side canonical and verification compatibility. It would not establish universal malformed-input equivalence, guest compatibility, two-bundle composition, chain acceptance/current spentness, backing, recovery, exits, cryptographic assurance or privacy. A failed or incomplete build remains build evidence, not a verifier disagreement.

The following SHA-256 values were measured in this source review:

| Input | SHA-256 |
| --- | --- |
| R | `ab513355d0d8e893d3742821a16fb3001ea0e9bc8ee7d10e86c44e50c270585d` |
| C | `75f424c68de986b4059e0caf5b392f2bda6cf91a2f120e1c21ac7de2ef80ba06` |
| Frozen `roadmap/ONE-V6-VERIFIER-COMPATIBILITY-PROTOCOL.md` | `b01cd6bbb4b0d9f097277e5986b0b4de7001b97896f5f74f3777d1ff50919932` |
| `poc/shared-pool/src/two_input/mod.rs` | `255f8e908fcb1c4a76dcc8ebe0ca5f4e9ddbadc8ba46f63036cb413298bc8150` |
| `poc/accelerated-bn254/common/src/lib.rs` | `ff8ef9d2ea1ef93440cadcfaac086ebafad33b2ae505ba3880b596b34660041e` |
| `poc/proof-classification/protocol.rs` (hash API only) | `2e6ccf9442315a342dff72cf63bff0f3c4d8ce7de85af6ff57a8327d6d303d81` |
| Public `rehearsal/descriptor.json` | `795eebdefb3eabea6446b3b1a9bd8c80e7f262fe32f7dfcf39efccbe7bbc07ac` |
| Public `verification-key.json` | `4fd7dc563e4a1f843c99d5517485ba7664a7dcb69057784ca2fac066b20cddaf` |
| Public `rehearsal/chain-confirmed.json` | `75ad01a25b1c534a59f5690c69556584a72e31cb6afeb914530104f00962b3b8` |

The public JSON paths are under `poc/shared-pool/evidence/2026-10-20-two-input-tn10/`. This report is the only file written by this review; evidence_lineage owns its index/commit.
