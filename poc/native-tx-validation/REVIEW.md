# Adversarial second-pass review

This is internal AI source review and executed local controls, not independent
cryptography/accounting approval. [ADR-0104](../../docs/adr/0104-unfunded-native-draft-authorization.md)
defines the isolation boundary. No accepted value transition is implemented.

| Attack or failure | Executed check / remaining limit |
| --- | --- |
| Inflate notes using an asserted input amount | No amount field exists in the packet. Ordered context comes from a separate synthetic UTXO map. Altered amount and compensated two-input substitutions fail actual signatures. This map still has no chain authority. |
| Redirect a payout or edit fee/mass/payload/budget | Changed complete native effects reject both ordinary and shielded signatures. Mass is signed but is a placeholder; no mass-validity or affordability result. |
| Authorize native effects with old signatures | Frozen original native encoding vector still roundtrips; its old RedPallas signatures fail the new native message. Legacy ordinary hashing is never used as v2 authorization. |
| Steal a funding input | Schnorr and ECDSA verify actual distinct message/key/index. Each corrupted signature, swapped slots, wrong key and alternate signature mode rejects. Low-S is checked before ECDSA verification; no silent normalization. |
| Accept a partial proof or a false changed statement | Actual complete Halo2 verifier runs. Canonical changed cv/nf/rk/cmx/anchor, wrong circuit key and corrupt proof reject at proof verification. Both SpendAuth slots and binding signature have separate actual rejection controls. |
| Treat aggregate b as an imaginary Action-circuit range proof | Real Halo2 proof still verifies after b-only substitution; signatures and the exact aggregate binding key reject. Public bounds are checked separately; hidden values remain upstream u64 with independent backing-induction review pending. |
| Spend twice / use stale state | Every real and dummy nullifier is checked against the supplied current set. Duplicate body markers, each occupied slot and an absent anchor reject after a genuine baseline. There is no state writer or concurrent/accepted-DAG engine here. |
| Replay across domains or tree coordinates | Domain/profile and anchor tuple are bound into Q/S. Altered native domain and anchor coordinates reject signatures; supplied wrong domain/anchor also rejects locally. No authenticated native history is claimed. |
| Forge recipient delivery | Recipient/outgoing ciphertext edits retain a passing Action proof but fail signatures. Upstream note decryption and real re-spending are used to generate the transfer/withdrawal, not asserted openings. |
| Parser denial or alternate encoding | Fixed packet/item/blob/proof bounds precede allocation; exact consumption and role-specific point encodings reject malformed inputs. Canonical zero NF and identity cv parse then fail the actual proof; identity rk/epk reject at decoding. |
| Key/dependency drift or provider disappearance | Exact Orchard revision, Cargo.lock and Rust toolchain; fixed capsule SHA plus fail-closed constructor diagnostic. No remote prover or archive dependency during verification after dependencies are available. Native capsule import and independent software/data availability remain open. |
| Hide a chain check behind a passing local verdict | API/CLI identify synthetic context, no native acceptance, no mass validation and no key import. Nonzero locks, nonfinal sequences and coinbase inputs refuse locally. No current node, funding authentication, store, reorg, rewards or bootstrap are implemented. |

No invariant text, old interop artifact, diagnostic export source, paused patch or
historical runtime is modified. There is no reserve-release API, alternate
withdrawal key, network client, broadcast or funded trial. A successful local
authorization is insufficient to apply any consensus state.

Primary source refresh on 4 November 2026 confirmed official Kaspa HEAD
`af6ff23a0b3e8271407da3203ce4017dd188d7ec` and Orchard HEAD
`616a669df8c9a59c33d47064d3ce04b25d026b2e`, unchanged since the
[retained delta](../../research/native-shielded-upstream-delta-2026-11-04.md).
The actual Kaspa
[hash domain implementation](https://github.com/kaspanet/rusty-kaspa/blob/af6ff23a0b3e8271407da3203ce4017dd188d7ec/crypto/hashes/src/hashers.rs#L45-L73)
confirms the ECDSA SHA-256 domain prefix; the
[secp256k1 0.29.1 API](https://docs.rs/secp256k1/0.29.1/secp256k1/struct.Secp256k1.html)
supplies the standard Schnorr/ECDSA implementation. The native message remains
this repository's proposal, not current Kaspa signing behavior. Mature protocol
reuse/rejections remain in the
[source review](../../research/native-kas-shielded-value-sources-2026-11-03.md).

Remaining approval/implementation gates: independent soundness/Kaspa/accounting
review and explicit I-1/I-2 decision; portable importer/backend conformance;
actual funding/context/resource checks and atomic DAG/undo/header/recovery
integration; activation/pricing; scoped privacy/cost/performance/recovery
qualification. The retained 21.10% prior-only privacy failure is unchanged.
