# Source basis for the integrated owner-private lifecycle

2026-10-24 UTC. Source/design evidence only, before the new profile's setup or
funding. The root-selected [interfaces](INTERFACES-01.md) and
[ADR-0064](../../../docs/adr/0064-owner-private-native-kas-lifecycle.md) select the
experiment; these upstream heads do not identify a deployed native network.

## Current official heads checked

The connected GitHub API returned these exact default-branch heads this run:

| Repository | Commit |
| --- | --- |
| [kaspanet/rusty-kaspa](https://github.com/kaspanet/rusty-kaspa/tree/4edcbbccb449f84832afb1ca157904b35f37d006) | `4edcbbccb449f84832afb1ca157904b35f37d006` |
| [kaspanet/vprogs](https://github.com/kaspanet/vprogs/tree/f9b84a863a7c7c20586a9cf947550475e894f72e) | `f9b84a863a7c7c20586a9cf947550475e894f72e` |
| [kaspanet/research](https://github.com/kaspanet/research/tree/c923faca11a49148fa7d912d27ce00197a5c5a4a) | `c923faca11a49148fa7d912d27ce00197a5c5a4a` |
| [zcash/sapling-crypto](https://github.com/zcash/sapling-crypto/tree/88a7946b4a3066787776e11f0a502654167e022d) | `88a7946b4a3066787776e11f0a502654167e022d` |
| [zcash/orchard](https://github.com/zcash/orchard/tree/616a669df8c9a59c33d47064d3ce04b25d026b2e) | `616a669df8c9a59c33d47064d3ce04b25d026b2e` |
| [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ/tree/113c4e47dd94bca9ecab029d2f0abe649bea5c52) | `113c4e47dd94bca9ecab029d2f0abe649bea5c52` |
| [arkworks-rs/crypto-primitives](https://github.com/arkworks-rs/crypto-primitives/tree/7816710fc19cd4d18d6239785dac8937d7b9b3ce) | `7816710fc19cd4d18d6239785dac8937d7b9b3ce` |

The MP-SPDZ repository is `data61/MP-SPDZ`; an initial `MP-SPDZ/MP-SPDZ` API
lookup returned 404. No unavailable lookup supplied a dependency or source fact.
The published Arkworks 0.6 crate/VCS identities remain the reviewed execution
selection; its current repository head is not silently substituted for them.

## Exact native source reread

At the current Rusty Kaspa commit, the
[tag dispatcher](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/tags.rs)
still admits Groth16 `0x20` and RISC Zero Succinct `0x21`; Git blob is
`803bb3211b737855176b1aa58b027af57669b90b`.
The [Groth16 verifier](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/groth16/mod.rs)
checks key arity, canonical curve decoding, proof trailing bytes and the pairing
equation; blob `19e930972c5ac1bec53c8b356010c73fec54f7db` matches the previous
review. This supports retaining the qualified native pin and a direct one-owner
Groth16 exit; actual policy/body execution remains a separate required test.

The current [vProgs covenant source](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/script.rs),
blob `b3dedc1cc2a0fb4de48887acd71f293f17e6bb93`, was reread for fixed verifier
identity, journal and exact successor-output binding. The preserved
[Toccata inline-ZK guide](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx),
blob `7b30fa59eeaace9f324b92abdc433bdea39d105d`, makes the same distinction
between proof validity and actual successor validation. Reuse those obligations;
no based-app runtime migration is selected by this bounded lifecycle.

## Existing privacy designs: reuse, adapt, reject

The exact primary files and mechanisms were re-inspected through the retained
[native composition source review](../../native-proof-composition-source-review-2026-10-22.md),
[construction source/API review](../private-construction/CONSTRUCTION.md),
[commitment review](../owner-private-payments/commitments/ARKWORKS-COMMITMENT-SOURCE-REVIEW-01.md)
and their linked official sources. These source pins are explicit research
selections; unrefreshed projects are not described as today's latest versions.

| Existing design | Decision for this experiment |
| --- | --- |
| Sapling/Orchard | Reuse distinct membership/authorization, spend/output value commitment and balance responsibilities. Reject a central all-witness PCZT builder and direct import of curve-specific Orchard circuits. |
| ValueShuffle | Adapt confidential complete-output construction, global blinding adjustment and checks before final authorization. Existing malicious MP-SPDZ computation replaces its particular mixing/sum implementation; its protocol proof does not transfer. |
| Aztec | Reuse allowed-key and consecutive-state/effect continuity checks. Do not import its runtime, field-valued economic model or proof format. |
| RAILGUN | Reuse exact bound effects, range checks, historical membership roots versus current spentness. Do not copy its circuits or assume its ABI equals native canonical BN254 bytes. |
| Monero | Reuse separation of range, authorization and commitment conservation; retain recipient scanning/data obligations. Do not import ring signatures or reimplement its arithmetic. |
| Litecoin MWEB | Reuse public-boundary amount/destination accounting and explicit reserve obligations. Do not import extension-block consensus or claim aggregation hides native payouts. |

The selected SHA/HMAC note/NF rules, recipient delivery encoding, Pedersen
generators, MPC field/engine, and RISC Zero/native bridge retain prior reviewed
semantics under a fresh domain and role keys. A new Exit relation binds full-note
value to payout plus fee while native logic authenticates current NF and actual
state/output effects. The source analogies do not establish its soundness,
privacy, accepted backing, durable data availability or independent custody.
