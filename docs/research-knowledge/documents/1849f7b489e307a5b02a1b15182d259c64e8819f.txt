# Public Arkworks 0.5 / native 0.6 differential

The three retained genuine public v6 proofs verify in Arkworks **0.5.0**, **0.6.0**, and the pinned native Kaspa VM. The finite decoder cases agree. The generic verifier APIs differ on malformed input arity; native Kaspa rejects those cases explicitly.

Evidence: `evidence/2026-10-22-public-differential/attempt-03/`. This is a public development-fixture check, not cryptographic correctness, general encoding equivalence, settlement, accepted state, backing, privacy or chain evidence.

## Measured result

| Layer/control | Result |
|---|---|
| Three genuine statements: one historical ordinary SPEND and the fresh public pair | All three verify in both libraries and standalone native `TxScriptEngine` / `OpZkPrecompile`, Groth16 tag `0x20` |
| 64 bounded decoder vectors | Same acceptance, identity, compressed roundtrip and uncompressed bytes in both versions: 41 decoded, 19 rejected, 4 harness guards |
| 25 statement cases | Native: 3 verified, 21 rejected, 1 predecode guard; all declared expected outcomes checked |
| Changed public inputs, individual identity proof points, sign flip | Genuine proof verification rejects |
| On-curve G2 outside the prime subgroup | Both checked decoders reject; native rejects when substituted into proof B or key beta |
| Fq/Fr modulus, modulus+1, coordinate modulus, illegal `0xc0` point flags | Both checked decoders reject |
| Nonzero point payload with infinity flag | Both decoders normalize to identity; reserialization differs. The strict profile rejects. This is a decoding behavior, not acceptance of a valid proof with that replacement |
| Trailing key, proof or scalar bytes | Generic deserializers consume the valid prefix and raw verification succeeds. Full-consumption strict profile and native reject all three |

The deterministic subgroup vector is the first result from at most 64 public `x=(n,1)` candidates; both versions independently report `x=(0,1)`, on-curve and outside the prime subgroup. It is only a serialization control. No new proof, setup, secret opening or proving key was used.

## Raw verifier arity difference

These are actual retained outcomes, not a claim of equivalence:

| Case under the same genuine statement | Arkworks 0.5 raw API | Arkworks 0.6 raw API | Strict caller profile / native |
|---|---|---|---|
| Empty `gamma_abc_g1` | `MalformedVerifyingKey` | Captured index-out-of-bounds panic | Reject / explicit empty-key error |
| One extra unused IC point | Arity error | `true` | Reject / arity error |
| Missing public input | Arity error | `false` | Reject / arity error |
| Extra zero public input | Arity error | `true` | Reject / arity error |

Pinned `ark-groth16-0.5.0/src/verifier.rs:29` checks `inputs.len()+1 == gamma_abc_g1.len()` before indexing. Version 0.6.0 starts by indexing IC0 and then zips input scalars with IC points without that guard. The harness catches and records the bounded raw API panic so later cases remain observable; it does not turn it into a verifier rejection.

The actual native `01b532e8b553523216471682649693af92f0fd16` implementation checks nonempty IC and exact arity **before** reading/pricing IC entries. It rejects trailing VK/proof bytes and requires exactly 32 bytes per scalar. Its checked curve decodes do not impose the stricter reserialization/nonidentity caller policy. No native vulnerability is established here.

The existing two-v6 guest common code independently pins key bytes, requires IC3, complete decode and roundtrip equality, rejects identity points, and constructs two inputs from each authorization. This experiment did not execute that guest or change its sources.

## Provenance and bounds

`PROVENANCE.json` retains all allowlisted public fixture hashes. The historical proof SHA is `01b2cdc52131f4a612fb354fb5f86e0ad7c5c5f4a2e4146d18484514180a6b9b`; its VK SHA is `9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef`. Fresh VK SHA is `2a9acd1639fb7b454384c65fb317a139695f5a2cbb3ebd941dd13b5f6045a2f4`. Public scalar bytes are SHA256(377-byte authorization), split into two 16-byte little-endian limbs, each padded with 16 zero bytes. Exact VK/proof/scalar bytes are retained in `input.json`.

Both backends use checked compressed deserialization. Accepted values are also serialized uncompressed to compare mathematical point/field representations. Decoder rejection wording is retained but excluded from semantic equality. Strict profile acceptance requires full consumption, exact roundtrip, no identities, IC3/input2 and VK328/proof128; verification remains a separate result.

All JSON is bounded to 1 MiB, 200 vectors and 50 statements. Before either generic VK decoder runs, its little-endian vector length at offset 224 is bounded to eight. VK/proof sizes are bounded to 512/160 bytes, point/field vectors to 40/72 bytes as appropriate, and statement scalar count to three. The u64-max count is rejected before vector allocation. Network access and writable source access are absent from the Rust execution namespaces.

`SOURCE.json` and `source/` freeze the actual executed source and lock; `MANIFEST.json` hashes the run artifacts. Exact selected upstream source files and hashes are retained separately in `UPSTREAM-SOURCES.json` / `upstream-source/`.

Final executable hashes:

- dual Arkworks: `a96f7ffa39099319effa291753b8377c3d60a82c599ec29a458833c2466caa7b`;
- native VM: `4016beb88d89f0f6cabf5046c6e5197a2632b3d6fd0d0fc303a98246778b0fff`.

The successful run used 2 CPU / 2 GiB hard RAM / zero swap limits and completed in 248 ms, 296 ms CPU, 27.4 MiB peak. Source and executable hashes were rechecked after execution. Build/runtime receipts are retained with actual command output.

## Retained failures and limits

Attempt 01 stopped at the raw 0.6 empty-IC panic; its complete input and source snapshot are retained. Attempt 02 recorded all results but validation failed because the additive native harness appended `OpTrue` after `OpZkPrecompile`, which already pushes true, violating clean-stack rules. Removing the redundant opcode produced attempt 03; all proof, input, mutation and native dependency bytes stayed fixed. Early compile/launch failures (private API fields/trait and a nonexecutable helper) are also retained in build logs. Previous binaries were hash-recorded, not copied into each failed attempt.

Only three genuine statements and these finite controls were checked. No exhaustive parsing, fuzz campaign, new proof/setup, proof-system security result, native transaction/covenant/chain acceptance, fee/default change, or new protocol architecture is claimed. Unreviewed code remains research code.
