# Compact batch design review

**State: initial obligations recorded; ADR-0057 and implementation review pending.**
Reviewed against base `a6fcdf1edd904dbe1bb395285230649b6c40d44c` on
2026-10-23 UTC. This is an independent AI-assisted source/design review, not a
cryptographic audit or runtime result. No private key, backup, witness, PK blob,
setup, proof, native runtime or network mutation was used.

The accepted native-only ADR-0056 does not itself select matched parameters.
The owner's new instruction authorizes proceeding toward that experiment;
ADR-0057 must select its precise relation and boundaries before implementation.

## Source reviewed

| File | SHA256 |
| --- | --- |
| `SECURITY-INVARIANTS.md` | `67b6e7ab82d8a57ab43967e1ac8414b07d34ca769717e52a1b941650ac2da2f5` |
| `docs/adr/0056-compact-native-batch-fee-screen.md` | `6901154567d5c48bdc8cb653de2c825df5dd679c5315be40de4e63cc8a5f3b4c` |
| `research/next-session/private-change/fees/CIRCUIT-OBLIGATIONS-01.md` | `d267923295d28467315e9d2809bdb4fc0e207bb1107a3367f16416e3e26efd25` |
| `poc/compact-private-policy/src/policy.rs` | `45a520be265cb3dfcbfb73009bbd02cb1a75f5339ab57bd5390a6d84edd4f759` |
| `poc/private-cashout-prover/src/circuit.rs` | `ef8f4fca15bd0f363d50f734d6d751360455b5a52fe35ea6486f01259fa90b64` |
| `research/next-session/compact-batch/PUBLIC-INSTANCE-01.json` | `b3a97af8c9caea15bc793175d934e96c3f4c6f7937b7e8b25bc8c82e10bc327f` |

The previous native source retains actual outpoint/state/reserve checks, exact
native payout/fee/output bindings, two sequential indexed-NF absence/insertion
checks, immutable successor code and a final complete-Auth Groth16 check.
`cm_mode` authenticates an empty target subtree and the ordered list, while
skipped empty positions rely on the prior-state empty-suffix induction.
The retained REVEAL computes the original HMAC NF from D, note CM and actual
physical position; neither verification-key role nor private mode belongs in
that real-NF preimage.

## Conditions before a matched experiment

1. Select fixed compact2 and wide32 relations under one fresh D. Compact accepts
   modes0/2; wide accepts only32 and P=0. New matrices, keys and parameter pins
   are required. Full SHA256(Auth528) remains two exact LE128 public inputs.
2. Constrain the full ordered CM-array digest, mode/start/reserved bytes, exact
   aligned range and every output. All496 wide pairwise CM comparisons include
   dummies. All values and sums have exact nonnegative integer semantics.
3. Compact terminal and continuing assignments must have identical matrices.
   Mode0 fixes every private Note168 byte, including rho, to zero; its Auth
   digest/metadata are zero sentinels and its cipher hash is SHA256(528 zeros),
   not SHA256(empty) or the commitment of a zero note. Only its inactive list
   and distinctness checks are gated off.
4. Preserve all original real NF derivation, input authority and current-root
   membership. Native current-context, sequential NF checks, tree updates and
   actual native output/fee checks remain mandatory; proof hashing does not
   authenticate caller-supplied accepted state.
5. Select only the bounded one32-recipient lifecycle for this financial screen.
   Its n<=126/m67 route does not solve private exits at saturated CM/NF capacity.
   Continuing no-append full exit remains a separate unselected decision.
6. Owners use their own backup, current public history and compact parameters;
   a wide PK or another owner's private witness must not be an exit dependency.
   Two-real-input circuit support is not permission to pool owner witnesses in
   the demonstration or its privacy/economic denominator.
7. A public capsule must anchor to a separately pinned descriptor/program/D/VKs.
   Its own content hashes provide internal byte integrity, not independent
   bootstrap trust, chain inclusion or current spentness. Fresh accepted-history
   and UTXO reconciliation must expose stale/reorg/pruned/incomplete state.
8. A32-slot proof is not evidence of32 real humans, already demanded payments,
   financial privacy or a live fee result. Keep native supplied-context,
   synthetic demand, heldout observer and accepted-chain evidence separate.

## Required adversarial evidence

| Question | Required guard and decisive control |
| --- | --- |
| Can value be minted? | Checked host u128 sums, per-value bounds and exact constrained input/output/payout/fee equality; coherent late-slot31 and32-value overflow controls. |
| Can a note be consumed twice? | Identical real NF across compact/wide/REVEAL, plus native current absence and two sequential inserts; role-cross-spend and stale-NF/root controls. |
| Can reserve be released incorrectly? | Whole Auth/state/current outpoint and native payout/SPK/fee bindings; wrong destination, diverted output, wrong reserve and replay controls. |
| Can the payment be linked? | Public wide/terminal mode, amount/time/fee/cipher format and legitimate participant records belong in a prospectively frozen observer model. Arithmetic SAT does not establish a realizable cryptographic alternative or owner anonymity. |
| What if a dependency disappears? | Cold namespace excludes original operator/cache paths, verifies an alternate public copy and fails closed on missing/corrupt parameters/history. Different local directories are not independent providers. |
| What if the chain changes? | Fresh accepted-prefix/suffix/current-UTXO join, removed-chain/pruning/gap detection; retained history alone cannot certify current exits. |
| What new trust exists? | Development setup honesty, selected local code/release/host, authenticated parameter-root distribution, retained selected-node history and correctly delivered ciphertext remain explicit assumptions. |
| Can the recipient actually spend? | Independently decrypt/rederive/CM-check each delivered positive receipt and spend it from only its own original backup. Hashing ciphertext is not an encryption-correctness or recipient-possession proof. |

Parser rejection, direct constraint UNSAT, genuine verifier rejection, native
Full acceptance and testnet confirmation must be reported separately. Negative
controls must isolate the intended rule by updating dependent public digests
where necessary. No financial setup, funding or privacy qualification follows
from this preliminary review.
