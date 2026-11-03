# RFC-0020: New-format private proof and native exit integration

**Status:** Implemented offline prototype; not a production protocol.
**Date:** 2026-10-23 UTC. Baseline `0c2f4c788a4274b381c4838e05cce5e9c32e8536`.

## Problem and scope

The public candidate-C experiment demonstrates native reveal authorization on
supplied synthetic state. It does not implement the genuine private relation,
recipient delivery, accepted backing, recovery or a complete payment lifecycle.
This work connects those obligations in a separately versioned offline prototype.
The goal remains native test-KAS deposit, recipient-owned private value, private
transfer, deterministic double-spend rejection and an authorized native payout.
All [invariants](../../SECURITY-INVARIANTS.md) and
[RFC-0012 targets](0012-useful-privacy-requirements.md) remain unchanged.

The owner authorized all five workstreams: note/proof integration, complete fees,
recipient recovery, native policy and independent adversarial/privacy checks.
This does not authorize real funds, mainnet, paid compute or an admin withdrawal.
The previously rejected S7 owner/replay/DRAIN workflows and their keys remain
parked. New source and development parameters must not reuse those identities.

## Design contract and review

The [note/state contract](../../research/next-session/private-integration/NOTE-STATE-CONTRACT.md)
defines the exact bytes, recipient-owned credentials, private and native shared
nullifiers, padding/capacity and amount rules. The
[source comparison](../../research/next-session/private-integration/PRIMARY-SOURCES.md)
records reused established hashing, HMAC, Schnorr, sealed boxes, Merkle trees and
Groth16 patterns. No new primitive is proposed. Independent review is recorded in
[the gate matrix](../../research/next-session/private-integration/ADVERSARIAL-GATES.md).

Recipient-issued one-time invoices are an experimental interaction requirement,
not a reusable anonymous address. A backup predating receipt derives the receiver
secrets; the sender constructs output commitments from public descriptor fields
without learning the receiver's nullifier credential or native signing secret.
Receipt acceptance must derive and verify the descriptor before credit. A later
duplicate invoice may contaminate privacy but must not freeze prior owned value
or erase any accepted liability. Disclosures survive rollback.

The proposed private relation uses fixed two-input/two-output shape, real or
domain-separated dummy nullifiers, and a sentinel-inclusive indexed-NF counter
without the old parity rule. A capacity argument must cover all remaining real
notes across both private and revealing transitions. Private proofs and native
reveal must use byte-identical commitments and positioned original nullifiers.

## Economic questions

A direct Groth16 verifier's 147,500-mass floor already exceeds the 100,000-mass
ordinary budget for one 10-tKAS payment at reference100. A genuine single-transfer
proof is integration evidence, never fee qualification. Recipient change is not
a second useful payment. Batching must count distinct useful payments, costs per
user, all final tails, funding, admission, retries and any service fees.

Study native public admission as a separate candidate: public descriptor/opening
and native amount checks might remove the admission verifier. It must authenticate
funding, commitment append, delivery bytes and immutable successor while
preserving every liability. Its ingress disclosures and stable delivery-key
linkage are privacy inputs. Genesis/accepted lineage is a separate obligation;
an arbitrary supplied root is not backed merely because its script validates.

An actual combined script must replace the previous NOP size allowance. Price
complete native bodies, including inactive branch bytes, current witnesses,
compute, transient and storage mass, and owner-authorized fees at100/200/500.
Retain the 60M claim /10M minimum payout /50M fee cap and the failed small-tail
cases. Do not infer that a faster prover changes native verification fees.

## Evidence order

1. Complete primary-source inspection and independently review the exact contract.
2. Compile the separate packages and measure actual circuit synthesis before
   selecting a fresh development setup and meaningful proof workload.
3. Freeze source, public statement, inputs, controls and parameter identity;
   generate a genuine new proof and independently verify it.
4. Execute the actual combined native policy on complete synthetic bodies with
   exact semantic failures and shared-NF race controls. Quote fees separately.
5. Exercise real encrypted receipt acceptance and pre-payment-backup restoration
   against declared durable public records, retaining missing-data failures.
6. Run the frozen incremental disclosure checks. The existing21.09772557% prior
   failure against the unchanged20% target is not repaired by these checks.
7. Only a complete new testnet rehearsal with confirmed payout can establish a
   testnet lifecycle. Offline proofs, oracle-authenticated snapshots and supplied
   UTXOs must not be reported as that result.

## Open decisions

The [complete supplied-context trace](../../research/next-session/private-integration/RESULTS.md)
now passes six linked native Full operations with a genuine new-format private
proof and both backup-restored native payouts. The actual three-branch immutable
script is 22,388 bytes. Exact complete native fees are 1.85177% and 1.85071% for
two distinct 10-KAS payments, with one payer and no private change. No positive
liability or reserve tail remains. This closes the scoped offline integration
question, not accepted backing or the full requirements.

[ADR-0042](../adr/0042-separate-delivery-and-note-receive-fields.md) resolves
the selected V2 invoice field separation; [ADR-0043](../adr/0043-native-public-admission-experiment.md)
resolves the offline native-admission experiment. [ADR-0044](../adr/0044-selected-development-key-loading.md)
scopes separately authenticated development-key loading without changing the
proof relation or native verifier. The checked primary load/proof takes 198.12
seconds and 5.41 GiB peak RSS; wallet resources remain unqualified. The native
control suite retains its three incorrect error-label expectations and the
capacity fixture retains one missing preparation-helper source identity.

The receive interaction/reuse policy, generic batching with change, independent
owner aggregation, accepted public admission initialization, durable public data,
current-chain discovery/reorgs and confirmed testnet payouts remain research
obligations. The prior privacy failure remains. Passing tests does not prove
cryptographic correctness, privacy, production safety or parameter-trapdoor erasure.
