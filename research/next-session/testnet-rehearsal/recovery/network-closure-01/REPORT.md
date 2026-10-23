# Confirmed TN10 recipient recovery closure

**Retained validating-node records confirm both seed-only recipient exits and
terminal zero reserve.** Six native bodies completed on testnet-10. Each
recipient received a100,000,000-sompi private note; Bob's native payout was
95,026,200sompi and Charlie's95,036,800sompi.

This is an additive artifact review. The earlier closed recovery packet and
all41 of its hashed payloads remain unchanged. No RPC, seed/backup read, proof
load, native execution or semantic checker rerun occurred in this closure.

Trial: `e406aff3-442b-4493-a778-68af2dec4cc7`.
Domain: `42fab9c9042a1fbf0e0ef7755cb04df8a79ce32b6715bdd600a3deb100bfe827`.
The [machine closure](RESULTS.json) retains exact body IDs, phase results and
payout outpoints; [source identities](SOURCE-FILES.json) hash24 curated public
JSON artifacts, including the parent `CHAIN-COMPLETE.json`.

## What the public records establish

All six ordered operation records agree with their exact public body/observation
hashes, transaction IDs, TN10 genesis/network and passing confirmation policy:
funding preparation → founding → admission → genuine private payment → Bob's
continuing reveal → Charlie's terminal reveal.

Five recorded `TRUSTED_TN10_ACCEPTED_NODE` recipient verdicts pass:

| Retained phase | Seed-only recipient result |
| --- | --- |
| After private payment | Bob and Charlie each recover100M and construct one current witness |
| After Bob's exit | Charlie still recovers100M and constructs one current witness |
| After terminal exit | Both have zero owned pool balance; both native payout UTXOs reobserved |

Every verdict explicitly records no payer/prover-secret read and preserves the
trusted validating-node/archive boundary. Process-isolation evidence belongs to
the parent rehearsal packet; this closure reviews its public results.

At the retained final observations, both payout amounts/SPKs/outpoints match
the actual accepted bodies and returned noncoinbase UTXOs. Their recorded
acceptance blue-score distances are755 for Bob and314 for Charlie, each strictly
above the20minimum and consistent with its accepting-header/sink scores.
Both observations follow the refreshed06:03:42.262UTC checkpoint; different
later sinks are expected. The consumed reserve predecessors are explicitly
queried and absent. Charlie's terminal body has exactly one payout output;
the final canonical reserve outpoint is null and reserve/liability is zero.

These statements describe the retained observations, not a new live UTXO query
or immutable finality guarantee.

## Scope

This closes the actual testnet payout/recovery step that the earlier LOCAL
packet did not establish. It remains a small liveness pilot using test KAS.
Trusted validating-node/complete-archive access is explicit. Independent network
recovery, durable data availability, financial privacy, fee targets, cryptographic
correctness, audit status and production/mainnet readiness remain unqualified.
The historical10KAS workload targets are unchanged by this1KAS-per-recipient run.
