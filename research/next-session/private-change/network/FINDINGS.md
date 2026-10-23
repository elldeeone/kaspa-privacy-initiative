# Private-change integration and funding route

Baseline: continuation `a8392f1127e656da59709e0b6f93ece7cf5eb9c2`.
Reviewed 2026-10-23. **Reuse the current public network/replay code byte-for-byte.**
The required implementation is a new owner payment/change client and fresh
instance/parameter selection. No network fork is currently justified.

## Source findings

| Question | Finding and source |
| --- | --- |
| More than the previous four pool operations? | Fetch follows founding output/input0 edges until an observed open head or terminal candidate. Replay follows the unordered graph while reserve remains; neither specifies actor names, expected operation IDs/counts or 60M claims. [fetch](../../../../poc/private-network-recovery/fetch.mjs), [semantic adapter](../../../../poc/private-exit-recovery/public_adapter.py) |
| Repeated P0 payments? | Auth528 `paid=0` requires zero destination and positive remaining reserve. Every continuing action inserts two NFs and appends two opaque CMs/ciphers. A P0 operation is classified PRIVATE_TRANSFER. [private_action/replay](../../../../poc/private-exit-recovery/public_adapter.py) |
| Positive private change with a native payout? | Public replay requires exact `R'=R−P−fee`, full payout SPK/value and continuing reserve output0 plus payout1. It processes two continuing private CM slots regardless of hidden values. It cannot distinguish positive change from dummy slots by parsing ciphertexts; actual hidden conservation/ownership require the native proof. [adapter](../../../../poc/private-exit-recovery/public_adapter.py) |
| Terminal after a longer history? | Terminal verifies complete inactive zero fields, preserves CM root/count, inserts both NFs and requires payout-only topology. Network reconciliation requires consumed inputs, every actual payout query and all queried live points watched. An absent address is insufficient for reserve zero. [adapter](../../../../poc/private-exit-recovery/public_adapter.py), [network composition](../../../../poc/private-network-recovery/network_replay.py) |
| Fresh D/VK? | The approved entire 24417-byte program has ten canonical D32 operands and one VK328 operand. Descriptor/manifest supply public parameters; code compares the whole reconstructed immutable tail. Current source is not CAF-specific. [policy gate](../../../../poc/private-exit-recovery/approved_template.py), [fetch gate](../../../../poc/private-network-recovery/fetch.mjs) |
| Native helper reuse? | The keyless helper reconstructs its source program, patches exactly ten D/one VK operands and compares the complete requested redeem. The generic Full validator also executes the actual supplied bytecode. These components need no D-specific fork for the unchanged ABI/policy. [helper program()](../../../../poc/private-cashout-native/src/main.rs), [generic validation serializer](../../../../poc/independent-recovery/native_validation.py) |

These are source conclusions about the unchanged Auth528 relation/program.
They do not establish new valid private proofs, accepted backing or wallet
support. The public predicate layer alone deliberately remains incomplete.

## Actual limits and off-chain assumptions

- Each Auth528 action has **two input slots, two NF updates and two private
  output slots**; arbitrary history length does not mean arbitrary transaction
  fan-out. Private payments can fit recipient plus change in those two slots.
  Private positive outputs retain the 60M floor; native payouts retain 10M.
- CM count is at most 65535; physical NF count is at most`2*n+1<=131071`.
  Continuing actions append two CMs; terminal skips CM appends. These are real
  state-capacity limits, not a fixed rehearsal-length assumption. See
  [State.counts/append](../../../../poc/independent-recovery/replay.py).
- Recovery scans all accepted chain records from birth, not only pool actions.
  Longer elapsed histories increase data/indexing work and retained-node/pruning
  dependence. Earlier small live captures do not qualify larger-history latency,
  sustained active-pool liveness,10k operations,20Mbit/s or15-minute recovery.
- Public replay's PRIVATE_EXIT record intentionally contains actual P/SPK/point,
  not a fabricated input-note CM/position association. Owner association stays
  local. Selected-node membership/history/current-view, trusted local software,
  correct encrypted delivery and development setup remain assumptions.

## New owner-client seam

The current [private_action.material/build](../../../../poc/private-cashout-wallet/private_action.py)
selects one whole owned claim, uses one real plus one dummy input, sets
`remaining=reserve−claimValue`, and creates only zero-value dummy outputs when
the pool continues. Its payout is always`claimValue−fee`.
[check_body/prove_and_build](../../../../poc/private-cashout-wallet/private_wallet.py)
assumes that shape and selects the first available claim.

A new package must support explicit own-note selection, receiver and self-change
invoices, positive private output notes/encryption, and correct accounting:

```text
sum(real input notes) = recipient private value + private change + P + fee
new reserve = old reserve - P - fee
```

For fixed recipient/private payment and positive change, a fee update changes
the change note value and usually the remaining reserve. Rebuild the dependent
note/CM/cipher, append paths, next state, Auth and complete quote binding on each
fee iteration. Do not reuse the old fixed dummy-output material while changing
only a fee field. The final proof must bind the exact stabilized body/context.
For two real inputs, fresh native destinations must differ from **both** real
emergency keys; the old one-claim payout chooser checks only its single claim.

The trial assembler's [receipt/action](../../../../poc/private-cashout-trial/action.py)
uses invoice index0. This is an off-chain fixture restriction. The
[receiver](../../../../poc/future-recipient/v2/recipient.py) can derive other
indices; duplicate invoices retain owner spend authority but flag privacy
contamination and suppress duplicate normal credit. Define a fresh invoice/
self-change policy in the new wallet; do not weaken those checks or claim that
missing historical issuance state has been solved.

## Fresh instance and selection wiring

1. Root creates a new unfunded identity/D and clones the unchanged relation for
   a fresh measured setup/VK/PK. Do not reuse CAF/AA keys or migrate old reserves.
2. Export the new canonical small public manifest and exact dimensions/source/
   build/provenance hashes. A fresh D may change measured constant-domain shape;
   authenticate the actual new export rather than assuming previous counts.
3. Emit the same strict ten-field descriptor with fresh founding point, birth
   anchor, approved initial redeem/VK and new manifest hash. User pins its
   canonical digest separately; descriptor/manifest are the only public config.
4. Clone the owner client into a **new** package. Update its own source and
   D/VK/manifest/prover/build selections. Keep network replay
   `00e034780c059febd92166148829ac7c15f27a3395d06df055ccc9c82a2ce0df`
   and network source freeze
   `19dffcaa74e4f45ac681bbfbb26e8b42783467f4348cd1fd6e20ae9eab83e207`
   unchanged when the underlying ABI/policy is unchanged. The crypto bridge,
   generic native validator and generic keyless helper can retain their reviewed
   identities, copied into ordinary 0500 trusted releases/read-only mounts.
5. Preserve public replay/software validation before backup access and complete
   selected parameter authentication/ready handshake before a private witness.
   Never mount old trial operator bodies, PKs, archives or precomputed exits into
   new cold recovery. No hosted prover or automatic revealing fallback.

This is selection/design advice, not creation of a fresh setup or owner client.

## Public controls executed

[PUBLIC-CONTROLS-01.json](PUBLIC-CONTROLS-01.json) records the exact network-off
namespace and source hash. **10 pure public-predicate controls passed**, including
two repeated P0 actions, a continuing payout/opaque-change branch, a seven-
operation trace, unordered rows, terminal CM preservation/two NF insertions,
and duplicate-spend, missing-query/watch, inactive-CM and wrong-NF-path rejection.
The terminal trace reconstructs n11/m13/R0 without a fixed operation-count rule.

The fixture deliberately has invented IDs/incomplete headers, opaque outputs,
an unselected mock manifest and invalid proof placeholders. Production SDK/
native checks would reject it. No SDK/native/prover/RPC, seed or PK was mounted
or executed in these controls; hidden positive change and private conservation
were **not** proved. All old frozen modules remained unchanged.

## Funding route: documentation and current read-only check

The [official Kaspa wiki](https://wiki.kaspa.org/en/testnets) links
[the TN10 faucet](https://faucet-tn10.kaspanet.io/). The
[SDK integration guide](https://kaspa.aspectron.org/faucets-mining.html) also lists
[the older testnet faucet URL](https://faucet-testnet.kaspanet.io/). On this host,
ordinary homepage GETs to both addresses returned403 browser-challenge pages
on 2026-10-23 at 11:19 UTC; official wiki GET succeeded. This shows reachable HTTP
challenge responses, not a working payout API or proven outage. No challenge
workaround, address, form submission or funding request was attempted.

The official [kaspanet/faucet repository](https://github.com/kaspanet/faucet)
is archived. Its pinned
[server source](https://github.com/kaspanet/faucet/blob/ddeb311bce21aa7e371b430fe56807966bfab749/server.go)
implements **GET/request_money?address=… as a mutating payout route**.
Its [amount](https://github.com/kaspanet/faucet/blob/ddeb311bce21aa7e371b430fe56807966bfab749/faucet.go)
and [IP usage](https://github.com/kaspanet/faucet/blob/ddeb311bce21aa7e371b430fe56807966bfab749/ip_usage.go)
encode a historical 1-KAS/24-hour limit. Do not call that GET as an availability
probe. This archived implementation is not authenticated as the current hosted
deployment; its limit/API cannot be assumed current.

Later owner-authorized browser faucet use or a transfer from known TN10
participants is a documented route. No external message or request was sent.
The wiki's CPU-mining guidance is not authorization to start mining, and no
miner was installed or run. Raw HTML/challenge responses and upstream source
snapshots are retained locally/hash-indexed but ignored from the public export.

## Later root-authorized finite funding query

Root separately authorized read-only queries of published controlled funding/
ordinary-change scripts. [KNOWN-PUBLIC-FUNDING-INPUT-01.json](KNOWN-PUBLIC-FUNDING-INPUT-01.json)
pins five scripts to public identities, accepted ordinary funding/change records
and older 200/105/45-KAS source records. No private profile/key/backup or address
derivation was used. Only getServerInfo/getBlockDagInfo/getUtxosByAddresses ran
through the pinned ordinary SDK/Node release and selected Vector node.

[The successful observation](known-funding-query-02/client-output/OBSERVATION.json),
SHA256`e64f3f53d0ca1f63a0ab5a2613e3cd636cca09ffd515a49786abb5856050b6a0`,
returned one coin: ordinary CAF change
`006d46b0fabbf551a50186d9e9edf2f873f39ba0d871342c3dd254c1b4a4fbbf:1`,
88,630,000 sompi. The other four queried funding scripts had no current entries.
No 11-KAS coin/aggregate was observed on this finite set. This does not prove
an empty wallet, absence on unqueried identities, private control or confirmation
depth. Root must establish control/fresh spend context before any future use.
Unrelated address data is excluded from exports.

The first controller text had a pre-execution syntax error; the first actual
query's export then rejected BigInt server metadata. Both failures are retained.
The successful repeat changed only lossless decimal metadata serialization;
the five-script scope and read-only methods stayed fixed. No faucet request,
signature, funding or broadcast occurred.
