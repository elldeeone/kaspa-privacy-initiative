# Scoped ordinary-funding follow-up

The single additional query found **two ordinary-change coins totalling
197,974,800 sompi (1.979748 test KAS)**. No individual coin or combined value on
these twenty scripts reaches the 1,100,000,000-sompi target. Discovery stops here.

| Current outpoint | Amount, sompi | Documented source |
| --- | ---: | --- |
| `1f165d970fe9a154a6ab70fb8ec1fbaf3e8972df1b2f589497756cc80cdc7b3d:1` | 98,987,400 | Two-input rehearsal founding ordinary change |
| `5b6863fb5a3e36bdbd7e5640e584c3612da68a711d9430ebe05925707580c178:1` | 98,987,400 | Two-input measured trial founding ordinary change |

The selected synced/indexed TN10 node returned these entries at
`2026-10-23T12:27:51.907Z`. The retained observation SHA256 is
`6a3c605a7bf13ceff0ba63295f364683f7686409b689df5b19df85be506b8aa7`.
This is a selected-node UTXO observation. Private control, confirmation depth
and present spendability have not been established here. Root must verify the
corresponding control and fresh context before use.

## Scope and provenance

The 200/105/45-KAS-era funding records return ordinary source change to the
already-queried `226cded9…` funding script. Re-querying that same address would
not add a funding candidate. The earlier five-script observation and packet
remain unchanged; its 88,630,000-sompi entry was observed at a different time and
is not added to a current aggregate here.

The new batch contains exactly twenty distinct, previously unqueried native
funding scripts: two each from the accepted contention rehearsal and measured
trial, four each from the accepted original full and partial four-wallet trials,
and four each from the accepted two-input rehearsal and measured trial. Public
`funding_scripts` manifests and the source ordinary allocator identify these
roles; each has an exact allocation output in a published accepted-chain record.
[INPUT.json](INPUT.json) retains the selected funding points and full source
hashes. [PROVENANCE.json](PROVENANCE.json) identifies the six allocation records.

Only these documented funding scripts were queried. Where present, selected
ordinary-change points require an empty-payload, single-input ordinary P2PK
transaction whose last output uses the same funding script. Recipient payout
keys, unrelated payout paths, sample or `DO_NOT_FUND` identities were not added.
No private stores, profiles, keys, backups, seeds or proving parameters were read.
No faucet request, signature, submission or external message was made.

## Execution and review

The query helper is an unchanged byte copy of the earlier successful read-only
query (`59f426af…`). It loads the pinned SDK2.1.0 through the unchanged selected
network module, and uses only `getServerInfo`, `getBlockDagInfo` and
`getUtxosByAddresses` against the selected Vector TN10 endpoint. Any returned
script outside the finite input set causes failure rather than export.

The ordinary SHA-pinned Node0500 release ran with `--use-openssl-ca`, a fixed
clean environment and read-only public source/configuration mounts. Only the
dedicated client-output directory was writable; controller plans remained
outside that mount. The host/release-owner immutability assumption from ADR0054
still applies. This network-enabled read-only run does not claim network
isolation, header/inclusion recomputation or independent consensus.

[RUNTIME-PLAN.json](RUNTIME-PLAN.json) retains the exact namespace command and
software/input hashes. [RESULT.json](RESULT.json) records successful exit and
output hashes. No retry, second funding batch or native/proof execution occurred.
The closure checks validate the finite query set, exact matching scripts and
amount arithmetic; they add no cryptographic or whole-wallet balance claim.
