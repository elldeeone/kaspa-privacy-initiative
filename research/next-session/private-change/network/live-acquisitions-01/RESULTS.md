# Six fresh descriptor-only network observations

The final fresh Electron capture contains **six accepted transaction bodies**,
all earlier complete bodies and input contexts, and ten exact current-outpoint
queries. The selected node reports every former pool reserve spent and these
native outputs currently unspent:

| Native output | Sompi |
| --- | ---: |
| Partial payout | 10,000,000 |
| Continuing full payout | 73,041,500 |
| Terminal payout | 41,042,400 |
| Ordinary founding change | 65,628,400 |

The final acquisition marks a terminal candidate. The owner client's separate
fresh public SDK/native replay establishes the terminal semantics and recovered
owner state; those wallet results are not asserted by this acquisition packet.
The original final [fetch.json](observation-06/client-output/network-data/fetch.json)
SHA256 is `4a9bb620e6a4e8ce3ab4885c188833407a4c8dc6c4ed4e8f5d122812fcc881de`.

## Acquisition sequence

Each observation ran only after root confirmed the preceding actual action.
Each client started from the same authenticated minimal ten-field descriptor
and small public parameter manifest, then discovered the accepted outpoint
graph itself. It received no expected bodies, operation IDs, actor labels,
payment map, previous observation, operator tree/profile or prepared exits.

| Observation | Endpoint | Bodies | Exact queries | Queried live pool continuation, sompi | Seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| 01 | Vector | 1 | 3 | 218,958,700 | 26.90 |
| 02 | Vector | 2 | 4 | 200,000,000 | 22.84 |
| 03 | Vector | 3 | 6 | 171,000,100 | 29.43 |
| 04 | Vector | 4 | 7 | 152,041,400 | 33.99 |
| 05 | Vector | 5 | 9 | 60,000,000 | 39.57 |
| 06 | Electron | 6 | 10 | None; terminal candidate | 41.68 |

All six succeeded on the first attempt. Each reached its exact finite confirmed
frontier, queried every selected consumed input and created output, watched
every currently live queried outpoint during post-query catch-up, and retained
no missing/pruned/removal/related-spend flags. Adjacent observations have exact
common prefixes of complete transaction bodies, input contexts and accepting
headers. The last Electron observation matches all five earlier Vector bodies
and contexts. It scanned 84,688 accepted transaction IDs from the birth anchor;
this is chain-wide discovery work, not a supplied pool transaction list.

[OBSERVATIONS-01.json](OBSERVATIONS-01.json) retains all capture hashes,
frontiers, counts, resources and cross-observation comparisons. Each observation
has its own immutable closure, manifest and explicit public file list. The
acquisition was handed directly to the next owner client before publication
hashing; no duplicate standalone native validation ran in this lane.

## Software and isolation

The network implementation was reused byte-for-byte from source freeze
`19dffcaa74e4f45ac681bbfbb26e8b42783467f4348cd1fd6e20ae9eab83e207`.
All 26 source/template/contract pins were rechecked unchanged. Its approved
24,417-byte program gate, SDK header/transaction-ID checks, finite frontier,
history-completeness, exact UTXO bindings and post-query checks were unchanged.
No new network protocol, policy relaxation or fixed six-step rule was added.

The descriptor raw and canonical SHA256 are both
`1e454b46148e3e10cdfad35c0f81babdaf24005e1b0312f4ed84b5bc9ee47208`.
The selected 2,500-byte canonical public manifest SHA256 is
`b440d08fddcdbbfb7d6b8355ab097a7bedd3fb85b8aa228f07070d4fcb3a91d0`.
The exact approved policy tail matched all ten domain and one VK patch slots.
No PK blob, prover, native validator, private backup or seed was mounted in any
acquisition client. Controller release markers and the workload selection
remained outside the client mounts; only a fresh client-output subdirectory
was writable. The earlier closed 27-path source/research and 13-path funding
packets were preserved.

All six active units showed the requested two-CPU, 4-GiB, zero-swap caps. Their
largest sampled memory peak was 936,914,944 bytes, with sampled swap zero. Every
owned unit was subsequently observed unloaded with PID zero. Missing teardown
kernel process observations remain null; they are not reported as verified
empty cgroups. Ordinary pinned Node0500 execution retained `--use-openssl-ca`,
read-only public software mounts and the ADR0054 clean-environment/trusted-host
and release-owner immutability assumptions.

## Limits and publication

This is selected-validating-node and retained-data acquisition, with separately
performed owner replay. Contacting Vector and Electron does not establish
separate operators or independent consensus. SDK hash verification actually ran
in acquisition; the Python closure hashes retained artifacts and does not
independently recompute those SDK checks. Neither fresh local validation nor a
retained observation proves a bundle remains current now. Views are non-atomic,
confirmation depth is finite, and ongoing active-pool catch-up is unqualified.

The smaller live functional workload does not qualify the unchanged larger
10-KAS fee/privacy targets, cryptographic correctness, financial privacy,
production safety, arbitrary history/pruning tolerance or general recovery
liveness. Root's workload selection is controller metadata, not a client input.

All 26 raw page gzip/decoded pairs were retained locally and hash-checked:
985,218,699 bytes of decoded JSON and 125,845,953 bytes of local gzip files.
These are distinct disk representations, **not wire-byte measurements**. They
include unrelated accepted transactions required for discovery and are ignored
and excluded from publication. Only selected bodies, contexts, expanded-parent
headers, coverage/current queries, source snapshots and runtime/hash receipts
are in the public allowlist. Original fetch and earlier sealed packets were
neither rewritten nor deleted.
