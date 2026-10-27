# Final public recovery data: reviewed tools

2026-10-26 UTC. Source-only preparation. No final accepted data selection,
original-seed audit, packet build, upload or data download has run under this
preparation. The live financial closure and software02 remain unchanged.

## Source identities

Exact-byte repository copies are under `poc/local-private-payment/recovery/`.
The reviewed external operator copies remain unchanged.

| Tool | SHA256 | Review evidence |
| --- | --- | --- |
| `prepare_data_packet.py` | `239bb48bfc25a65390940d7fcdc9c128437e82ed12702aeb73d7d38ba9c72de0` | 49 public container controls |
| `prepare_data_packet_tmpfs.py` | `e958bd50cf77a8f69c8064c2aa3c8d61c69d54e9796ea41b42ee9cc8e510d584` | 61 reproduced controls and 13 additional output-boundary controls |
| `final_publication_launch.py` | `bfe8b9e38a1c66f627557ec97e0044e7dd9ee73c05b7f4ea654d5ade5b4bb1ab` | 29 scope, 7 namespace and 28 additional controls |
| `final_publication_launch_large.py` | `c465c8e6c77b80a9d4f3928cbbe97704751104ec96488fcf9516efe007ceff42` | 19 reproduced and 14 additional resource/admission controls |
| `optional_volume.py` | `afb3d20c13909aff6c0b745a256b6ceb058e804200a5ee6c2736b178b6e6948f` | 8 known-public controls; retained preimage |
| `optional_volume_final.py` | `b8127aabd90ba738fa521cfc023e40e0dd50c7d8cd8b7cc385b664b4212e0e9c` | 11 reproduced and 7 additional functional controls, with namespace checks |

The separate `ingress/recovery_data_download.py` is
`aa4c01b423a656e2005d18e316521383daad5efd4cfdb8d82804d6a0348cfac7`.
Root independently reviewed its complete source and ran 14 public boundary
controls. This data decoder has its own schema; the software02/ExitPK download
receipt does not attest downloaded final history.

## Final execution inputs

The packet uses twelve explicit roles: terminal handoff, activation, history,
context, current entry, replay results, fetch, selection, descriptor, assets,
parameters and accounting. Its finite rows must also retain both fetch page
arrays and any explicit ordinary-transaction/accounting source dependencies.
Cached fetches retain the original Full-fetch format; external full validation
uses the original Source57 verifier without trusted-cache admission.

Before any actual original is mounted, freeze and independently review the
exact candidate/source closure and the three accepted-history plus six creation
contexts. All nine literal checks scan the same candidates. The six creation
checks retain their NONCHAIN/no-authority scope. The three accepted checks use
the genuine terminal history and context. Pinned packet asset provenance and
the relocated software02 worker assets are distinct byte objects; their mapping
must be approved in the concrete closure.

Literal and derived workers remain unchanged. Their zero-match results alone
do not establish a positive number of owned exits. The separate final-volume
helper privately requires three distinct owned spent exit nullifiers, terminal
zero reserve and existing wallet payout-key reconstruction/reconciliation. It
emits only the fixed-workload and approved-exit-coverage booleans. Combine those
results only when bound to the same original, history and assets used by the
derived-byte audit. No owner mappings, indices, key counts or private hashes are
exported.

## Resource and retention limits

The tmpfs sibling additionally permits fresh output children of exactly
`/dev/shm/kpi-local-private-payment-publication-01`; that public parent must
already be owned by the operator, mode0700 and free of symlink ancestors.
Other output parents remain refused.

The resource launcher authenticates each candidate through unchanged guard09.
It copies candidates below 1MiB and binds larger candidates as exact single
read-only files. Executed source/context staging is unchanged. Its summary
reports the small-copy bytes per job, their nine-job total and largest transient
candidate payload. Read-only binds rely on the explicit trusted-host absence of
concurrent mutation; they are not immutable snapshots against host writes.

At final freeze, measure archive plus unpacked members plus decoded audit pages
and block-allocation overhead. Verify decoded sizes across every gzip member;
the last ISIZE footer is insufficient. Run after GPU work stops, keep at least
6GiB system/worker headroom and select bounded concurrency from actual sizes.
Decoded audit pages are shared read-only across workers.

Publish final data as `data.tar`, `DATA-INVENTORY.json`, `PACKET.json` and
`DATA-SHA256SUMS`. The last name preserves the existing software `SHA256SUMS`
asset. The data downloader authenticates all four external pins, exact archive
members and both page arrays, then streams decoded hashes without retaining a
second decoded copy. It never follows preserved host selector strings.

These controls support bounded source and byte-integrity claims. They do not
establish cryptographic correctness, independent consensus, general privacy,
off-host execution, independent administration or durable external retention.
Actual fresh Tor/TLS acquisition is still required after publication.
