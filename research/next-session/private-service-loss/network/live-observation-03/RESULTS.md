# Fresh terminal observation from the alternate endpoint

Electron successfully supplied a new descriptor/manifest-only acquisition after
the terminal private payout confirmed. No Vector fallback was needed. The client
independently discovered the whole reserve graph from the authenticated founding
point; no operation list, previous capture, owner data, operator rehearsal/exit,
parameter blob, prover or cashout helper was mounted.

Bundle: [`client-output/network-data/fetch.json`](client-output/network-data/fetch.json).
SHA256: `4c137a71336dae9ed2dc2f613bbd9b4587010681bc08b3f3942fbb136b0794bf`.
Descriptor canonical SHA256:
`7d8f74edc7cffc813201af8c932fb4196adffa4a2ccb5593910bc5cd82bf1a57`.
Public manifest SHA256:
`008689b84cd171187cc75d32402dbf13d6d4e3ed149d3349ecfbc418bfcaad54`.

The scan selected four pool bodies from 86,619 accepted transaction IDs. All
selected IDs were recomputed with populated input contexts and full header
hashes were checked. The complete finite frontier was
`c41fe5b6cde9c7ab73990a5dc643a409f5ef89ca8ea78b4259d8723c0bc21308`
(blue score 592598727); post-query catch-up reached
`935a8532b5d7a6f59b4377eedbf49a8139729540b8fd86c069242e7bcbae9d61`
(blue score 592599316). No gap, pruning, removal or related-spend flag occurred.

Seven exact current queries observed all selected reserve/input points spent.
Only these selected outputs remained unspent:

| Kind | Outpoint | Sompi |
| --- | --- | ---: |
| Ordinary change, outside reserve | `006d46b0fabbf551a50186d9e9edf2f873f39ba0d871342c3dd254c1b4a4fbbf:1` | 88,630,000 |
| First private payout | `71a1536f3a4824026c0d309d2a0f46e1a14103ba99a2e8db9b6013f7ac17a9b4:1` | 41,000,100 |
| Terminal private payout | `e7696fa34a50e759e630011bca08eec5a2283f22e59db200b7b2627a056e53ee:0` | 41,042,400 |

All three live points were watched during post-query reconciliation. The fetcher
reports a terminal **candidate**. The two separately isolated recover-only
clients authenticate actual terminal/no-CM-append and both NF updates through
public semantic/SDK/native replay before ownership recognition; reserve zero
does not follow merely from an absent query. Those clients have no PK, prover
or cashout helper mounted, and their evidence owns the recovery/crypto claims.

The common complete bodies, witnesses, populated contexts and accepting headers
match earlier observations exactly, including the three-body Vector prefix.
The derived comparison is retained in `CORROBORATION-OBSERVATIONS-01.json` one
directory above. This demonstrates contact with two endpoints and coherent
retained data; it does not prove separate operator ownership or consensus.

The acquisition took 60.84 controller seconds, with sampled cgroup peak
1,273,294,848 bytes and zero swap. The manager explicitly observed unloaded/PID0;
kernel process observation after teardown was unavailable and remains null.
The dedicated writable client-output mount excludes controller plans, markers,
telemetry and software snapshots. Source19dffcaa and ordinary SHA-checked0500
trusted-release execution/clean environment remain unchanged, with explicit
host/release immutability trust and no same-inode hostile-writer protection.

All seven raw gzip/decoded pairs were rehashed locally and ignored. They total
433,082,147 decoded JSON bytes and 63,490,185 local gzip bytes, **not wire bytes**.
Bulk unrelated pages remain locally retained outside the public export; the
unchanged bundle retains complete selected bodies/contexts/headers/current
queries plus every page's hash/size index. No original capture was rewritten.

This is bounded testnet evidence under selected validating-node, retained-data,
user-pinned instance/VK and development-setup assumptions. RPC views remain
non-atomic and finite observations can age. General financial privacy, durable
data/parameter availability, independent consensus, sustained activity and
10k-operation/20Mbit/s/15-minute performance remain unqualified.
