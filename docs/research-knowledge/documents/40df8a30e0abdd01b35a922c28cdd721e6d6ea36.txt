# Fresh acquisition for two unspent-owner recoveries

Two new read-only acquisitions used the unchanged reviewed fetcher, the same
nine-field public descriptor, and fresh output directories. The first captured
the unspent private-transfer head. After the root controller confirmed a newly
constructed Bob exit, the second independently scanned from birth and captured
its successor. Ownership recognition, exit construction, signing, native replay
and broadcasts belong to the wallet/root evidence, not this acquisition packet.

| Acquisition | Bob input | Charlie input |
| --- | ---: | ---: |
| Selected pool transactions | 3 | 4 |
| Accepted transactions scanned | 23,309 | 51,582 |
| Exact current outpoint queries | 5 | 7 |
| Controller elapsed seconds | 19.31 | 24.89 |
| Sampled cgroup peak bytes | 497,496,064 | 761,245,696 |
| Sampled swap bytes | 0 | 0 |
| Raw main/post-query pages | 2 / 1 | 4 / 1 |
| Decoded JSON bytes, including post-query | 72,576,556 | 152,750,479 |
| Local gzip bytes, including post-query | 9,253,431 | 19,440,636 |

Decoded JSON and local gzip sizes are not wire bandwidth measurements. Both
acquisitions contacted Vector only; the separately prepared Electron fallback
was unnecessary and remains unexecuted.

## Inputs and separation

- Descriptor canonical SHA256:
  `c9ecb633fff4337d841670a5ab8e25cc2b61c3852cc50415ce97d7913cd8d36e`.
- Descriptor raw SHA256:
  `af67b7c6f99b1b39bc427ba8c12846f3ed65d3ebc66678c43539c0b807777462`.
- Fetch source SHA256 remains
  `356d832583fc47b0fa9d7bc3efb68a05f908cec22e300791a3f603d95cce8453`.
- The approved policy template, pinned SDK, Node ELF, system-CA settings,
  restricted public mounts and 2 CPU / 4 GiB / swap-zero limits are unchanged
  from the reviewed completed-pool acquisition.
- New `FREEZE.json` SHA256:
  `91dde9ea6f23b096066b2ad76ff81c6fd904a64ae691f527458015b1e06672dc`.
  Its runtime/controller differences are descriptor, stage, output, unit and
  freeze identities only. The adversarial reviewer independently rehashed its
  13 pins before execution.
- No operator archive, tree, profile, seed backup, recipient key, proving key,
  prover, precomputed exit, prior fetched bundle or expected payment map was
  mounted. Controller release markers were checked outside the sandbox and
  were not mounted. The client discovered the reserve graph from the founding
  outpoint; controller observations never became client selection inputs.

## Exact results

Bob input bundle:
[`bob-vector-01/network-data/fetch.json`](bob-vector-01/network-data/fetch.json),
SHA256
`babcbb8c9e4937634c12fe5ccbe070b030974b22d0297bdee12ba161b7f97d81`.

The finite confirmed scan ended at
`86d72c579719e5c0b58fd9f18043ceee20f3e716b44b8c936804a46cf26b0a2e`
(blue score 592491439). The graph-derived head
`c04331508a7871c2f57981ef2c51003f217e65fe6dbd9a08df7baaf1f5420753:0`
was queried unspent at 120,000,000 sompi. A finite post-query catch-up ended at
`9c17afce1756290802bd8c9dab1b16f8b4c8511b410c84f4144e44eef9e2b848`
(blue score 592491566).

Charlie input bundle:
[`charlie-vector-01/network-data/fetch.json`](charlie-vector-01/network-data/fetch.json),
SHA256
`d4729cc645e76a6d7faed396d3aa8fdc9d9817212523643fbe24585c459fd5ca`.

This fresh scan from the same birth anchor discovered Bob's confirmed
`043b8919e6c582232479e09f3fd3f553259754c031fe9c204eeacecbe176f060`
transaction. Its output 0 was queried unspent at 60,000,000 sompi and its
payout output 1 at 55,026,200 sompi. The finite scan ended at
`cbb9a50ae2861e8234aed9611f080bd4e6744edeacaa499d701273200c5df766`
(blue score 592495229); post-query catch-up ended at
`631fc97e8c54f02035f940fd8c71e51b69a5317867787bdd5fd5f00c752f1845`
(blue score 592495410).

Both bundles have complete finite coverage, SDK-recomputed selected transaction
IDs, no recorded missing/pruned/removal flags, and no newly confirmed related
spends during the post-query catch-up. Every selected body, populated input
context, full expanded accepting header, coverage header and current query is
retained in its unchanged public `fetch.json`. Both owned units stopped and
their process groups were empty.

## Evidence boundary

This packet demonstrates fresh operator-archive-independent acquisition for an
unspent pool and its later successor under the selected validating-node
assumption. It does not authenticate note ownership, validate a new exit or
claim independent consensus. Replay and one-owner backup recovery must validate
these bundles before any spendability claim.

The RPC views remain non-atomic; a new related spend after these observations
can make the head stale. Sustained active-pool catch-up, all-source pruning,
10,000-operation recovery, a 20 Mbit/s link and a 15-minute performance target
remain unqualified. The OLD-KPX2 REVEAL exit profile exposes the pre-existing
public exit fields; this acquisition does not establish stronger exit privacy.

Eight bulk unrelated Full-page gzip captures are retained locally and omitted
from `PUBLIC-FILES.txt`. Their decoded/gzip byte and SHA256 pairs are public in
the unchanged bundles and rechecked in `RAW-PAGE-INTEGRITY.json`; the local
`.gitignore` covers both stages. The selected complete bodies and contexts are
included in the small publication packet. No raw capture was deleted or
rewritten, and the old completed-pool packet was not modified.
