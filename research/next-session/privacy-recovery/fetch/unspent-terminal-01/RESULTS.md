# Fresh terminal acquisition after independent owner exits

The final descriptor-only scan independently fetched all five pool bodies after
both newly constructed owner exits confirmed. It queried every selected
input/output point and observed both native payouts unspent. Only public replay
can authenticate the terminal transition and reserve-zero semantics; acquisition
alone does not infer zero from an absent address.

Bundle: [`vector-terminal-01/network-data/fetch.json`](vector-terminal-01/network-data/fetch.json).
SHA256: `d96702bf1ce58edf502532dbf521d94d4ae99970854268d797a51944da8ad140`.

## Independent inputs and observed state

The sandbox received only the same nine-field public descriptor, unchanged
reviewed fetcher and approved policy template, pinned SDK, exact Node ELF,
system libraries/DNS/TLS and a fresh writable output directory. It received no
earlier fetched bundle, operator tree/archive/profile, backup, private key,
proving key, prover, precomputed exit or expected payment map. Root's Charlie
confirmation marker was read only by the outer controller and was not mounted.
The earlier completed-pool and 36-path unspent packets remain unchanged.

Descriptor canonical SHA256:
`c9ecb633fff4337d841670a5ab8e25cc2b61c3852cc50415ce97d7913cd8d36e`.
Fetch source SHA256 remains
`356d832583fc47b0fa9d7bc3efb68a05f908cec22e300791a3f603d95cce8453`.
Supplemental runtime freeze SHA256:
`85cb1ea964ad7867e544ae4761edb02dca903e2f7ea1d92907fce95dd8f01031`.
Its runtime changes are descriptor/output/unit identities only, with the same
restricted public mounts, CA settings and 2 CPU / 4 GiB / swap-zero limits.

From the founding outpoint and accepted spend graph, the scan discovered the
founding, ADMIT, PRIVATE, continuing REVEAL and terminal REVEAL bodies. All five
selected transaction IDs were recomputed by the pinned SDK using their actual
populated input contexts. No stage IDs were supplied to the client.

The finite confirmed frontier was
`2a101895a3177357d9516df619999eb18f1fc31dcf3e85cf8b05289698696880`
(blue score 592498797). The finite post-query catch-up ended at
`d36a0515dc731b4ad6362d4f018558deef33d58b2758a3e113ab35c8edd1ca81`
(blue score 592499245). Coverage was complete, with no recorded missing,
pruned, removed-chain or newly confirmed related-spend flags.

Eight exact input/output queries observed only these two selected points unspent:

| Outpoint | Sompi |
| --- | ---: |
| `043b8919e6c582232479e09f3fd3f553259754c031fe9c204eeacecbe176f060:1` | 55,026,200 |
| `c39d0ca13d326ee3da7f2199b6702e566c429cb827f06bdc42ac306f802b6ca1:0` | 55,036,800 |

All former selected reserve heads were queried spent. The fetcher's result is
explicitly a terminal candidate pending replay; the actual terminal body and
public predicates must justify reserve zero.

## Resources and retained evidence

The Vector-only acquisition took 34.02 controller seconds and scanned 73,690
accepted transactions. The sampled cgroup peak was 796,008,448 bytes with zero
swap; the unit stopped and its process group was empty. The separately prepared
Electron fallback was unnecessary and remains unexecuted.

Five main pages plus one post-query page total 228,986,175 decoded JSON bytes
and 30,605,585 local gzip bytes. These are not wire bandwidth measurements.
All six decoded/gzip byte and SHA256 pairs were rechecked locally and their bulk
paths are ignored. Raw pages remain on disk outside the publication allowlist;
the unchanged bundle retains their complete hash/size index. Selected bodies,
populated contexts, expanded headers, coverage and exact queries are public.

This is a testnet observation under the selected remote validating-node and
retained-history assumptions. It establishes neither independent consensus nor
durable recovery if every source prunes required data. RPC views remain
non-atomic. Sustained active-pool recovery, 10,000 operations, 20 Mbit/s and a
15-minute qualification remain untested. OLD-KPX2 REVEAL still has its existing
public exit fields; this acquisition does not establish stronger exit privacy.
