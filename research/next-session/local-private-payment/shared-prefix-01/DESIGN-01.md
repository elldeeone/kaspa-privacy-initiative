# Shared baseline: nonlive source contract 01

This is a prospective storage/path experiment. No active profile, runtime, admission or campaign has been changed or selected. All fixtures and controls are public and synthetic; no Original, private state, plan, route, logs or live baseline is read.

## Frozen change

1. `fetch_borsh_shared_prefix.mjs` derives from strict fetcher `b3a725...`. It keeps source/admission checks before acquisition and calls unchanged `prepareBaseParallel(info,a,output)` exactly once before connecting to either peer. Successful preparation leaves the sole ordinary baseline under `output/cached/`; permission finalization makes these new files `0400`.
2. `acquire_cached_shared.mjs` derives from `419d0f...`. It requires the prepared object bound to the admitted `info.base`, an existing real common bundle and an existing direct child named `attempt-[0-9]{3,}`. It deep-clones prepared state and metadata using the installed Node's built-in `structuredClone`; no compressed baseline bytes are copied per peer. Existing financial and current-state predicates remain unchanged.
3. The acquisition derivative reads/discovers from the common bundle, writes primary delta and post-query data only within the current attempt, and adds the attempt prefix exactly once. The primary delta locator offset remains `base.pages.length`. Original cached records and their fingerprint remain unchanged.
4. `confirm_pool_borsh_shared_prefix.py` selects the new fetcher and adds the acquisition derivative to its explicit source closure. Its replay, expected whole CASE, amount, confirmation and payout checks are unchanged. `campaign_pool_borsh_shared_prefix.py` selects that confirmation sibling; its other behavior is unchanged.

The old source files remain exact. Runtime68 `30da3b8e5573248f20753173654723cf683e3e44066ee1b6e6b0f64bbf2e1be1`, admission `fd47c3f8c6ae75d03be3eb335782bd68ac88e53ddbc7f6650929d6470d3db514`, financial sources, guards, SDK and strict RPC `597...` are neither replaced nor reinterpreted. No production fake-admission path, prepared-state CLI injection or skip-verification flag is added.

## Path contract

| Evidence | Path relative to the common bundle |
|---|---|
| Sole prepared baseline | `cached/00000.json.gz`, etc. |
| Peer primary delta | `attempt-NNN/delta/pages/...` |
| Peer post-query pages | `attempt-NNN/post-query/pages/...` |
| Peer event/error evidence | `attempt-NNN/PUBLIC-BORSH-EVENTS.jsonl`, `INCOMPLETE.json` |
| Full fallback primary pages | `attempt-NNN/full-fallback/pages/...` |
| Full fallback post-query pages | `attempt-NNN/full-fallback/post-query/pages/...` |

Cached results already contain common-bundle-relative paths; the fetcher must not prefix every page with `attempt-NNN`. Full fallback continues to rebase **both** page arrays from its own working root. No failed-peer page may enter a successful fetch selection.

Unchanged `verify_bundle_cached.mjs:213–216` obtains prefix `''` from a first path `cached/...`; this is a valid rebase, not an empty baseline. Its fingerprint and lineage comparisons, `verifyCopied`, `pageData`, hashes, no-`..`/absolute-path rules, symlink checks and single-link guarded reads remain authoritative. The common baseline must remain inside the final bundle so existing replay/export and publication consumers resolve every selected path without external aliases.

## Failure and resource contract

Preparation completes before any peer RPC connection or frontier timer. Its existing six-worker guard implementation still settles started reads on the first failure. Any preparation or chmod failure returns global `INCOMPLETE`, `attempts:[]`, a local-preparation phase and the first error category/class. Partial files remain; the output's existing exclusive/freshness checks prevent automatic reuse. No peer receives blame for a local copy failure.

After preparation, each peer has separate mutable metadata and its own new attempt directory. The unchanged stale/reorg fallback categories remain `CACHE_STALE`, `REORG`, `STALE_FRONTIER`, `STALE_CURRENT_VIEW`. Other peer errors retain the existing incomplete evidence and failover policy. Existing fetch-before-sidecar publication order is retained: a later write failure can safely halt without a valid joined confirmation; no overwrite or resume mechanism is added.

Root's measured baseline was 2,404,226,437 bytes; sharing avoids one additional retained copy of that payload. This is not a guarantee that all acquisition/fallback work fits any free-space figure. Full fallback can require additional history, and downstream reference preparation, selected-page reads and copied-page hashes still run. `0400` is not host sealing. No benchmark or privacy/Native qualification is inferred.

## Mandatory public controls (freeze before execution)

| ID | Required observation |
|---|---|
| C01 | Two peers: first fails after retaining delta evidence; second succeeds; preparation occurs once and evidence directories remain distinct. |
| C02 | Base bytes, inode identity, records, requests, edges, founding/frontier and fingerprint remain unchanged; first-peer/result mutations do not contaminate the second peer. |
| C03 | Nonempty primary delta and post-query arrays use exact common-root paths, correct locator offsets and unchanged path/hash verification. |
| C04 | Same-frontier empty arrays remain valid; an advanced frontier with missing required data refuses. |
| C05 | Full fallback rebases both arrays exactly once and does not falsely select cached pages. |
| C06 | Bad baseline authentication fails locally before any connection, retaining the first failure. |
| C07 | Forced local write/finalization failure retains partial output, makes zero connections, does not retry peers or resume that namespace, and requires a fresh identity. |
| C08 | Malformed attempt names, traversal and alias/path escapes refuse under the applicable unchanged guards. |
| C09 | Changed shared gzip bytes fail unchanged copied-page/export authentication. |
| C10 | Wrong prefix fingerprint or source lineage refuses unchanged verification. |
| C11 | Missing, double-prefixed or escaping primary/post-query paths refuse; successful selections exclude failed-attempt paths. |
| C12 | Missing/stale acquisition-helper closure entries refuse; the exact seven network source members join the saved fetch and unchanged runtime/admission. |

Assertions may group these obligations, but observed failures must be retained rather than weakening an expectation. Tiny synthetic RPC/module seams test actual new control/path logic; they do not qualify real financial admission, Kaspa consensus, Native replay or recovery. No live RPC, profile materialization, campaign launch or actual dataset execution is authorized by this contract. Root and independent review precede actual adoption.

`SOURCE-FREEZE-01.json` pins the four derivatives, unchanged immediate sources and this contract/ADR. The companion exact source diffs preserve the implementation boundary for review.
