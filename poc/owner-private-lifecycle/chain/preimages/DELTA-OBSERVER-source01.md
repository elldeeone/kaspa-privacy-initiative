# Whole MAIN page delta observer

`delta.mjs` is a new read-only producer of the existing `kpx8-gn3-network-fetch/v1`
format. Its output remains `FETCHED_PENDING_REPLAY`. The unchanged
`verify_bundle.mjs` and `replay.py` must cold-replay every MAIN and post-query page
and every native case before any consumer advances state. The adapter has no
signing, transaction submission, financial policy or privacy workload code.

The caller selects the previous confirmed `HANDOFF.json` by external whole-file
SHA. The handoff must bind the same selection, descriptor, prior fetch and MAIN
page hashes and lengths. Cached pages are individually authenticated using both
compressed and decoded SHA and length, with canonical paths and no links.

The previous last raw MAIN response can extend past the previous fixed confirmed
frontier. The adapter never truncates or projects it. It reuses only whole exact
MAIN responses entirely before or at that frontier, then fetches fresh `Full`
responses from the final reused page's confirmed end cursor. The entire dropped
trailing response is reacquired. Prior post-query pages are never reused as MAIN
pages. For the actual Exit1 capture `fc5296a8…`, pages 0 through 40 are reusable;
page 41 contains the old frontier at group 477 of 1,242 and is discarded/refetched.
The fresh seam is `804adaa21c482c12ca0577b15444820d92b5aa48d59c6d2a43df45128cd620df`;
the old confirmed frontier is
`e0d8990f3ae429c9466ed93907071620d291ee21fa045ea7a3fcec9e320ce648`.

The selected real RPC freshly checks the exact birth, seam and old-frontier
headers and selected-chain membership. Fresh continuous delta coverage must
include the old confirmed frontier and reach the new fixed frontier. Removed
blocks, gaps, altered bytes, wrong selections, stale frontiers, a missing cache,
or an uncertain seam cause the existing full `fetchOne` acquisition fallback.
Fresh exact current-entry and payout queries, post-query delta and final repeat
queries use the original acquisition functions and original depth policy.

The new collector is explicitly recorded as `source.collector` with its source
hashes. Rewriting page metadata paths is the only change to reused page records;
compressed raw bytes and their decoded contents remain exact. The collector is
not represented as the old `fetch.mjs` source. Existing fixed verifier and native
source identities remain independently pinned by the recovery packet.

This follows the official RPC semantics at upstream
`4edcbbccb449f84832afb1ca157904b35f37d006`:
[V2 service](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/rpc/service/src/service.rs#L1479-L1529)
preserves removals and trims unconfirmed additions;
[chain traversal](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/src/processes/traversal_manager.rs#L34-L59)
returns removals back to the common ancestor and additions forward from it.
The source describes the algorithm; it does not attest the remote deployed build.
The existing validating-node/transport/host trust remains; this is not an
independent consensus proof or continuous-currentness proof.

Invocation (only after the host exclusion policy has guarded all public source,
SDK, selector, prior handoff, prior fetch and candidate MAIN page paths):

```text
node delta.mjs PROFILE PROFILE_SHA DESCRIPTOR DESCRIPTOR_SHA PRIOR_HANDOFF HANDOFF_SHA FRESH_OUTPUT [--rpc URL] [--sdk-dir DIR]
```

`delta.test.mjs` contains synthetic transport controls for whole-page selection,
tampered cache bytes/lengths, removals, predecessor gaps, stale fresh frontiers,
missing pages and wrong cursor requests. These do not demonstrate acceptance of
an actual transaction. Integration additionally requires a read-only same-Exit1
control: fresh incremental fetch, complete unchanged SDK/native replay, and exact
HISTORY/CHECKPOINT byte-hash agreement with the full Exit1 confirmation.
