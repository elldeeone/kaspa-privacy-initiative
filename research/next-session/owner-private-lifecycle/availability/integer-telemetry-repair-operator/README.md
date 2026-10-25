# Integer-telemetry interoperability repair

After five confirmed exits, the frozen downloaded parser refused a fractional
transport diagnostic: `source.transport.cache_preparation_seconds=65.038`.
This was a liveness failure in the observer/wallet boundary. The complete
financial parser, native rules and privacy checks were kept unchanged.

The separately reviewed [one-input normalizer](normalizer.py), SHA
`2be1e915203a0b0be3970305a40f952cf5732f06667bea33890f2868eb8f704f`,
converts only that selected diagnostic to integer milliseconds using exact
integer-ratio arithmetic. Typed equality after removing the two diagnostic
paths requires every other field/value/type to remain unchanged. Whole pages,
transactions, witnesses, budgets, populated contexts, monetary amounts, roots
and payout queries are preserved. The original captured fetch remains intact.

[Source-to-copy provenance](SOURCE-TO-COPY.json) authenticates three exact safe
copies: the normalizer, its [read-only controls](NORMALIZER-CONTROLS.json) and
the [original normalization provenance](NORMALIZATION-PROVENANCE.json). It also
pins existing source/review/release/resume records without duplicating them.
No old or normalized fetch body, configuration, HEAD, client data, private order,
raw log or acquisition artifact is included.

## Actual replay and resume boundary

The [actual replay receipt](ACTUAL-NORMALIZED-REPLAY.json) and
[isolation receipt](REPLAY-ISOLATION.json), copied under a separate
[append-only supplement](SOURCE-TO-COPY-02.json), record unchanged downloaded
SDK/native Full/every-input replay with exact original accepted E5 history and
checkpoint. Original paths were absent; network, owner backup, witness, PK and
GPU mounts were unavailable. This is execution evidence distinct from the
[conditional Root release](../ROOT-INTEGER-TELEMETRY-RESUME-RELEASE-01.json).

The [reviewed generic resume caller](../../integration/operators/independent-exit-resume-operator.py)
and its [copy provenance](../../integration/operators/RESUME-PROVENANCE.json)
reconstruct the five completed transitions from actual public accepted cases,
discard old private scheduling/ownership state and restore three fresh
original-seed clients before starting candidate06. Prior durable transaction
markers remain used. This is the same financial trial; no confirmed transaction
was resent and no new financial profile or proving parameters were selected.

## Honest producer attribution

Original accepted E5 was captured by **Source02**,
`whole-main-page-delta/v2`, source SHA
`9006cb70accfcb8cf8e0bb35336e2b51daec151983670b45044f7c8fc1c43f7b`.
The normalization has its own source/old/new/projection hashes. It is not relabeled
as a Source03 capture.

[Source03 review](../../review/DELTA-INTEGER-TELEMETRY-SOURCE03-REVIEW-01.json)
and [11 targeted controls](../DELTA-INTEGER-TELEMETRY-CONTROLS-03.json) cover the
future collector's integer-millisecond diagnostic and v3 label. Existing
Source02 preimages remain in the chain archive; this folder adds no replacement
copy of that financial/public-data runtime. Every subsequent actual capture
still requires all normal complete-prefix SDK/native/current-state/payout
checks. Source-only controls do not establish a later payout or terminal result.
