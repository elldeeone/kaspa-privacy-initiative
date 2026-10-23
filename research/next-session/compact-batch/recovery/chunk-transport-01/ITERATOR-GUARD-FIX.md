# One-shot exclusion iterator correction

Independent review found an API defect in initial source
`8cbe9d2ce5d78297cb69e65b748b031835a1b7fd0e981f15ef73111b6d3825bc`.
`restore()` consumed `forbidden_paths` to collect inode metadata, then passed the
same iterable to the manifest reader. A one-shot generator was exhausted before
that second pass. Chunk opens retained the collected exclusions, but the manifest
open lost them. CLI arguments are lists; the initial actual public-key roundtrips
passed no exclusions or private paths, so their whole-byte verification is valid
within that narrower scope. They do not demonstrate this missing API case.

`iterator-regression-before-01` retains a deliberate failure against exact initial
source. A canonical public synthetic manifest serves as its own forbidden inode;
a positively calibrated kernel IN_OPEN watch observed content-open and the call
did not raise the required error. No real backup, seed, PK or other private bytes
were present. The independent reviewer also reproduced the same defect during a
crossed-message window. Both negatives are one defect/control category, not two
distinct successes.

Current source
`c713a4871079acd040f5c434ceed47c4d6f71885c8e5256199a86488a5f724aa`
materializes exclusion and absence-probe iterables once, before either metadata
checks or public reads. The manifest reader therefore receives the same complete
exclusions as chunk opens. Chunk semantics, external whole anchor and financial
code are unchanged.

Root's second pass found the same repeated-iterable pattern in the pre-existing
`stage_capsule`, `pack_local` and HTTPS `retrieve_capsule` outer APIs. Each now
materializes `forbidden_paths` before any metadata/public read. The exact current
and historical source bindings are listed in
[SOURCE-SUPERSESSION.json](SOURCE-SUPERSESSION.json). Historical manifests, lists
and source archives are retained verbatim. Their entries naming an old production
path describe that historical version; the supersession map points to its exact
existing archive and the separately bound current file. No old hash is rewritten
to pretend it measured current source.

`fixed-controls-01` ran all **17 distinct controls**: the original 16 plus the one
generator regression. All passed; the new control rejects the manifest before
content-open and publishes no output. Earlier reruns are retained without adding
them to the distinct count. The fixed source also has a fresh actual compact and
wide roundtrip in `actual-roundtrip-02`. That run completed with the historical
capsule helper before the expanded outer-API fix. The final `actual-roundtrip-03`
selects the current capsule helper. Earlier actual results and source snapshots
remain unchanged and versioned separately. Current outer-API controls and their
additional generator regressions are recorded separately; executions are never
summed into extra distinct control categories.
