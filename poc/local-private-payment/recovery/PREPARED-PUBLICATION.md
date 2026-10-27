# Admit public audit inputs once per batch

`final_publication_launch_prepared.py` separates the public admission work from
each isolated wallet check. The selected `final_publication_launch_large.py`
source remains pinned to `c465c8e6c77b80a9d4f3928cbbe97704751104ec96488fcf9516efe007ceff42`;
the literal and derived workers are unchanged.

`prepare(files, releases_by_context, runtime, selected_c465_row)` takes the exact
file rows from a finite publication release. Each context release and the base
launcher use closed `{source, bytes, sha256}` selections. All context releases
must select the identical file rows. Preparation admits every candidate through
unchanged helper09 and stages small candidates and public sources once.

The returned object exposes `execute(original_metadata_args, cohort, identity)`.
It checks only the Original's metadata in the controller, then runs separate
one-leaf literal and derived namespaces. Current public metadata and Original
metadata are checked before and after each worker. Every unchanged worker still
authenticates the complete selected candidate bytes before its private read.
New worker results use a fresh unchanged helper09 reader to avoid stale private
inode history; no helper is altered or cleared. Used job identities cannot be
reused. `close()` disables further execution and retains public evidence.

Large candidates are ordinary single-link files bound read-only. They are
**not sealed storage**. This retains the base launcher's trusted-host and
no-concurrent-host-mutation boundary. Small staged files and public code also
have their identities checked; an administrator controlling the host remains
outside this experiment's claim. No Original descriptor is cached or shared,
and no audit PASS marker substitutes for public admission.

The controller must separately pin this derivative and the base source. Every
envelope binds the derivative's actual source hash, base hash, candidate
manifest, context release and public preparation provenance. The batch
controller remains responsible for complete Root-selected page coverage,
all nine Originals across every batch, supplemental metadata scanning and the
three positive historical-exit checks against the same accepted context.

Physical storage includes one copy of small candidates and public sources per
prepared batch, plus the producer's existing decoded batch and archive. Large
views add no persistent payload copy. Admission temporarily reads one complete
candidate, so peak process memory includes the largest selected file. Worker
scanning and host RAM/tmpfs headroom must still be measured before execution.

The companion controls use deliberately public seed fixtures. They run the
unchanged literal checker in real empty namespaces and use explicitly mocked
derived results to test supervisor result checks. They do not qualify actual
Original coverage, financial acceptance, cryptographic correctness, privacy,
long-term availability or physical offhost recovery.
