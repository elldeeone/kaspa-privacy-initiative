# Publication boundary

Publish source and exact executed snapshots, public fixture parser, plans,
acknowledgements, log/failure/resource/cleanup records, Auth484, proof128 and
VK328 only. The fresh 1.28 GB PK, executable and Cargo outputs stay outside Git.
The result uses the original executed snapshot before the explicitly recorded
post-run cosmetic formatting. Freeze paths can name local immutable binaries;
those are identities, not published executables.

The plan's original current-source paths are verified against build-01/source
for the two files listed in POST-RUN-FORMAT-ONLY.json. No original plan, source
acknowledgement, binary or result is overwritten to pretend formatted bytes
generated the retained PK. Current source passes rustfmt. Full raw matrix
serialization/hash is not claimed. Whole-process RSS and cumulative/proc
snapshots are labeled separately from cgroup accounting.
