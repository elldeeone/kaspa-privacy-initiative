# Public fixed-claim proof-performance packet

This packet contains two independently verified public Succinct proof artifacts
for the same selected B2 claim. IPC18 completed normally. The separately selected
actor18 experiment produced a valid saved candidate but its topology monitor
stopped shutdown, so its original operational FAIL/incomplete qualification and
missing exact client timings remain. See [the result](../../RESULTS.md).

The original6656 MiB admission FAIL and the separate7680 MiB profile are retained
as distinct records. SDK shutdown warnings preceded the actor guard; no claim is
made that the guard caused them. The historical sample did not record process
state. A separate future correction/regression observes a real child in Z state;
that correction was not used in either frozen GPU run and no proof was rerun after the monitor failure.

Contents include reviewed source/locks and exact runner snapshots; selected public
input/P/J; candidate/saved proof data; full stage logs and matching-PID telemetry;
prospective plans; source-backed analyses; independent verifier source, oracle,
control vectors/results; and independently checked cleanup. Every record is local
synthetic/public research evidence. There is no funding, broadcast, new native
transaction, owner/replay/withdrawal/recovery workflow or wallet qualification.

`MANIFEST.json` and `SHA256SUMS` cover every other file in this directory. Their
own hashes are reported externally; self-hashing manifest loops are excluded.
Use `sha256sum -c SHA256SUMS` from this directory to check the published files.

This is a deliberate publication view. Generated client/verifier/guest/worker
executables, toolchains and runtime caches stay local. Their hashes and locations
are in `OMITTED-LOCAL-ARTIFACTS.json`. Full historical build manifests referencing
those files cannot all be rehashed from Git alone. The source-reference manifest
and addendum are also metadata views: the container-extracted upstream source
snapshot remains local, with exact image/head/file hashes retained. No exact
clean upstream sppark checkout is claimed from its dirty-cache metadata.

Build the host from the package source/lock and the existing pinned repository
sources. The original public guest/program must be restored by its separately
pinned source/tool recipe or obtained and checked by hash. The CUDA worker is the
retained qualified3.0.3 CUDA build; the ordinary official release executable is
not a substitute for its GPU identity. The runner snapshots retain exact historic
absolute paths; they are evidence, not a command to overwrite or reuse a past run
identity. Future runs require fresh task-local paths and a prospective selection.

No compiled software is distributed in this packet. `.bin` files are public
cryptographic proof data, canonical parameters or public fixture/control vectors.
