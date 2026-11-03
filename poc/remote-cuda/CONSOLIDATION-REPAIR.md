# Historical replay and process deadlines — 3 November 2026

The consolidation reproduced 11 failures in the 58-test remote-tooling suite:
nine fixed-package source mismatches and two external-controller-loss failures.
The repaired suite passes 67 tests, including the original checks and new
historical-source/deadline regressions. This is local CPU/process evidence.

## Historical source qualification

The fixed lifecycle and recovery binaries were built before the depth-four
changes. Their identity files correctly rejected newer source as a match for
those old binaries. The repair supplies explicitly selected
[historical source closures](historical-sources/README.md), then checks every
original source hash, binary archive, input, policy and program identity.
The installed historical B client is tested against those same frozen sources.

Default current-source restoration still rejects drift before creating output.
`restore-historical` labels the binding historical. No old identity file,
binary archive, proof, program image or expected journal was rewritten.

## Process-group deadline

The installed `/usr/bin/timeout` reported uutils 0.10.0. After killing the
controlling process, the retained timer stopped its immediate command at its
deadline but left that command's `sleep` grandchild running. Both real
controller-loss tests reproduced this failure. A version string is insufficient
evidence that the whole process group will stop.

The lifecycle and recovery workers now launch the shared
`process_deadline.py` command inside the new session already created by
`worker.run_phase`. The guard:

1. validates a finite positive duration and refuses unless it is its own
   session/process-group leader, before starting the command;
2. waits independently of the service and telemetry; and
3. sends SIGKILL to its complete owned group on timeout, interruption or a
   parent command exiting while live background peers remain.

Normal completion preserves the command's exit status. Partial artifacts stay
on disk. Existing aggregate-hour and lease limits are unchanged. The source is
included in both Docker recipes and their application-file identity checks.
No image was built, published, rented or deployed during this repair.

## Controls and adversarial second pass

The tests retain real controller termination, real grandchildren and absence-or-
zombie checks. New cases cover foreign-group refusal before child creation,
invalid durations, exact normal exit status, nested timeout with a retained
artifact and early parent exit with a surviving background child.

The guard accepts no target PID/group argument. It signals only while it is the
live group/session leader, avoiding an unrelated shell or a reused group ID.
Descendants that deliberately create a different session are outside this
same-group guarantee; the separate provider lease guard remains a distinct
boundary. Local root/host compromise is not addressed.

No verifier, value-conservation, nullifier, root, key derivation, reserve or
payout rule changes. Failed historical evidence remains retained. These repairs
establish no MPC privacy, GPU execution, chain acceptance, independent recovery,
cryptographic correctness or production safety.
