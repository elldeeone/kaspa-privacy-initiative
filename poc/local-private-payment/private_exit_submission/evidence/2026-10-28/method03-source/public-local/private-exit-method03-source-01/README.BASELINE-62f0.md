# METHOD03 controller metadata candidate — source only

This directory grants no generation, capture, Original, proof, network, scoring
or broadcast authority. The passed e2e4 controller, 7d65 owner role, 88cb
transport, Source22, defaults and all completed evidence are unchanged.

Publication agreed these exact schemas and source-assigned labels:
`controller`, `receiver/0`, `transport/0` through `transport/5`, and `owner/0`
through `owner/5`. Slots A0..2 map to transport0..2; B0..2 to transport3..5.
That labels outgoing submissions; it creates no incoming-frame pairing.

## Two functions

`clock_snapshot(role)` runs **inside the actual calling role**, before Original
or candidate intake. Required captures are controller, receiver0 and all six
transports. Retain owner captures too. Its schema is
`kpb-method03-clock-snapshot/v1` with exactly:

```
role, pid, boot_id, clock_id="CLOCK_MONOTONIC",
time_namespace:{link,inode}, time_for_children_namespace:{link,inode},
timens_offsets:{monotonic_ns,boottime_ns},
sample:{monotonic_before_ns,realtime_ns,boottime_ns,monotonic_after_ns}
```

`read_observation(stream, reader_id="controller/"+role, role=role)` reads the
selected **fixed-status** pipe. Immediately after `readline`, before decoding,
logging or queueing, it samples monotonic, realtime and boottime clocks. Its
schema is `kpb-method03-status-observation/v1` with exactly:

```
reader_id, role, reader_pid,
reader_observed_monotonic_ns, reader_observed_realtime_ns,
reader_observed_boottime_ns, value
```

Both records include their `schema` field. The reader PID is the actual local
reader process, not the actor PID. Namespace-local role PIDs must be joined to
the separately retained actual host Popen/PID/PPID/namespace metadata by the
source-assigned role key. A snapshot from a bwrap parent or another proxy must
not stand in for the actual transport or receiver.

The queue consumer preserves the returned observation unchanged. It may add a
separate outer `consumed_monotonic_ns` or event timestamp; that is queue/logging
time and cannot replace the recorded read observation. No wait-start timestamp
is used as a successful202 upper bound. Observing the fixed transport receipt
is a controller observation of that status, not an invented server receipt time.

Only existing finite owner FRAME_WRITTEN/REFUSED, transport202 receipt/readerFD,
and receiver listener/summary status schemas are admitted. Unknown fields,
duplicate JSON fields, false financial claims, wrong-role statuses and
content-derived labels refuse without returning or recording the raw line.
EOF returns None and is not a receipt. The module adds no queues, delay,
barrier, order change, retry, fallback, source selection or launcher.

**Critical pipe contract:** owner status input is stderr2. Never attach the
reader to owner stdout1, which carries the private frame. The selected caller
must prove that binding. Transport and receiver status inputs are their fixed
stdout streams. All other actual Tor/readiness/launch/exit events, PIDs/PPIDs,
argv, mounts, pipe inodes/FD mappings, launch/order and fallback records remain
fully retained by the caller. This module neither redacts nor replaces them.

## Clock interpretation

The installed primary reference is
`/usr/share/man/man7/time_namespaces.7.gz`, SHA256
`a4531fa3a3cc70f65d71af746fa89865494c3c3b4b766babbcc20d86ea77d190`.
Its example has a shell remaining in the original current namespace while
`time_for_children` and its `timens_offsets` refer to the new child namespace.
Consequently offsets cannot silently be attributed to the current namespace
when these identities differ. The adapter records both identities and verifies
their stability, plus the offsets' stability, around its bracketed samples.
Seconds and nanoseconds are parsed as exact integers, including negative
seconds. No normalization is applied. CLOCK_REALTIME is auxiliary evidence,
not a substitute for a proven monotonic clock relation.

The independent extractor must refuse comparison unless it has actual
same-kernel boot/namespace/offset evidence, or a separately Root-frozen
calibration. A current/children mismatch is ambiguous and cannot be qualified
by this module. There is no caller-provided clockQualified flag or uncertainty
fit. Missing/malformed/changing kernel evidence refuses capture. Procfs is
trusted only under the separately selected real launcher/kernel assumptions;
this module does not defeat a privileged host fabricating its environment.

## Caller admission and controls

The module uses only stdlib and fixed public procfs paths. Before importing its
selected bytes, the external caller still performs the established seven-root
metadata inventory, default Original/truth exclusions and exact source/helper
admission. It does not import a private guard or inspect private state itself.
Mount this selected module as public source in any later role wrapper; do not
modify passed role/transport files. The new METHOD03 generator/role wrappers,
complete selection, clock procedure and persistent budgets still need Root's
explicit freeze before any private execution.

`public_controls.run(admitted_module_bytes)` uses only finite public status
fixtures, procfs and one ordinary public Python child. It checks a delayed JSON
decoder/consumption, strict metadata refusals, exact offset semantics, actual
public parent/child namespace evidence and a synthetic ambiguous namespace
fixture. It does not launch the passed pipeline, inspect an Original/candidate,
capture any private event, generate a note/proof, or use a network. Its clock
records are source controls and must never be relabelled actual METHOD03 role
captures.
