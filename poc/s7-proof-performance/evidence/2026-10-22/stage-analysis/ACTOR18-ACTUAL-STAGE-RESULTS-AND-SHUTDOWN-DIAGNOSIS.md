# Actor18 observed stages and preserved shutdown failure

The trace completed all 390 segment proofs, 390 lifts and 389 joins. The
original resource profile remains **failed/incomplete**: its frozen topology
guard fired during shutdown. No original status, source or guard was changed,
and no retry was started by this analysis.

Exact live config/PID/start-tick capture identified RPC parent 2387956, primary
worker 2387963 and secondary worker 2387964, all with start ticks 39888998.
The parent was never observed with GPU memory. Each of the two GPU workers
matched its captured selected executable and config during the proving work.

| Descriptive observation | Result |
| --- | ---: |
| Worker ProofRequest to job `done` marker | 448.231687 s |
| Primary task service union | 314.662679 s |
| Recursion SDK marker intervals | 436.279553 s |
| Lift SDK marker intervals | 306.627753 s |
| Join SDK marker intervals | 129.651800 s |
| Primary service / recursion SDK overlap | 308.990603 s |
| Joins completed before last primary `Done` | 5 of 389 |
| Sampled matching GPU memory sum peak | 5532 MiB |
| Primary worker sampled peak | 3828 MiB |
| Secondary worker sampled peak | 1704 MiB |
| Sampled global device memory peak | 5671 MiB |

These are task/prover markers, not CUDA kernel timings. Primary intervals end
at manager `ProveSegmentDone`, which includes verification and message delivery.
Unions avoid double-counting delivery lag. Positive memory in both worker PIDs
shows resident allocation overlap, not simultaneous kernel execution. The
primary and secondary peaks happened together at sample 13 in this run.

The worker Session log independently recorded 390 segments, 102105088 total,
77752334 user, 13018888 paging and 11333866 reserved cycles. Actor SDK paging
and reserved fields remain **unavailable**: its zeros are placeholders. The
actual worker log values above must not be relabeled as returned SDK fields.

The secondary config orders task kinds `Lift, Join, Union, Resolve`. Exact
official `actors/factory.rs:137-155` selects the first pending kind in that
order. This gives a source-grounded explanation for lift priority and is
consistent with only five joins completing before primary work ended. Queue
availability, GPU contention, CPU scheduling and thermal/allocation history
also vary; one observation does not isolate a causal throughput improvement.
The captured factory source is in source-reference manifest addendum 02.

The sole topology flag is sample 2973 at `22:02:55.101701Z`. It names the same
captured primary PID/start ticks, but `/proc/2387963/exe` was unresolved and its
command line empty while NVML still reported 1552 MiB. Job `done` was logged
at `22:02:55.041942Z`; the complete candidate receipt's file mtime is
`22:02:55.042234800Z`. This is consistent with a shutdown visibility race.
It does not justify changing the frozen guard's failure or its incomplete
memory-qualification result.

The selected client saves/fsyncs the candidate before explicitly dropping its
prover. Its later local receipt checks and post-Drop report were interrupted;
`receipt.bin` and `report.json` were not produced. The preserved 223898-byte
candidate is SHA256
`2891e246e4feff140528a28215562ac1bb512a206f3792b56a6277a89ef722cc`.
Independent verification is a separate parent-owned observation.

A separate read-only cleanup audit checked all six observed PID/start-tick
identities; none remained present. No process was signaled by the audit.

Evidence: `actor18-8gib-final-stage-analysis-03.json`,
`actor18-8gib-worker-identity-capture.json`,
`actor18-8gib-posthoc-shutdown-diagnosis.json`, and
`actor18-8gib-independent-process-cleanup.json`. All are additive analyses;
the original monitor logs and flags remain unchanged.
