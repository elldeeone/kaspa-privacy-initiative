# Same-claim B2 GPU performance result

Both new saved proof artifacts passed independent CPU cryptographic verification
against the unchanged image/input/J336/successful claim, official JOIN, no
development mode and no unresolved assumptions. Existing crypto/control negatives
and eight exact outer-journal field mutations passed for each artifact. No guest,
circuit, setup, native transaction or compression changed.

| Measurement | Historical IPC19 | IPC18 | Separate actor18 / 8 GiB profile |
|---|---:|---:|---:|
|Reported startup/proof interval|302.926s historical|505.118s startup+API|Unavailable|
|Launch to actor JobDone|—|—|448.524s (different interval)|
|Segments|170|390|390|
|User cycles|77,752,334|77,752,334|77,752,334 in worker log|
|Total cycles|89,128,960|102,105,088|102,105,088 in worker log|
|Sampled matching GPU peak|6096 MiB|3828 MiB|5532 MiB|
|Host cgroup/sample peak|503,586,816 B|482,467,840 B|1,356,480,512 B|
|Independent receipt verification|Historical pass|Pass|Saved candidate pass|
|Operational completion|Historical pass|Pass|FAIL; incomplete qualification|

IPC18 reduced the sampled peak by37.20% while taking202.192s longer than the
historical proof. This is a single contextual comparison: CPU caps, caches and
concurrent CPU work differ. IPC18 recorded no cgroup CPU throttling and no swap.
The eight-core constraint suite ran during IPC18 and was absent during actor18.
No p95 or isolated causal scheduling claim follows.

IPC18 completed390 segment proofs,390 lifts and389 joins. Primary broad work
was242.708s; lift markers totaled112.465s and join markers134.568s. Its complete
primary3828 + recursion2926 + margin512 =7266 MiB failed the original6656 MiB
actor admission rule. That failure is preserved. No job ran under that failed
profile. A separately selected7680 MiB guarded experiment used the same8192 MiB
card and unchanged cryptographic/product checks.

The actor completed390 segment proofs,390 lifts and389 joins and saved its
candidate before shutdown. Host task intervals overlapped for308.991s; these
are not isolated CUDA kernel timings. Source and logs show pending lifts take
priority over joins; only five joins completed before the final primary task.
That explains a later join phase but does not isolate the cause of total latency.
Actor SDK paging/reserved zeros are unavailable placeholders; the worker's actual
execution log separately records13,018,888 paging and11,333,866 reserved cycles.

The actor did not complete its normal client report. SDK shutdown warnings at
22:02:55.043546/.067847 preceded the monitor guard. At22:02:55.101701 the guard
misclassified the already observed primary PID/start identity after its exe became
unavailable and cmdline empty, then stopped the unit. The frozen sample did not
record process state. It is consistent with exit, not evidence of an extra live
GPU worker. Candidate fsync preceded the guard; independent verification later
passed. Exact client API/Drop-cleanup times are unavailable. Preserve the original
operational FAIL and incomplete memory-qualification flags despite the valid
receipt and observed5532 MiB peak. All six observed identities are now absent,
the unit/cgroup are gone, and no GPU compute process remains.

The future correction in [monitor](../../monitor/README.md) was not used in either
experiment. Its classifier/topology seam distinguishes a previously authenticated
exited identity from an unexpected live worker, retaining its reported allocation.
Nine CPU-only regression cases passed, including a real Linux child observed in
Z state with missing exe and empty cmdline, then reaped. Foreign/reused/RPC-parent
and extra-worker rejection, and incomplete unknown/missing-identity evidence,
remain explicit. Historical runners, manifests and statuses stay byte-identical.

The60s latency diagnostic fails in all three runs. None qualifies R8's CPU-only
wallet,10s warm p95,60s payment p95, full user fees, independent exits or financial
privacy. No GPU proof rerun followed the monitor failure. All software binaries,
SDK/toolchains and runtime caches remain local with hashes; published artifacts
contain source, public proof data, logs, telemetry and independent verification.

New receipt SHA256 values:

- IPC18: `3ea11d808b1dac69a1aa1ba28543ce4874519270db977eb203125f557bdad83b`
- Actor saved candidate: `2891e246e4feff140528a28215562ac1bb512a206f3792b56a6277a89ef722cc`
