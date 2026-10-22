# GPU v3 runtime qualification — 2026-10-22

Status: **BLOCKED at runtime attestation; release stopped.** Actual Linux CPU, memory, PID and owned-descendant cleanup probes passed. The fixed observer screen, namespace controls, reference profiles and CUDA work did not start.

This report covers the authorized Forge attempt beginning **20:04:20 AEDT** (09:04:20 UTC), with an unchanged 1,800-second overall deadline of 20:34:20. Setup failed at **20:05:36**. Parent explicitly stopped this release; no retry or check relaxation occurred.

## Source, output and resource identities

The frozen source is /home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/revisions/v3, raw manifest SHA-256 **a9765efdc8bbf427cb896a3c34ec58626be75b180611d0e26447d481ec5bf7dc**. All 27 manifest leaves were verified before copying and again after failure. The frozen originals and the execution copy's source bytes remain unchanged. V2 was never run.

The new exclusive execution root is:

/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/executions/20261022T090300Z

Its package/ directory contains the exact source copy and the preserved failed private environment. Qualification scripts, logs and receipts are siblings. No active research checkout or private evaluation data was copied or mounted.

Parent allocated worker limits of 2 vCPU / 4 GiB RAM / no swap / 64 PIDs, a separate controller allowance of 128 MiB and up to 0.25 CPU for timed work, and 2 GiB GPU allocator / 3 GiB sampled whole-device VRAM stops. Thus the planned screen's aggregate RAM reservation was 4.125 GiB. No timed controller or worker was started. Setup instead ran alone in a unit capping the entire setup/controller/helper tree at 2 CPU, CPUs 0–1, 4 GiB, no swap and 64 tasks. Its unit had a 900-second backstop; the overall deadline remained unchanged.

The 19:58:48 capacity refresh found approximately 21.19 GiB MemAvailable and GPU 1 MiB / 0%, without a heavy KPI worker. Immediately before setup at 20:04:53, MemAvailable was 21,036,371,968 bytes with zero memory-PSI averages. A separately coordinated recovery build was active; timed measurements were held pending a quiet window.

## Kernel enforcement and owned cleanup

Qualifier unit: kpi-gpu-v3-qualify-20261022T090300Z.service, invocation fd549711223f4377b109f4122e3725be. Its controller was capped at 128 MiB, 2 CPU, CPUs 0–1, 64 tasks and 75 seconds.

A fresh disposable sibling cgroup used stricter limits: 134,217,728 bytes memory, zero swap, memory.oom.group=1, 8 PIDs and cpu.max=50000 100000. This exercised controller behavior without deliberately exhausting the full worker allocation. Separately, the actual v3 job cgroup's unchanged 4 GiB / 2 CPU / 64 PID configuration and attach/kill permissions were verified.

| Probe | Observed result |
|---|---|
| CPU | 1,557,260 microseconds CPU usage over 3.111 seconds before cleanup; 31 throttled periods. |
| Memory | Controlled 256 MiB allocation in the 128 MiB probe was killed; memory.peak was exactly 134,217,728 bytes. Final probe counters: max=37, oom=1, oom_kill=2, oom_group_kill=1. |
| PID | Forking beyond eight total tasks returned EAGAIN; pids.events max increased by one. |
| Descendant cleanup | An owned wrapper exited while its child and grandchild ignored TERM. Reviewed v3 tracking and escalation completed in 1.049 seconds; wrapper exit was observed, no tracked survivor or populated cgroup remained. |

All four probes passed by 20:04:28. The qualifier used the reviewed v3 guard implementation after verifying its manifest. This is actual Linux qualification of these bounded cases, not a proof of arbitrary process-cleanup safety or a 4 GiB stress benchmark. The disposable probe was removed. Its source hash is 13cc0a50d79bce9580f40883c977b11574b4a714c8135daca26f86b48899b3dd.

## Private installation and exact blocker

Setup unit: kpi-gpu-v3-setup-20261022T090300Z.service, invocation a112a335bbc24348b141261e105836de. Systemd recorded **43.356 seconds wall, 19.167558 seconds CPU, and 4,294,967,296 bytes peak charged memory**. Charged memory can include file cache; this is not a process-RSS measurement. The terminal result is exit-code / status 1 with the attester's Python exception.

Wheel-only, hash-required installation from the explicit PyPI index completed for 12 distributions using the lane's private environment and caches. Direct versions were NumPy 2.3.5 and cupy-cuda12x 14.2.0; CUDA toolkit metadata was 12.9.2.0, runtime 12.9.79 and NVRTC 12.9.86. The complete exact transitive set and wheel hashes are preserved in requirements.lock, SHA-256 **52c90385c6914d4ec96396df5e62fb0dffb265d60c24c87d74b9562c55958011**.

The installed-record/version checks were reached before the failure, but the attester returned **no runtime-lock.json**. Therefore no complete installed-environment identity is accepted. Wheel installation is not CUDA readiness.

The exact exception is:

> RuntimeError: unapproved runtime link: /usr/lib/python3.14/sitecustomize.py

In frozen runtime_identity.py:37–47, tree() permits links only when the resolved target stays inside the tree, except the specifically allowed /usr/bin/python3.14 interpreter link for the venv. Line 131 calls tree(/usr/lib/python3.14) without that exception. This host layout fails the rule; no import of the hook is needed to trigger rejection.

| Path | Type / ownership / mode | Provenance |
|---|---|---|
| /usr/lib/python3.14/sitecustomize.py | Symlink, root:root, 0777 | Exact target /etc/python3.14/sitecustomize.py; package libpython3.14-minimal:amd64. |
| /etc/python3.14/sitecustomize.py | Regular file, root:root, 0644, 155 bytes | SHA-256 43d81125d92376b1a69d53a71126a041cc9a18d8080e92dea0a2ae23be138b1e. |
| /usr/lib/python3.14/config-3.14-x86_64-linux-gnu/libpython3.14.so | Symlink, root:root, 0777 | Resolves to /usr/lib/x86_64-linux-gnu/libpython3.14.so.1.0; package libpython3.14:amd64. |
| /usr/lib/x86_64-linux-gnu/libpython3.14.so.1.0 | Regular file, root:root, 0644, 8,247,200 bytes | SHA-256 982cb3768d1d8b00126255ee2785bccf8360c68b197fb3dec95858ab56195f87. |

The second external link would also violate the same rule. For the hook, libpython3.14-minimal version 3.14.4-1ubuntu0.2 records conffile MD5 d6b276695157bde06a56ba1b2bc53670, which matches the current file. This is agreement with the local package database, not independent upstream signature verification.

A final bounded source read using /usr/bin/python3.14 -I -S -B found that the 155-byte hook attempts to import apport_python_hook and install its exception handler when available. The file itself contains no authorization or sandbox check; the imported Apport module was not inspected or executed for this diagnosis. No host hook, Python, driver or Bubblewrap configuration was edited.

Inspection limitation: earlier metadata-only helper scripts used plain system python3, which resolves to Python 3.14 and does not exclude normal automatic sitecustomize startup. No explicit hook import/call was issued, but those startups cannot be represented as excluding it. Actual setup attestation and qualifier actors used -I -S -B. Subsequent inspection also used those flags. Python documents this startup distinction in its [site documentation](https://docs.python.org/3.14/library/site.html).

## Terminal state and retained evidence

At 20:09:57 AEDT the qualifier was inactive/dead/success and setup failed/exit-code 1; both MainPID=0, ControlPID=0 and no ControlGroup. Every setup helper receipt reports complete cleanup with no survivors. No tracked probe PID/start identity or active lane program remained. The unused v3 worker cgroup had zero memory events, zero peak and zero processes; it was removed after recording its state. The disposable probe cgroup was also absent. The 4.125 GiB reservation is released.

The RTX 3070 remained at 1 MiB / 0%, device UUID GPU-352aec53-18dd-0961-df17-b193565c24f6, with no compute owners. Only read-only nvidia-smi telemetry was used; no CuPy/NumPy import, CUDA context, NVRTC compilation, observer profile or benchmark was launched.

Receipts under the execution root:

| Receipt | SHA-256 |
|---|---|
| qualification/summary.json | e2c857c86176826c6e043f75c9c7eb35d77b24deb2270a77d62f94e5247c1d07 |
| provenance-inspection.json | 65efc1a5bcdbebd0473a40924da2e8823de3fd5d28616bad8ab292245ba4b741 |
| terminal-evidence.json | f30abf8733da89c86bb34885f87b9f9f7c1b04de658629c8b11372d565412884 |
| release-terminal.json | 36991ffe819341bd41bfeef8fac33d6ad9abba1133ca9ac332f6c84dbe163ad3 |
| package/setup-receipt.json | b07b8db71bb28bc91946bd12f95229ff413b6a43e21527336970a6a7d0e31f21 |
| setup-unit-terminal.txt | 9aa04e0bfa2c534a17c2691dd2be987447934e70f20d8a3a5f04477bd7df3ad7 |
| setup-unit-journal.txt | aa6ef2921250264dad520c3682024648af9c232fc9a23a097145d69897c1b75c |

The failed environment, caches, setup stage logs and source copy are preserved. Their existence does not supply a missing runtime attestation. This document and RUNTIME-RESULT.md are the canonical Git-facing receipts; evidence-lineage owns staging and commit.
