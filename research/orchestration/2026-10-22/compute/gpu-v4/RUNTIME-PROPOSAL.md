# V4 exact distro-link compatibility proposal

**SOURCE ONLY: independent review and a NEW resource allocation required.** No v4 module, installer, attester, mock test, profile or GPU operation has run. Static Python AST parsing is syntax evidence only. Frozen v3 and its failed environment/receipts remain unchanged. Canonical failed-v3 reports were committed as a0553063f149a9e0af4621af2c600580ad5db21d.

Keep the same /usr/bin/python3.14, standard library, -I -S -B startup, private dependencies and numerical code. Add manifest-pinned stdlib-external-links.json and validation limited to two exact relations:

| Source relation | Target identity |
|---|---|
| /usr/lib/python3.14/sitecustomize.py -> /etc/python3.14/sitecustomize.py | Root:root0644 regular file,155 bytes, SHA25643d81125d92376b1a69d53a71126a041cc9a18d8080e92dea0a2ae23be138b1e; libpython3.14-minimal:amd64 3.14.4-1ubuntu0.2. |
| /usr/lib/python3.14/config-3.14-x86_64-linux-gnu/libpython3.14.so -> ../../x86_64-linux-gnu/libpython3.14.so.1 -> libpython3.14.so.1.0 | Resolved /usr/lib/x86_64-linux-gnu/libpython3.14.so.1.0; root:root0644 regular file,8,247,200 bytes, SHA256982cb3768d1d8b00126255ee2785bccf8360c68b197fb3dec95858ab56195f87; libpython3.14:amd64 3.14.4-1ubuntu0.2. |

Every link hop is bound to its exact text, path, root ownership and mode0777. Target path/type/size/ownership/mode/hash must match. Package name/architecture/version/install status must match one local dpkg status record; every hop and target must occur in its exact package file list. Package metadata must be regular root:root0644 with no symlink ancestors; reads are bounded to8MiB for status and1MiB for a list. No subprocess, hook import or package operation is added.

The validator proactively checks both relations before traversal, rejecting missing links or regular-file substitutions. It checks each encountered external relation again. All other external links remain rejected. The exception applies only to the exact /usr/lib/python3.14 tree, never another root or the venv. Full installed RECORD, venv, stdlib, named tool and driver attestation remains. Accepted link evidence, package-record/file-list hashes and policy hash enter the runtime identity, which must be recomputed and exactly matched before dispatch.

No host hook, Python, driver, Bubblewrap configuration or worker mount changes. /etc is not added to the namespace. The155-byte hook source installs Apport's exception handler; its imported module was not audited. Earlier v3 metadata helpers used normal Python startup and may have loaded sitecustomize automatically; canonical v3 receipts disclose that. V4 preparation used explicit /usr/bin/python3.14 -I -S -B for Python helpers.

A hermetic CPython would change additional interpreter, library and mount paths and need newly approved supplier/runtime bytes. None was selected or installed. The exact distro relations are the smaller supported compatibility correction with the existing interpreter. This is an explicit scoped trust-policy addition, not a generic symlink exemption. Local package metadata agreement is not upstream signature verification. Concurrent privileged host mutation remains outside the harness prevention claim.

## Minimal delta and unchanged experiment

Substantive changes: runtime_identity.py and stdlib-external-links.json. Mechanical isolation changes: guards.py, launch.py and PROVISION-CGROUP.sh rename only the owned cgroup basename from kpi-gpu-benchmark-v3 to kpi-gpu-benchmark-v4. SETUP.sh executes its adjacent setup.py, so a staged copy cannot accidentally dispatch the frozen old revision.

benchmark.py, setup.py, capsule/adapter.py, capsule/worker.py, reference observer/tests, fixtures and complete expected predictions are byte-identical to v3. Retained mocked PID receipts remain historical v3 evidence, not v4 execution evidence. No new executable mock test is claimed.

Unchanged requirements: both views;64 targets;13/26 full variants; exact integer sums, eligibility, order, ties, deduplication and Fraction semantics; eligible profile share>=25% and calls>=100,000 in EACH view; GPU>=20% better cold AND warm end-to-end against BOTH reference and packed CPU in BOTH views. Worker2CPU/4GiB/no-swap/64PID/300s; allocator2GiB; sampled whole-device3GiB; nominal30min overall. The planned controller allowance is separate128MiB and at most0.25CPU during timing. All backends use the same newly attested runtime. Package/kernel success is not adoption.

## Review and future release

Review the exact-link policy/validator, adjacent setup wrapper and mechanical cgroup rename. Confirm rejection of changed link text/hops/resolution, target bytes/type/owner/mode/size, package version/status/ownership, missing or replaced expected links, and any unexpected external path. There is no broad /etc approval. No authored code has been imported/executed; only text parsing and byte comparison occurred.

Only after independent acceptance and NEW allocation: stage a fresh exact copy, run setup with its whole tree capped2CPU/4GiB, inspect and pin the successful actual runtime lock, qualify namespace/controls/owned cleanup, then both-view reference profiles/parity and finally CPU/GPU measurements. Preserve failed v3. Do not retune, extend time/caps, reuse a failed identity, or silently change the workload.

Prior setup took43.356s, not a guarantee; retain its900s backstop and a new explicit1800s overall clock only when allocated. A15–25minute quiet screen window was requested for uncontended development timings, subject to remaining overall/worker limits. Scheduling under a controlled concurrent load would require the parent's explicit interpretation/release and must be labelled accordingly; no numerical gate changes are proposed. Waiting does not extend the clock.

Canonical proposal/patch belong in Forge Git under research/orchestration/2026-10-22/compute/gpu-v4/. Evidence-lineage owns independent review and commit. V4 execution is not released.

## Frozen review identity

Package: /home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/revisions/v4

Raw manifest SHA-256: 2515abffcb08c0ff2e942e5551c21b017b74c7a862e1e0e693ed35db2daa8e61

Minimal source patch SHA-256: 6f6e7976c748ecd166196b43868fe19fb9decf2082b89b37290a0ef4588bf645

The package has 28 manifest leaves. The independently reviewed timing/equivalence code and inherited source/input/oracle leaves remain unchanged.
