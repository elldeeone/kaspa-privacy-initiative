> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# GPU package v3: narrow execution-safety delta review

**Disposition: bounded static acceptance of v3's identity/mock/path delta. No remaining source blocker found in this scope. This is not execution approval or GPU readiness.**

Reviewed on 2026-10-22. Source root: /home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/revisions/v3. This review inherits the unchanged v2 execution-safety review and the independent v2 timing/equivalence review; it does not repeat statistical or numerical analysis.

## Immutable identity and closure

- Raw manifest SHA-256: a9765efdc8bbf427cb896a3c34ec58626be75b180611d0e26447d481ec5bf7dc.
- STATUS.json SHA-256: 7f612a80add5b0001aba849b549575fe949723bdb93bad05a75854724b5c82e4.
- Independently verified all 27 manifested files, totaling 997,260 bytes, plus the manifest/status relationship. The directory contains exactly those 27 files and manifest.json/STATUS.json; no extra files or symlinks, including path ancestors, were found.
- Reverified all 18 original v1 files and all 24 original v2 files against their preserved manifests. All 12 archive-mapped v3 inputs/expected outputs/reference sources retain their v1/v2 pins. Their public-archive provenance remains the previously verified archive 05b3d80d080aa51ec48fed387caecd0197ca64efe141eb18dfa33af5830a5950, base 9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02; this narrow pass did not unpack or rehash the entire archive again.
- Both final v2 review files match their manifest pins: execution review 59223f2b26828c6931eace2250e1f6edca6f4b14aba006509e2c3f65c424fb1a and timing/equivalence review 7b80ed371f842b65496bf32af4f6296a856c81e9901903c9990d003e88e557d2.

## Reviewed defect is closed at source level

V2 could replace a remembered PID/start identity during refresh and then signal an unrelated process occupying a reused PID. V3 captures the wrapper identity immediately after Popen and before any polling/reaping (guards.py:119–127). Missing initial identity remains missing.

Refresh begins with matching saved identities (132–137), excludes the original numeric root from later adopted-child acquisition (141–143), rejects a reused tracked identity during descendant traversal (146–148), and uses setdefault rather than replacing recorded identities (153–155). Matching known descendants remain roots after wrapper exit, so legitimate survivors and their newly discovered children remain trackable. Existing pidfd-open/current-start verification before signaling is retained (159–170).

Both cleanup completion paths additionally require a non-None wrapper return code (180–181, 205–208). Missing proc metadata alone therefore cannot certify an executing wrapper gone. Finite polling and the cgroup-based worker enforcement inherited from v2 are unchanged.

## Mock evidence and limits

Inspected tests/pid_identity_mock_test.py in full. It extracts only the four undecorated TrackedProcess methods, rejects imports in that class, and supplies fake process/procfs/pidfd/signal/wait/clock endpoints (18–83). The pre-exec callback is never invoked; ctypes and exit endpoints fail if reached. Its cases exercise foreign and direct-child root reuse, descendant reuse, legitimate survivors, adopted/prior-child selection, missing initial identity, missing-metadata cleanup, and reuse between pidfd open and identity verification (85–154).

The pinned receipt reports all eight v3 cases passed and the unchanged v2 negative control reproduces the primary root/descendant faults. Receipt source hashes match verified guards.py files: v3 f44e516f24a74fd463873b7d94ccffaba5134f6486cc7e7e0faedcfc223c0f19; v2 58c7845862842479825023497bb2cafc33aac41466845cc69056881cdf424acb. Test hash: 0843aa6e85111c8fe9732559fb839097a18b23eedb58745c66d77d73fa77bc23.

The author's external Mac receipt records 0.22 seconds real and 17,022,976 bytes maximum RSS. I inspected and hash-verified these receipts; I did not independently rerun the mock. It provides useful regression evidence for actual extracted methods, not evidence of kernel pidfd behavior, process reparenting, namespaces, cgroup.kill, GPU cleanup, or hardware performance.

## Mechanical paths and remaining gates

The only other executable-file deltas are the matching v3 cgroup path in guards.py, launch.py and PROVISION-CGROUP.sh, SETUP.sh's exact v3 setup path, and benchmark.py's descriptive/status labels. Observer, adapter, worker, setup/runtime implementation, fixtures, expected outputs, limits, timing rules and gates are byte-identical to v2. The changed-file list is exact.

STATUS's blocked disposition remains accurate. Before any bounded execution, root must release capacity after frozen work reaches a terminal state and retain the exclusive lease. Complete both-view public reference profiling/parity first; pooled Mac work was censored and does not satisfy that gate. Qualify the dedicated 4-GiB cgroup/controllers and finite descendant-cleanup behavior on Forge, pin the actual private runtime/tool bytes, then establish namespace/CUDA/whole-device telemetry compatibility. Static review does not establish availability of those facilities. The Mac compute hold remains in force.

No authored package was imported, parsed/compiled or executed by this review; no setup, GPU command, live cleanup, private evaluation access, build, test, commit or checkout edit occurred. Only short stdlib metadata/hash/source reads and this lane report write ran through SSH.
