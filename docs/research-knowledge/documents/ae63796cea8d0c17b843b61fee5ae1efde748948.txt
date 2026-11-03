# GPU v3 runtime result — 2026-10-22

**BLOCKED_RUNTIME_ATTESTATION. No GPU acceleration result was produced.**

The authorized Forge attempt passed small actual Linux CPU-throttle, memory-OOM, PID-limit and owned-descendant cleanup probes. Its private wheel installation then failed installed-runtime attestation because the frozen verifier rejects an existing packaged standard-library symlink outside /usr/lib/python3.14. Parent stopped the release. No retry, modified source, relaxed predicate or increased limit was used.

The source pin, exact unit identities, provenance, timestamps, resource receipts and terminal cleanup are in [RUNTIME-QUALIFICATION.md](RUNTIME-QUALIFICATION.md). Raw evidence is preserved at /home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/executions/20261022T090300Z. Frozen v3 manifest SHA-256: a9765efdc8bbf427cb896a3c34ec58626be75b180611d0e26447d481ec5bf7dc.

| Required gate | This attempt |
|---|---|
| Kernel CPU/memory/PID enforcement and owned Linux descendant cleanup | PASS for documented tighter disposable probes; actual worker settings verified unchanged. |
| Exact installed runtime identity | BLOCKED; runtime-lock.json was not produced. |
| Bubblewrap CPU controls and forced worker-descendant cleanup | NOT RUN. |
| Both-view reference profiling: eligible share >=25%, calls >=100,000 | NOT RUN. |
| Complete reference prediction parity: 64 targets, 13 C+D / 26 pooled variants | NOT RUN. |
| Packed CPU parity and cold/warm timings | NOT RUN. |
| CUDA context, kernel compilation and GPU parity | NOT RUN. |
| GPU >=20% cold and warm end-to-end gain against both CPU controls in both views | NOT EVALUABLE. |

No timings from dependency installation or the kernel probes are observer performance measurements. There are no predictions from this attempt, and no basis to claim GPU speedup, failure of the eligibility idea, or readiness for adoption. Earlier Mac C+D profiling is separate development evidence and does not fill these missing both-view Forge gates.

Setup took 43.356 seconds wall / 19.167558 seconds CPU and reached 4 GiB peak charged memory inside its 4 GiB unit. It ended with the explicit attestation exception, status 1. All helpers cleaned up. The qualifier and setup units are terminal with MainPID=0 and ControlPID=0; no tracked process identities remain. The owned probe and unused worker cgroups were removed after recording their empty state. At 20:09:57 AEDT the GPU was 1 MiB / 0% with no compute owners. The reservation was released. No benchmark CUDA context was created.

## Specific blocker and proposed next decision

The first rejected link is /usr/lib/python3.14/sitecustomize.py -> /etc/python3.14/sitecustomize.py. The target is a root-owned, mode-0644, 155-byte configuration file from libpython3.14-minimal 3.14.4-1ubuntu0.2; its current bytes match the local dpkg conffile record. The second external standard-library link is the packaged libpython3.14.so link. The frozen verifier's tree() rejects either external target regardless of content. This is a mismatch between its accepted filesystem layout and Forge's actual packaged layout, not evidence that the hook is malicious.

The bounded source read shows an Apport exception-handler installer. Its imported module was not audited. The actual benchmark design already uses -I -S -B; -S suppresses ordinary site initialization and sitecustomize startup. Earlier metadata helpers used normal Python startup, so their execution cannot be claimed to exclude the hook; this limitation is recorded in the qualification receipt. [Python site documentation](https://docs.python.org/3.14/library/site.html)

A separately approved, self-contained CPython 3.14 runtime could plausibly satisfy the existing *containment principle*: pin its archive and interpreter identity, keep its standard library and linked support files inside the approved runtime root, and reject any unapproved external target. Astral's uv documents its CPython distributions as coming from python-build-standalone and being self-contained; an exact candidate archive and its link graph have **not** been selected or verified here. This is a proposal, not a ready installation command. [uv CPython distribution documentation](https://docs.astral.sh/uv/concepts/python-versions/#cpython-distributions)

It cannot satisfy the current frozen v3 implementation unchanged. V3 explicitly selects /usr/bin/python3.14, attests /usr/lib/python3.14 and permits that particular interpreter target for its venv. A new source revision would have to bind those paths to one explicitly approved private runtime, verify its full byte identity, and map only that runtime into the worker namespace. Merely making another venv or using --copies does not establish an independent standard library: a venv is built on a base Python installation. [Python venv documentation](https://docs.python.org/3.14/library/venv.html)

Such a proposal must preserve the host hook and its normal consumers. The isolated benchmark would continue the already specified startup policy, with loss of host Apport handling inside that process made explicit, rather than claiming arbitrary hooks are safe to bypass. No host Python/hook edit, global Python download, shared-cache mutation, or new execution is proposed as an implicit continuation of this stopped release.

If that distinct runtime source is approved and pinned, a fresh bounded attempt must requalify runtime/namespace cleanup, then run the unchanged full reference/parity/profile sequence before any CUDA screen. Preserve exact integer sums, eligibility, ordering, deterministic ties, deduplication, Fraction semantics, all variants and both controls. Keep the original >=25%/100,000-call hotspot gates and >=20% cold AND warm end-to-end gains against BOTH CPU controls in BOTH views. A successful package or kernel alone remains insufficient for adoption.

The failed v3 environment should remain evidence. This result does not authorize another installation, execution window, performance-threshold change or GPU-prover work.
