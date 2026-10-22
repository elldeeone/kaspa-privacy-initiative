> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Compute lane v3: immutable process identity correction

**BLOCKED pending the narrow independent delta review and future Forge qualification.** V3 fixes the sole required new source finding in the final v2 execution review. It does not extend the GPU/runtime platform or change the experiment, numerical predicates, oracle, timing definitions, speed gates or resource limits.

Directory: /home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/revisions/v3. V1 and v2 remain preserved. V2 raw manifest is 7fdac38ef8ef02fa339c86b72edd5bb73abd973e71546922e27fd440eac63052.

## Final reviews read

- /home/luke/projects/kpi-orchestration/2026-10-22/evidence-lineage/GPU-PACKAGE-V2-DELTA-REVIEW.md, SHA-256 59223f2b26828c6931eace2250e1f6edca6f4b14aba006509e2c3f65c424fb1a. Its only required new source correction is PID identity replacement in guards.py:124–141.
- /home/luke/projects/kpi-orchestration/2026-10-22/statistical-review/GPU-BENCHMARK-V2-DELTA-REVIEW.md, SHA-256 7b80ed371f842b65496bf32af4f6296a856c81e9901903c9990d003e88e557d2. Bounded static acceptance of v2 timing/equivalence; no correction requested in that scope.

Neither review grants execution or CUDA readiness.

## Narrow source change

guards.py now captures the original wrapper PID/start identity once, immediately after Popen and before any poll/reap. A missing initial identity stays missing. refresh() starts from matching saved identities, never from an unconditional numeric root PID. A replacement root is excluded from both direct-child adoption and descendant discovery. Previously recorded descendant identities are never overwritten; new identities are added with setdefault only after discovery checks. Known surviving descendants remain trackable after the wrapper vanishes.

The existing pidfd-open/current-start comparison before signaling remains. Cleanup additionally requires the wrapper to have actually exited before reporting completion, so missing metadata cannot falsely certify a still-running wrapper gone. It remains bounded and still depends on the dedicated cgroup for whole-subtree enforcement.

Other source changes are mechanical version isolation only: the dedicated cgroup name becomes kpi-gpu-benchmark-v3, SETUP.sh points at this revision, and the benchmark's descriptive version/status label is V3. No observer, adapter, worker, setup/runtime algorithm, numerical threshold or comparison changed. BENCHMARK.md retains the same fixed workload, two CPU controls, complete-output oracle, 20% cold AND warm gates in both views, 4 GiB worker memory boundary and finite time/VRAM stops.

## Tiny fully mocked Mac regression

Luke's explicit Mac exception authorized this one self-contained check. tests/pid_identity_mock_test.py parses the immutable source text and AST-extracts only the four TrackedProcess method definitions. It does not import guards.py or execute its module body. Every process, procfs, pidfd, signal, wait, clock and pre-exec endpoint used by the subject methods is replaced by a fake. The pre-exec function is never invoked. No real cleanup, signal, child process, cgroup, namespace, numerical dependency or GPU operation is reachable inside the test.

All eight v3 cases passed:
1. Foreign replacement of the root PID is ignored, with its children.
2. A replacement root cannot enter through the controller's direct-child adoption path.
3. A reused descendant PID cannot replace its saved identity or admit its children.
4. Known surviving descendants remain discoverable after root exit.
5. New adopted children are handled while preexisting unrelated children stay excluded.
6. A missing initial root identity is not acquired from a later process.
7. Missing metadata cannot certify a still-running wrapper cleaned.
8. PID reuse between pidfd open and the subsequent identity check is not signaled.

The same mocked tests against unchanged v2 reproduced the reviewed root/descendant replacement defects. Two existing safe-path tests passed in that negative control. The test result is therefore a regression check of actual extracted methods, not a mirror of the corrected algorithm.

Observed budget: /usr/bin/time reported **0.22 s real, 17,022,976 bytes maximum RSS (16.2 MiB), zero swaps and zero signals received**. The test's own timed body was 0.0091 s. The external timer observes only the test's own resource usage. No other Mac benchmark or profile was started.

Pinned tested bytes:
- v3 guards.py: f44e516f24a74fd463873b7d94ccffaba5134f6486cc7e7e0faedcfc223c0f19
- unchanged v2 guards.py negative control: 58c7845862842479825023497bb2cafc33aac41466845cc69056881cdf424acb
- test: 0843aa6e85111c8fe9732559fb839097a18b23eedb58745c66d77d73fa77bc23

Raw receipts are mock-validation/mock-result.json and mock-validation/mock-resource.txt. Exact test invocation on the Mac was:

```sh
cd mac-artifact:work/mac-validation/compute-plan/v3-mock
/usr/bin/time -l /usr/bin/python3 -I -S -B pid_identity_mock_test.py v3-guards.py v2-guards.py > mock-result.json 2> mock-resource.txt
```

Only those tiny guard-source/test copies and receipts were staged locally. All project authoring and provenance inspection stayed on Forge. No authored code was imported, compiled or executed on Forge while the frozen run remained active.

## Remaining gates and review request

Please inspect only the guards.py identity/cleanup delta, the mock's isolation/coverage, and the mechanical revision paths. The v2 timing/equivalence acceptance is inherited unchanged; all inherited source/fixtures/expected outputs retain their pins.

**A mock pass is not Linux cleanup qualification.** Before any full screen, parent must still confirm the frozen evaluation's terminal completion, hold exclusive Forge capacity, authorize/provision the dedicated empty 4 GiB cgroup, qualify private runtime/tool bytes, and run the real bounded CPU namespace/control/forked-child cleanup sequence from BENCHMARK.md. Require matching process identities, successful cleanup and an empty cgroup. CUDA visibility and performance remain unqualified.

The complete both-view reference gate also remains unresolved: Mac C+D parity/hotspot passed, while pooled was censored by its swap-pressure guard. No additional Mac reference/array/GPU work is authorized by this report. No held-out result is changed, no package installed, no cgroup created, and no GPU operation, commit, push or external post occurred.
