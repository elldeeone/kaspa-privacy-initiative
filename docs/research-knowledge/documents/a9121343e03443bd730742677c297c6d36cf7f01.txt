# Independent review of the bounded next experiments

Read-only source/design review, 2026-10-22. The prior publication check is closed;
this note concerns ADR-0038. No build, proving, native execution, owner workflow,
ledger replay or default change was performed by this reviewer.

The useful next steps are the existing B2 performance comparison and the
ordinary-only operational-budget checker. No correctness blocker was found in
the written architecture decision or re-derived ordinary source bound. This
does not pre-approve an unreviewed runtime driver or qualify the payment system.

1. **Ordinary1600 source-bound gate passes.** For S7 native source
   `7df243d9b94224e464cd2b49f60cbcce24b0ae2db649c89d7241fd3cdde689cb`,
   the ordinary branch retains 277 SHA calls, 528 Merkle CATs plus 17 other wide
   leaf CATs, and 29,969 units of wide-selector excess. The complete conservative
   bound is 15,857,502 units, below 16,009,999 by 152,497. I checked the pinned
   native engine's skipped-branch handling: inactive paired instructions do not
   execute or charge newly created bytes; conditional controls have no hidden
   proof/hash charge. Charging 32 units for every byte of the entire 24,576-byte
   union also covers the added ordinary dispatcher. This covers successful,
   fixed-shape ordinary reserve input0; ADMIT input1 has its own meter. Fresh
   DRAIN execution remains absent, and paired execution is outside this bound.
2. **Keep the factory seam narrow.** Shared `native::BUDGET` feeds both
   `ordinary_settle` and `paired_settle`. The proposed checker must mutate only
   ordinary input0's typed compute commitment, leaving the shared constant,
   paired1700, redeem, profile, proofs, fee authorizations and outputs unchanged.
   Native v1 ID and SIG_HASH_ALL omit that commitment; the full hash includes it.
   Thus unchanged signatures are expected, while Full validation and mass caps
   remain necessary. The written control plan preserves these obligations.
   Independent pre-run arithmetic predicts SPEND/bootstrap compute/mining mass
   200,511→190,511 and ADMIT 201,631→191,631. Their actual 40M fee passes the
   rate200 quote, but still fails rate500. The retained1700 failures stay valid.
3. **Reject misleading control layers.** Each native mutation needs its exact
   predeclared Full and reserve-engine error. A changed ciphertext with its hash
   left stale may fail an equality guard; updating that hash changes the proved
   authorization and should reach proof verification. These are different tests.
   Synthetic ADMIT bodies changing signed fields need a legitimate public test
   signature, or must remain source-only. A host/factory refusal, stale funding
   signature or resource abort cannot substitute for a native semantic result.
4. **Performance changes must preserve the statement.** Reuse the exact selected
   guest/input/image/J336/completed claim and pinned SDK/control profile. A fresh
   receipt must independently verify with development mode disabled and no
   assumptions; changed image/J/claim, fake receipt and corrupt seal must reject.
   Segmentation/backend settings may alter the proof artifact, not the accepted
   statement or security parameters. Account for every GPU worker: an actor
   pipeline's two workers cannot each be compared against the entire GPU's
   available memory. Preserve failed/slower attempts, cleanup identities and
   aggregate memory samples. Separate execution, proving, compression and
   verification; disclose cache state and concurrent host work. A single GPU
   run is neither p95 evidence nor the CPU-only wallet/end-to-end target.

The architecture note correctly counts B payments rather than 2B outputs and
preserves the genuine pair's actual 80M fee. Native mass savings do not reprice
those authorizations. Repeating the genuine pair cannot be a larger successful
batch: duplicate/current-spent NFs must reject. A larger positive requires
distinct valid statements and sequential authenticated NF/CM/history updates.
Neither aggregation nor faster proving repairs the retained prior-information
floor or the named 60M/rate500 singleton-exit contradiction. The conditional
aggregate framing arithmetic independently checks: P=92+498B,
pair-input=92+1377B and state-input=753+5233B reproduce B2's 1088/2846/11219
bytes. These are generalization formulas, not acceptance by the fixed B2 code.
The planned per-B current NF/CM/history, multiplicity, bijection, capacity and
checked reserve-fee obligations are explicit. No larger proof is released.

The full-circuit boundary source was also inspected. MAX/MAX+1, floor±1 and
conservation cases rebuild commitments, NFs and membership paths; the high-bit
position case uses a consistent low16 path and full-position NF. Count65536 and
u32MAX positives are explicitly relation-only. Padding controls target inactive
canonical fields. No expectation blocker was found; actual results and synthesis
shape errors must remain distinct.

Reviewed inputs: [ADR-0038](../../docs/adr/0038-bounded-cost-and-proving-qualification.md),
[architecture decision](ARCHITECTURE-DECISION-REVIEW.md),
[ordinary bound](ordinary-budget/SOURCE-BOUND.md),
[ordinary control plan](ordinary-budget/CONTROL-PLAN.md), and
[boundary plan](BOUNDARY-TEST-PLAN.md).

The [GPU design](AGGREGATE-COST-DESIGN.md), initially
`23b98e6aea1911acb18086d438a7ad5e7ef74f6422547f033e2774074b8783c7`,
and initial thin client
`a602b8463fd96684ff8ea1c8075a4001b97414ad3bb1d4dd744ce79c89a7eede`
were inspected. The client preserves exact program/input/image/J/claim, explicit
backend and worker hash, segmentation18, no development mode, immutable
candidate-before-verification and the original SDK/decoded JOIN checks.
Independent receipt verification by the historical selected host remains required.
The conditional actor admission rule sums the measured primary and recursion
peaks plus 512MiB before fitting within 6656MiB; it is a conservative admission
rule, not a hard CUDA quota. IPC18 must finish and independently verify first.

Two concrete reporting corrections were sent before execution. A temporary
`default_prover().prove_with_opts(...)` drops the actor prover before the next
statement; its SDK destructor waits for shutdown, so the initial
`proof_response_seconds` includes cleanup. Bind the prover and timestamp its
response before explicit drop, recording startup/shutdown separately. Also,
actor SDK statistics hardcode paging/reserved cycles to zero; mark these
unavailable instead of interpreting them as reduced work.

Both corrections were independently rechecked in final client
`a316fc59e1c625749e1eac8369519cfb42f82e66a3f59083ac895eba659f0deb`:
startup, API response, explicit backend cleanup and combined elapsed time are
separate, and actor paging/reserved cycles are labeled unavailable. Lock remains
`e885cfbb2fd894a65a6a7ddd6a54278586a5ed41b46612dffd3b7b62e96062d5`;
corrected design is
`253d34a2e007d765bcaf9107f072021b60b8c059d9b6bccfaefb6c3c86858783`.
The source gate passes for the additive cached build.

Final IPC18 runtime-source checks also passed: client
`84e3b0e2773e25e1a3fe528c42f69729d0b2471a177a9a82a8ef778a6e4e93cb`,
runner `407f5210fcd2c337f7f4b438f6e90361b35d4ba50caa61f4725c4fe185f115f3`,
freeze `f7f4fe36350f2867c8f3d1a74b5956618c9e4c06cdfa55bb3400db068d5810b9`.
All 84 source/archive/tool/client/input/program/verifier identity checks matched.
Read-only mount ordering, local-network preflight, fresh outputs, generous
resource caps and whole-cgroup cleanup were inspected. A third concrete issue
was corrected: failed GPU queries previously looked like zero allocation.
Failed/malformed/missing samples now remain explicit; reliable actor admission
requires complete attributable measurements. New GPU PIDs are accepted only
after exact cgroup membership, not executable-name inference. The summed VRAM
guard overrides an otherwise successful exit. This ACK permits the selected
IPC18 diagnostic under root's release; actor18 still requires its later receipt,
memory and reviewer/root gate. No performance outcome is asserted here.

The closed ordinary1600 results were then independently recounted without a
native rerun. All 393 packet members and 579 source/runtime/provenance identity
checks matched. Four genuine ordinary cases plus 17 exact Full/reserve
negatives, unchanged paired1700, and 28 synthetic contexts plus 28 exact
negatives are retained. One excessive-budget case passes Full/reserve and fails
the separately labeled mass-policy screen; it is not a Full rejection. All 32
old/candidate bodies differ only in input0's typed budget; exact 40M fees,
190,511/191,631 masses and rate200 pass/rate500 failure match the pre-run
prediction. Maximum synthetic reserve use is 14,970,643 units. The helper now
checks the full produced prefix UTXO tuple and derives/asserts its 17-control
count, correcting the earlier txid-only link and hardcoded-report weaknesses.

The ordinary sampler matched the outer bwrap process before the checker; its
empty mount rows do not attest the checker's runtime namespace. The source
command uses read-only input/binary and disjoint output, and before/after hashes
match, but this observation gap remains qualified. No repeat was requested.
Independent recount: `ordinary1600-independent-results.json`, SHA256
`adec8123729e96f751231e11e6fc14459348223837518fcec90ea8bfc44e3a50`,
retained in the separate reviewer worktree. Factory/paired defaults, old failures,
note floor, owner/DRAIN gaps, accepted-lineage and privacy limitations remain.

The original seven-group state source
`bbe1ce75f6a198a6d126744ab3fb0e9b5016c6219d75a95cb49ad326d9912487`
and append-only high-NF source
`ab5006cfaf33211c0c82a85737a33d7359ed790141c4d620ea985a7c0ce12e81`
were independently reviewed. The full-array oracle matches the exact published
n5 input and derives n7/n65531 conditional histories. Stale second NF/CM/history
witnesses are authenticated against the original roots, targeting precise
sequential root/occupied failures rather than arbitrary corruption. The full
17th-bit NF fixture uses m131054→131058, an actual predecessor above65535 and
an occupied low16 append alias. Its Root/Occupied expectations and the wider
count/LE comparator oracles are consistent. This source review neither reruns
those tests nor promotes conditional trees to accepted ancestry/backing.

IPC18 subsequently produced the genuine receipt
`3ea11d808b1dac69a1aa1ba28543ce4874519270db977eb203125f557bdad83b`.
I independently ran the original immutable f00ce354 verifier under the existing
one-CPU/2GiB verifier-only driver. Exact image/J336/claim/JOIN/P checks passed,
development mode was disabled, assumptions were empty, inherited crypto/control
negatives passed, and all eight field-specific outer-J mutations failed with
independently derived exact claim-digest errors. Independent report SHA256:
`e239b556c0697b115e073c9e50a07a666cb4070a0b47cee96220aabd3c2a5635`.
Final telemetry/log hashes matched; all four recorded PID/start identities were
independently absent and the unit was inactive with no cgroup/MainPID. Actual
startup+API response was505.118s: above the60s single-run diagnostic, without a
p95 or end-to-end qualification claim.

The original actor admission condition **failed**: disjoint primary/recursion
samples establish3828+2926+512=7266MiB>6656MiB. Later observations cannot lower
those already measured maxima. That failure is retained independently and no
actor run is approved under that profile. A separately proposed7680MiB
operational envelope must preserve the old failure and state that sampled phase
peaks do not prove simultaneous allocation fit. Official source shows two GPU
worker processes and serial task queues, with lazy HALs and no CUDA proof work
in the Execute-only parent; per-instance CUDA contexts and process-persistent
sppark NTT caches prevent an assertion of exactly two contexts or a static VRAM
upper bound. A new monitored profile needs its own source/runner identity gate.

Root then separately selected `actor18-8gib-20261022-01`. Its SPEC and narrow
runner diff passed review: fixed actor18, fresh paths, unchanged client84e3,
archived compiled-source pins, original failed gate required, new7680 summed
guard, explicit missing-data limits, and failure on unexpected GPU parent,
executable or more than two GPU worker processes. Physical8192MiB was checked.
Runner `157d81c5c8198d0302145db4aa5bb5e97674ebb0c97de310c10e0e66128e8fec`
and freeze `b30dfa3f5dec184c0d6f80cdbd2ded47d76c89aa6b9079a1a8f0dac752562a00`
matched the reviewed artifacts. Independent pre-execution record SHA256:
`e553879c20c3a058217765aee725b9acf9a2cd23e6ca0185797bdef9f2d0c0fd`.
This ACK covers root's exactly-one new operational experiment; it does not
revise the original6656 result or establish a memory/performance outcome.

The closed boundary packet was independently rehashed and recounted: all207
members including its manifest, six selected checkout sources,30 frozen
outcomes,11 satisfied/17 unsatisfied complete systems and two partial shape
errors match. MAX/MAX+1 and one-sompi conservation results agree with integer
arithmetic. The original13,830-byte test file is an exact prefix of the new
18,451-byte file, adding4621bytes; the result remains seven-plus-one, without
rerunning the first seven groups. Independent report SHA256:
`9f7b9df3d602279aedbb2d6e164082c773d6e3e33ee118e69ad21866776125cc`.
The wrapper CPU/RSS observation gap and conditional-state scope remain explicit.

The actor experiment saved candidate receipt
`2891e246e4feff140528a28215562ac1bb512a206f3792b56a6277a89ef722cc`.
Independent frozen-host verification passed the same exact statement and all
inherited/field-specific controls. Verification report SHA256:
`b778128cce2670027e4cf888fffc3ea74e4997fd3dd3253e098a8febdb950a2d`.
The operational result is nevertheless **FAIL**, with incomplete memory
qualification and no final client API/Drop timing report. After the candidate
was saved, the frozen guard saw the known primary PID/start identity with
empty command line and unavailable executable during exit; it classified that
as unexpected topology and stopped the unit. This is a lifecycle-observation
race, not evidence of a third GPU worker. SDK shutdown warnings precede the
guard, so their cause cannot be attributed to the later stop.

Independent log/sample recount finds390 completed segments,390 lifts,389 joins,
one JobDone and2974 samples. The sampled matching peak is5532MiB; it does not
override the failed operational profile. Request-to-JobDone is448.232s from
logs, above60s, without substituting for the missing API/cleanup report. All six
recorded PID/start identities were independently absent, the unit was inactive
with PID0/empty cgroup, and the GPU compute list was empty. Cleanup/diagnosis
report SHA256:
`d68ffc128005174ac3ae98140a9f6aa548f78f3307c06194fa4aae5428688d9c`.
No repeat was performed or requested. The original6656 gate failure remains.

The compact pre-final-publication screen found no credential/private-wallet
material, escaping symlink, ELF or50MiB file among696 current candidate files.
Intentional PUBLIC/DO_NOT_FUND fixtures and source-only wallet names were
distinguished from private material. This screen precedes the final GPU packet
and is not an indexed-blob audit. The fee-frontier wording correctly limits the
adopted1%/2% cap to reference-rate100, labels200/500 percentage rows sensitivity
diagnostics, and still requires exits at every rate. No broader safety,
privacy, accepted-lineage, backing or owner-exit qualification follows.
