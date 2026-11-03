> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# KPI evidence-lineage decision register

Read-only source review on Forge, 22 October 2026, 18:24 Australia/Sydney. Source checkout: `/home/luke/projects/kaspa-privacy-shared-pool`, HEAD `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. No tests, builds, runtime changes, private evaluation reads, commits or broadcasts were performed. Only this lane's report files were written.

**Scheduling decision:** retain the direct-L1 candidate and its payment/change/exit mechanisms; keep the rejected cashout policies stopped. Complete the existing price-baseline experiment before selecting another mitigation. Nothing in the reviewed evidence qualifies useful privacy. The companion [decision-register.tsv](decision-register.tsv) contains 15 discrete decisions, exact experiment/version identities, evidence classes, surviving claims, rejected claims and reopening conditions.

## What the evidence actually carries forward

- **Direct-L1 is a demonstrated research path.** H1 completed four TN10 transactions without an operator withdrawal signature, sponsor input or vProgs runtime. H6 preserved an exit proof through 100 payments; H13 extended mechanics to two inputs, payment/change and partial withdrawal. This establishes those bounded native sequences, not that every intended requirement is possible without a runtime. [E01, E06]
- **Fresh normal proofs and private saved fallbacks remain useful.** Waiting cannot enlarge an old proof's historical membership set. Fresh proofs improved withdrawal inference in the tested fixtures, but H16 still failed on two additional early payment links. Saved proof bytes surviving is exit evidence, not anonymity evidence. [E03–E04]
- **Equal net credits solved a specific funding-label symmetry problem.** H12's 0/704 unique deposit reconstructions depended on all deposits preceding spending; all four live funding sources shared one allocator cluster. It does not establish four independent anonymous people or justify compulsory deposit normalization. [E05]
- **Partial payout/change works; the tested cashout policies do not qualify.** H17 improved links but failed delay; H18 passed costs/delay but produced zero privacy improvement. The later working-balance policy helped overlapping independent demand, failed sparse continuation, and worsened receipt-correlated amount guesses. These are different experiments, not contradictions or a general impossibility result. [E07–E08, E13]
- **Persistent balances remain a hypothesis.** Early prompt cashout exposed 99/99 amounts while persistent balances resisted the three tested guesses much better. The subsequent 16-history arithmetic screen found no certified breach but explicitly had `qualification_pass=false`. A later genuine-native history produced 12/36 amount hits versus prior 7/36 after the next withdrawal. Do not pool these unlike workloads into a privacy rate. [E09–E11]
- **The sparse diagnosis changes the explanation, not the score.** Eight of eleven successful guesses used unrelated supports, three touched ancestry without closed flow, and none of 1,074 constructions matched the real payment inputs. All eleven remain hits. Wrong explanations neither prove zero transaction information nor select a structure/runtime rewrite. [E14]

## Material lineage traps

1. **Historical next-step text is stale.** `TWO-INPUT-RECONSTRUCTION.md:41–46` says the wallet-policy follow-up has not run; H15 subsequently completed (`WALLET-POLICY-PRIVACY.md:3–20`). H15's proposed participant follow-up at `:50–57` is H16, already completed and failed (`PARTICIPANT-PRIVACY.md:3–12`); H16's proposed common payouts at `:163–173` became H17/H18. These old paragraphs must not generate duplicate assignments. Current journal/ADRs govern scheduling.
2. **Version-specific recovery evidence cannot be combined into a current live claim.** H7 restored older compact wallets on another host/RPC without saved proofs (`RECOVERY.md:11–28`). H13 v6 TN10 used precomputed capabilities, known funding sources and one host/RPC (`TWO-INPUT-TN10.md:147–169`). M2 later demonstrated v6 original-backup recovery, but with synthetic ancestry and same-host isolation (`WALLET-LIFECYCLE.md:38–66`). None alone proves current v6 independent live recovery after loss of the original services. [E02]
3. **Older observer rules are not current wallet rules.** H15/H16's single-input exit restriction does not match the later wallet (`POPULATION-PRIVACY.md:36–39`). Reusing the old privacy percentages for current two-input EXIT would promote evidence beyond the tested policy. The later ownership-aware model exists; do not rebuild the ownerless model as if new. [E04, E09]
4. **Component timing is not payment latency.** H13 warm proving was 20–22 seconds, but M2's measured preparation plus proving was about 59–60 seconds before transport/replay, with about 203–206 seconds cold parameter loading (`WALLET-LIFECYCLE.md:102–112`). Use the latter boundary when planning current wallet work; neither is a qualified p95.
5. **Current files are ahead of the commit.** The plan's header still names evidence baseline `c3afb1b`, whereas its current next action includes ADR-0033. The price specification/ADR are untracked and current journal/plan are modified atop `9e0dca5`. HEAD alone does not identify the running frozen experiment. E15 records the read-time spec hash; the engineer's frozen manifest must supply the execution identity.

The canonical current documents explicitly retain these limitations. I found no basis to upgrade a completed mechanism screen into a privacy pass; the material documentation inconsistency is stale historical next-step wording, not conflicting measured results.

## Do not repeat without a new reason

- H14 → H15 → H16 → H17 follow-ups: already executed. A new observer/workload question must identify the difference.
- Frozen-proof waiting or extra unrelated traffic as a cure for the fixed old-anchor singleton. Reopen only with a different authorization/observable mechanism.
- H18's 2-tKAS, 5–15-minute tail schedule or its native continuation. Reopen only with independently justified behavior and a new frozen comparison, not timer/seed tuning.
- Native integration of the rejected working-balance policy. Sparse failure is decisive under its own gate; accounting success cannot override it.
- Whole-history solver runs with only more workers/time. Preserve three no-prediction formulations and the Z3 OOM; require a demonstrated algorithmic/scaling improvement on permitted development controls before spending a large new budget (`POPULATION-PRIVACY.md:15–26,217–232`).
- Recounting sparse supports or rerunning the current baseline as another independent experiment. The diagnosis already has independent backward-flow verification ([docs/RESEARCH-JOURNAL.md:132–153](../../../../docs/RESEARCH-JOURNAL.md)); current active evaluation has one owner and a fixed barrier.

## Three genuinely unresolved decisions

1. **What does the current baseline justify studying next?** Consume its sealed result only after completion and independent recount. Material public advantage directs review to observable amount/timing structure; participant-only advantage directs review to the knowledge model; a small/unresolved result requires another independently motivated test. No branch automatically authorizes a mitigation, privacy claim or runtime switch. [E15; `PRICE-LEAKAGE-SPEC.md:170–175`]
2. **What user/workload promise is actually intended?** The current known-price distribution is about 21.10% guessable before transactions, above the adopted 20% absolute cap. Independent and half-receipt cash needs are modeled, not empirically established. Keep old targets/results intact; an explicit requirements decision and supported behavior model are prerequisites to changing the qualification workload. [[docs/adr/0032-sparse-diagnosis-and-privacy-evaluation.md:53–60](../../../../docs/adr/0032-sparse-diagnosis-and-privacy-evaluation.md); `WORKING-BALANCE-SPARSE-DIAGNOSIS.md:114–124`]
3. **When can current v6 advance beyond the offline milestone?** The early privacy gate remains ahead of dedicated milestone 3. Current-version independent recovery, availability/fee stress, cryptographic review and practical cost remain unqualified. Define the smallest missing evidence against the existing milestones; do not rebuild H7, H13 or M2 under an ambiguous 'recovery works' banner. [`SHARED-POOL-PLAN.md:25–55,123–138`; E02]

## Source identity and limits

All source references are repository-relative `path:line` ranges, inspected on Forge. Committed reports are anchored by the register's record commits; record commit and execution/freeze identity are deliberately distinguished. The current uncommitted file hashes at 2026-10-22T07:24:30Z were:

| File | SHA-256 |
| --- | --- |
| [docs/RESEARCH-JOURNAL.md](../../../../docs/RESEARCH-JOURNAL.md) | `dee443b4af67c2daddcc2c04f61b6fab6cb15714ccaa8e14f9f9e87c51071d2d` |
| [docs/SHARED-POOL-PLAN.md](../../../../docs/SHARED-POOL-PLAN.md) | `02816f3b58bf4842d8dd639fac58073ce521c62efe8a76a6e20f17a2070567a7` |
| `docs/adr/0033-price-baseline-evaluation.md` | `44e693c6bd07ce08906c89e3ed2f325f58d09c29453de98991ca93892f9cb302` |
| `poc/shared-pool/PRICE-LEAKAGE-SPEC.md` | `104bea66d0798c523de6c5d283861d4d4867632c0e30189f8179c1763bcfa885` |

This is documentary evidence lineage, not a fresh artifact replay, cryptographic audit or evaluation of the statistical formulae. Public reports' counts were compared for scope and consistency; hidden truth, active run data and seed material were not inspected. The active run's completion/status remains the engineer/orchestrator's responsibility. No external-source refresh was performed, so this report makes no new claim about current upstream capabilities.
