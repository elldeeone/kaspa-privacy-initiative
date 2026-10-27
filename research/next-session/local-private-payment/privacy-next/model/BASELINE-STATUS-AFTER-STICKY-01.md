# Frozen baseline: finite-model result 01

**One original approved run completed. The expected active-retry failure was
retained. This was no cryptographic or native privacy test.** No existing model
source, input, expectation or output was retuned after execution.

All 15 observer cells met their frozen combinatorial expectations. The retained
9,792 complete joint NF-owner/output-partition assignments reproduce all 15
stored enumeration digests. The ideal accounting/consent arm produced 29
expected rejections and 12 other control/accounting records, including explicit
private-batch liveness loss and public-data availability failure.

| O-active view | A NF candidates | A complete output-pair candidates |
| --- | ---: | ---: |
| Single hidden-partition ABC | 2 | 6 |
| Same-cohort/same-tuple retry | 2 | 6 |
| C Exit wins after ABC egress; known ADE retry | **1** | **1** |
| Reorg then C Exit and known ADE retry | **1** | **1** |

Global changed-cohort assignment counts remain 12 because D/E remain ambiguous;
that aggregate count does not preserve A's privacy. Public pair identifiers,
ordinary per-intent framing and the individual-Delta equality oracle each
uniquely expose the NF/output partition in their frozen negative controls.
Two-server reconstruction is outside the assumed one-corrupt-server threshold
and likewise exposes the map.

**Observer precision:** the baseline's `O-ledger` label means a hypothetical
**public-egress/mempool observer**, receiving every released candidate batch,
including unaccepted or aborted ABC. It is not guaranteed to be a
confirmed-chain-only observer. Its cross-attempt NF/output-pair intersection
requires those candidate disclosures. If ABC was never observable to a
confirmed-chain-only party, this model supplies no corresponding result for
that party. `O-active` additionally sees named owner cohorts, submission
sessions and C's own input/output material. No real network observation occurred.

In the reorg arm, observer knowledge of the previously released/apparently
accepted ABC is retained independently from current accepted-state rollback.
Its hypothetical public output data remains in the observation history; the
accounting arm separately rejects authority from orphaned outputs and stale
successors. This is ideal fork reconciliation, not an executed chain reorg.

Consent, proof validity, commitment/share opacity, backup derivation, decryption,
accepted-state authenticity and ciphertext/tree recovery are explicit oracles.
The entire fictional fixture is public; the enumerator receives only its
stipulated observer projection. These results establish finite information-flow
properties of that projection, not real cryptographic indistinguishability,
actual seed restoration, native settlement, paid fees or production safety.
The frozen 21-KAS 2% all-in fee FAIL remains unchanged.

Retained immutable evidence:

| File | SHA256 |
| --- | --- |
| [Source](run_model.py) | `fe89cee8847733f960407c3edf8e0bc64ff0f27cc7fd5d49e9fa8d7f5cb43a18` |
| [Inputs](INPUTS-01.json) | `503d77c6250ad898e1aea5a38d019d2350d03e6b32205a292068d318180e3fc5` |
| [Freeze](MODEL-FREEZE-01.md) | `cb42ca26f45a1925b0ff58708e40fff3c10d6ebdc65030465df12fdfd26452cc` |
| [Source manifest](SOURCE-MANIFEST-01.json) | `4d8e95975600dd91494cec901669cfccba61e0389f4e27a585fe2e77c2bcc3d6` |
| [Root pre-execution review](ROOT-BASELINE-EXECUTION-REVIEW-01.json) | `62f2f568a1f97a8385a4cd9f6550e7535d2a38e4eb7e49416ecc47faa6b05a27` |
| [Result](run-01/RESULT.json) | `0584ade39771b94c2599bb51af689f5ef99c3e4b1fc8f86f87828bab30507b6f` |
| [Every joint assignment](run-01/ENUMERATED-ASSIGNMENTS.json) | `4db2d4264105ef15b1c2131919480c0e543df070c87039852748177705ceb6b0` |
| [Execution record](run-01/RUN-RECORD.json) | `f6b4cdef7e73a7745cb7271147c03dd980c947134e07c240728e7ffa71574b71` |

The separately versioned sticky OWNER-basket control is prospective and remains
unexecuted pending its own Root source review. It does not change this baseline
or convert its expected failure into a pass.

Independent [static review](../../review/PRIVACY-NEXT-MODEL-STATIC-REVIEW-01.md),
SHA256 `d4aeeded7fd162d9a1ff63dcc701a132501e1d00ffbeabfc2b7dbb45469876f3`,
found no source/enumeration blocker within the stipulated ideal view and
independently derived the frozen counts without running the model. Root
accepted that review. Counts are consistency counts, not probabilities or
entropy; different owner universes are not directly comparable privacy scores.

Its control limits remain explicit: most tuple, recipient, fee, anchor and
range mutations are rejected first by the exact-approved-intent comparison.
They exercise the ideal consent oracle and do not independently isolate each
downstream predicate or validate a circuit. `reject_case` compares a snapshot
of `initial` even when an operation targets another state. The reviewed code
clones before mutation and no current mutation bug was found, but those
assertions alone are not a comprehensive atomicity proof for every target.
No source change, rerun or adjusted expectation was made to conceal these
coverage limits.

Subsequently, the separately versioned sticky OWNER-basket control received
its own Root pre-execution release and ran exactly once. See its
[separate outcome](sticky-owner-basket-01/OUTCOME-01.md). This updates the earlier
freeze-time execution status only; it changes no baseline source, expectation,
failure or output. Conditional remaining-honest-owner multiplicity and the
sticky control's explicit departure/history failures remain separate findings.
