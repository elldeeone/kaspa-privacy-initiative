# Active coordinator abort/retry intersection: experiment record

**Status (2026-10-25): EXECUTED; bounded active privacy FAIL in an MPC wire
fixture.** The [public audit](ACTIVE-RETRY-EXECUTION-01.json) checks three real
phase-one MASCOT admissions and the count-only report. No financial or testnet
claim follows.

**Repository context:**
`research/shielded-kas-feasibility` in
`/home/luke/projects/kpi-intensive-2026-10-22/continuation`, based on committed
checkpoint `2e56d8a10fde5c998dde3bac3c7070c9d36f6827`. The sender-private
work was still in progress in the working tree when this record was written.
The executed trial is `active-retry-03`, with source and software pins frozen in
its `SELECTION.json` before owner truth was created. Earlier `-01` and `-02`
identities failed in launcher setup and are retained; neither is scored.

## Research question

Can a coordinator that knows who joined each round learn which input belongs to
an honest owner by aborting after stable nullifiers (NFs) become visible, then
observing another round with an overlapping but changed cohort? The target is
**input ownership** under an active coordinator. It is separate from passive
input mixing, input-to-output linkage, recipient identity, amount privacy,
financial soundness, and network anonymity.

ADR-0065 privately mixes NF/CV inputs in one MPC phase and Spend authorization
rows in a second phase. This removes direct owner-labelled readiness and proof
slots from public assembly. Phase one nevertheless opens the mixed NF set
before financial authorization or settlement. An aborted round leaves the note
unspent, so its NF can appear again. Fresh round aliases do not conceal cohort
membership from a coordinator that already knows the endpoints. These are
source/design facts. The executed wire diagnostic below tests the specified
active inference against owner-local truth.

## Declared observer and conditions

- The active observer is the implemented coordinator, which knows round
  membership and sees its actual role-visible admission transcript, including
  opened mixed inputs. A colluding participant may disclose its own NF. The
  trusted launcher or host administrator is outside this observer model.
- The illustrative comparison uses three contributors per round, with two
  honest owners in each. A and B participate in both rounds; C participates
  only in the first and D only in the second. B is the permitted colluder.
  The same unspent A and B claims retain their NFs across the two attempts.
- Exactly one real input is contributed per member in each compared attempt.
  The inference may use a repeated NF that was actually observed; it must not
  infer owner absence merely because a particular NF is absent. An owner can
  select a different claim on another attempt.
- CV blinding can change on retry. The proposed comparison therefore concerns
  stable NFs, not equality of CVs, output tuples, aliases, or sort positions.
  It applies only when the coordinator has the stated membership knowledge and
  the relevant NF sets actually become visible before settlement.

Under those conditions, the two observed NF sets and B's legitimately known
input can make A's repeated input uniquely attributable even though each
individual mixed round contains two honest owners. That was the **expected
source-level failure** before execution. The selected MPC run reports three
owner-verified unique matches for the changed cohort.

## Frozen method and observed controls

The frozen [experiment specification](../privacy/EXPERIMENT.md) calls for fresh
synthetic owners, fresh session aliases and sorting randomness, actual selected
phase-one MPC outputs, complete coordinator-visible transcripts, predictions
sealed before owner truth is checked, and aggregate-only scoring. It separates
wire-fixture evidence from genuine financial component evidence. A wire-fixture
result measures the admission transcript and inference only; it does not
establish payment authorization, reserve backing, native acceptance, or
financial privacy. No test KAS, real funds, or production participants are
needed for the proposed diagnostic.

The required comparison and boundaries are:

| Case | Observed result and limit |
| --- | --- |
| A+B+C then A+B+D, both aborted | Two opened NFs repeated; 3 of 3 unknown eligible owners had unique, owner-verified predictions. Active input-ownership privacy fails for this observer and fixture. |
| A+B+C again after the first abort | Three opened NFs repeated; 0 of 2 unknown eligible owners had unique predictions. |
| Fresh legitimately spent claim | The separate [genuine two-round component check](FRESH-CLAIM-COMPONENT-CHECK-01.json) has three checked input NFs per round and zero repeated NFs after round-one spending. This is a component control, not an active MPC retry or a general uniqueness proof. |
| Two known colluders | The fixed enumerator's synthetic control leaves one feasible assignment and identifies the remaining input. No second colluder was added to the scored MPC run. |
| Malformed, duplicate, substituted, stale or wrong-state material | 42 privacy and 35 admission unit controls passed for their tested cases. The wire fixture performs no financial authorization; wrong-state financial safety remains a separate gate. |

The inference rule must consider all ownership assignments consistent with
observed sets, known membership and legitimate colluder knowledge. It must
retain ambiguity where multiple assignments remain. Prediction selection must
precede truth access. Owner-local truth stays in isolated owner records; public
output may contain only aggregate eligible and matched counts. Missing
transcripts, unavailable truth, or an incomplete run mean **INCOMPLETE**, not a
privacy pass or an attack success.

The 128-world, eight-cell study in the same specification is the separate
passive/participant-artifact comparison. Its sample size and statistical
thresholds are **not** a measured result or a substitute for this
active diagnostic. The active failure remains an explicit negative cell even
if a passive comparison later reports no excess linkage.

## Evidence available now

1. [The public audit](ACTIVE-RETRY-EXECUTION-01.json) pins the selection, three
   completed admissions, 15 coordinator-visible artifacts, nine fresh aliases,
   two repeated opened NFs across the changed cohort and three across the same
   cohort. Each run aborted before authorization; all owned containers were
   removed. The count report is
   `/var/tmp/kpi-sender-private-lifecycle-01/public/active-retry-03/final/RESULT-CORRECTED.json`.
2. The observer sealed predictions before the `QUERY-CLOSED.json` barrier and
   four owner-local count leaves. The restricted aggregate reports changed
   cohort 3/3 owner-verified unique matches and same cohort 0/2. It exports no
   owner/NF map. The host-side public audit does not open private owner truth.
3. The original aggregate retained all counts but wrote the query-context
   schema label because dictionary expansion overwrote its report label. The
   [public correction](../../../../poc/sender-private-lifecycle/privacy/active_report_correction.py)
   changed only that label; original and corrected hashes are in
   `final/CORRECTION.json`. The exact executed worker is preserved in
   [the source preimage](../privacy/preimages/active-retry-03/active_worker.py);
   the current worker fixes the label for future runs. No prediction or count
   changed after truth was opened.
4. The separate genuine [two-round component result](../components/COMPONENT-WORLD-01.json)
   and its [fresh-claim check](FRESH-CLAIM-COMPONENT-CHECK-01.json) cover the
   distinct-claim boundary. Another 42 privacy and 35 admission unit controls
   passed. Each supplies only its stated component or synthetic evidence. No
   test KAS, reserve state, native acceptance or payout was used in this active
   diagnostic.

The older frozen passive-study source selections and cohort output still say
`UNEXECUTED_BLOCKED`; that field records their earlier freeze, not the status
of this later, separate diagnostic. They were left byte-identical.

## Adversarial second pass

The wire fixture has no value, wallet spend, reserve or native exit operation,
so it cannot mint value, double-spend or release reserve KAS. It also cannot
establish those safety properties. The scored observer received B's own truth,
the known cohort handles and the complete selected coordinator-visible phase-one
artifacts. Owner truth was mounted one owner at a time only after the prediction
seal and public query-closure barrier; the host-side audit reads public bytes
only. A missing MPC phase, artifact, owner leaf or count aggregate would halt
the runner rather than become a privacy pass. The trusted launcher remains able
to inspect local secrets and is outside the tested observer model. The random
wire state is not a checked financial prior state; reorg and stale-state behavior
are unmeasured here.

## Mitigation questions already identified

The [design follow-up](ACTIVE-RETRY-DESIGN.md) compares four possibilities:
delaying NF disclosure, a durable authenticated attempt history, a
deterministic recoverable cohort rule, and anonymous membership with isolated
network identities. None is established as a drop-in fix. Delayed disclosure
must still support whole-effects owner authorization; a local attempt log can
disappear or roll back after seed recovery; a fixed cohort reduces private
payment availability; and fresh aliases alone do not hide known participation.
Any selected remedy needs a reviewed lifecycle showing what a restored wallet
knows about earlier disclosures and what happens when peers or recovery data
disappear. It must preserve value conservation, single spend, exact-effects
authorization, reserve backing and independent exits.

**Current conclusion:** the declared known-cohort coordinator plus B colluder
identified all three unknown eligible input owners after a changed-cohort abort
in this genuine MPC wire fixture. Same-cohort retry retained the two honest
owners' ambiguity. This is a measured active admission-channel failure under
the frozen conditions, not a claim about general network anonymity, financial
authorization or native settlement. A passive result cannot erase this negative
cell.
