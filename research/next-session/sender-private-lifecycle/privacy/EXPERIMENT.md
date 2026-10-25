# Sender/input linkage experiment

2026-10-25. **Frozen before any scored candidate world: 128 worlds, eight cells
with 16 fresh worlds each.** No candidate linkage outcomes have been observed.
This extends the completed
ADR0064 lifecycle and keeps all earlier privacy/fee failures unchanged.

## Question and evidence classes

Does joint input mixing followed by separately mixed whole-effects Spend
authorization remove the public and passive coordinator's participant-to-input
certificate, without restoring a sender-to-output certificate?

Keep two evidence classes separate in every receipt and statistic:

- `GENUINE_COMPONENT_PROTOCOL`: fresh notes, six genuine Output proofs, two
  actual selected MASCOT runs, three whole-effects Spend proofs, and independent
  verification of all nine proofs. Repeated-use cases genuinely spend a
  received payment or change. The cohort does not itself claim chain acceptance.
- `MPC_WIRE_FIXTURE`: actual selected MASCOT runs with fresh random fixed-width
  rows or placeholder proofs. This tests transport/permutation behavior only.
  It cannot qualify private payments, statement binding, or financial privacy.

Never combine those classes to increase a sample size. A genuine outer/native
integration and confirmed TN10 lifecycle remain separate required gates.

Root selected **128** on runtime-only calibration
`f9719a26a5e2265e701ccc00e4a33ece2c9d9d76c824c5e53ab26f6483532966`:
actual phase-one/phase-two engine runs took about 85.3/18.6 seconds, with about
20.1 seconds total compilation. Calibration contained public placeholder rows,
no real proofs, no hidden ownership and no privacy scores. At most two MPC
worlds may run concurrently (12 CPU ceiling); coordinate genuine proof workers
with integration. The [fixed registry](WORLD-REGISTRY.json) names all 128 worlds.
After freezing, no
outcome-driven resizing, replacement, dropping, strategy adjustment or threshold
change is permitted. Store a fixed ordered world registry and exact source pins.

## Allowed views

1. **Public:** actual public session, financial state/effects, final mixed
   inputs/outputs, authorization rows and published protocol messages. Public
   entry/exit amounts, timing and funding ancestry stay visible where present.
2. **Passive coordinator:** every byte actually available to the implemented
   network-off coordinator, including its complete input IPC, stdout/stderr and
   all output files, plus its permitted public knowledge. Do not substitute
   selected summaries or redact labels from a legacy transcript.
3. **Coordinator plus participant 0 persisted artifacts:** the same public/
   coordinator material plus every actually saved file in participant0's own
   wallet/MPC runtimes: its engine stdout/stderr, saved preprocessing/share
   state, TLS key/certificate files, contributed rows, private wallet records
   and legitimately decrypted incoming receipt scans. Repeated worlds include
   both its original and restored runtimes. Run this observer inside that same
   participant's isolated private capsule; never publish/read/hash those files
   from the controller. Internal comparison ID `coordinator_colluder_0` is kept
   unchanged; its displayed scope is explicitly
   `COORDINATOR_PLUS_PARTICIPANT0_PERSISTED_ARTIFACTS`.

**Prospective capability amendment, before zero candidate scores:** the stock
engine's saved files do not establish a complete capture of ephemeral incoming
online shares, TLS session memory, process memory or an arbitrary malicious
party's full protocol view. That original stronger question remains explicitly
**INCOMPLETE**. The third measured comparison covers the persisted artifact
view above only; its result must never be promoted to arbitrary colluder
security. This source/capability finding occurred before any candidate outcome.
The 128 worlds, eight workloads, six comparisons, target selection, strategies,
conditional candidate counts and family/per-comparison thresholds are unchanged.
The exact previous contract and owner-helper hardpin are retained in
`preimages/capability-01`. No active experiment or alternative execution path
was introduced; the separately blocked active experiment stays UNEXECUTED.

At least two participants must remain honest for the bounded passive ownership
target. The trusted launcher/host administrator is outside that target. A global
network observer does not inherit absent packet captures: unmeasured network
timing/correlation remains explicitly INCOMPLETE, not a successful cell.

Capture full actual role-visible artifacts and externally pin their inventory
and bytes. Missing private colluder access or a missing owner truth oracle is
INCOMPLETE. Role isolation itself needs a capability check: no other owner
leaf, host home, daemon socket, private launcher plan or arbitrary execution
interface may be available to an observer.

## Targets, strategies and truth separation

The six primary comparisons are the three observer views above times:

- `owner_input`: identify the final input NF belonging to a selected participant
  or funding handle legitimately known to that observer.
- `input_payment_output`: identify the payment-output CM created with a
  selected published input NF. This is an input-to-payment-output target, not a
  claim to recover a receiver's civil identity or address from a ciphertext.

Freeze challenge selection and one guess per comparison per independent world.
The selected input/output candidate cardinality is the **eligible honest prior
universe**, not the observer's post-inference feasible set. Colluder-created
inputs and legitimately already-known complete target associations are not
unknown targets. If the specified target has fewer than two genuinely unknown
eligible candidates, preserve the boundary/incompleteness; do not score a
trivial own-input answer as evidence of an attack.

Calibrate the unchanged baseline's explicit marker, roster/READY pairing,
fixed-index assembly and owner-labelled authorization on fresh synthetic public
records using their actual source encodings. A fixed-order guess is not a
deterministic certificate after a real shuffle. Removing literal identifiers
is not by itself a successful attack measurement.

Candidate observers must inspect actual role-visible messages before sealing
predictions. Include explicit participant/NF joins, same-packet byte joins,
fixed-order guesses, repeated identifiers, timing/amount/fee constraints and
legitimate colluder knowledge. Seal every prediction batch before any owner
truth comparison. Owner-local workers may open only their own fresh records,
must reserve the diagnostic once before truth access, and must never expose
their NF, payment CM, output positions, target eligibility or per-owner scores.

The restricted aggregator receives exactly three distinct owner count leaves
and exports only global eligible/matched counts. Each query must have exactly
one actual eligible owner. Missing truth cannot become a miss. The fixed 148-B
count encoding binds experiment, world, full view batch and prediction seal.
The pure encoding functions do not themselves establish namespace isolation or
one-use enforcement; the reviewed runner must do that.

## Workload and side information

Preserve equal and heterogeneous amounts, single and repeated spending, and
simultaneous and staggered scheduling as separate registered workload cells.
Use integer sompi throughout. Equal cells request 5 KAS each in round one and
2 KAS each in round two. Heterogeneous cells request 3/5/7 KAS in round one and
1/2/1 KAS in round two. Each admission is 20 KAS. Repeated cells use
received-or-change, change, received-or-change note policies for participants
0, 1, 2 in round two. Selection prefers an incoming receipt and falls back to
change when that participant has no suitable incoming receipt. Participant 1
must pay participant 0 or 2 in round one, so at least one of 0/2 spends received
value; participant 1 spends change. Requiring both 0 and 2 to have received a
payment was a feasibility error: random honest destinations need not satisfy
that. This prospective amendment was selected before any candidate privacy
score; the original strict-selection contract/registry and rejection are
retained. It does not alter N128, amounts, thresholds, scheduling or world
inclusion. Scheduling
is either no deliberate delay or 0/250/750 ms before the owners' stage launch;
these are experimental scheduling instructions, not claims to capture a global
network observer. The registry stores all amounts as integer sompi.
Existing CM16 capacity permits GN3 plus at most
two three-spend/six-output rounds (n15), so repeated cases use **two** rounds.
Fresh worlds use new notes, keys/blindings, sessions, aliases and MPC scratch;
relabeling a fixed commitment set is not a new world.

Amount/fee/timing/ancestry overlays on fixed-width wire fixtures are labelled
models. They cannot replace actual wallet behavior, transparent native payout
amounts, packet captures or genuine repeated received-note/change spending.
The fresh candidate fee policy was selected **before any scores**: round the
quoted native minimum mixed-batch fee upward by 0, 1 or 2 sompi to a multiple of
three, then charge three identical integer shares. The existing financial
authorization binds that exact fee and native validation still requires at
least the actual native minimum. This prospectively removes the earlier
owner-index one-sompi remainder for this candidate only. Preserve the prior
failure and test its old allocation as a calibration; do not change the fixed
useful-payment denominator. Other amount, fee and sparse-participation channels
remain in scope.

## Required active and boundary controls

These are fixed before candidate measurement and are not excluded after a fail:

- **Aborted-session roster intersection:** actual phase-one runs A+B+C then
  A+B+D with a repeated unspent NF, fresh session aliases/sort keys/outputs and
  the coordinator's known memberships. Participant B may supply its own NF.
  Intersect candidate ownership explanations using repeated NFs and exactly one
  contribution per member. Fresh aliases do not erase known participation.
  Each session still has two honest owners. This is an expected active failure
  of the initial two-phase design unless an actual mitigation closes it.
- **Same-cohort control:** repeating A+B+C without an ownership disclosure must
  leave the two honest input assignments ambiguous for the bounded observer.
- **Fresh-claim control:** changing a legitimately spent claim changes its NF;
  never change the NF of the same unspent note to make an attack disappear.
- **Two-colluder elimination:** with two of three inputs already known, the
  remaining input is identified. Report this expected boundary explicitly.
- Malformed/missing/duplicated/substituted rows, wrong effects/state, proof-slot
  swaps, stale/replayed authorization and owner loss must fail safely. A timeout
  cannot revoke old authorized effects or justify a new broadcast of them.

The active inference enumerator uses membership intersections only when an NF
is actually observed; it never equates absence of an NF with owner absence.
An owner may select different claims in different attempts. Synthetic controls
test the attack algorithm; an actual attack finding requires actual MPC output
and separately sealed owner-local truth counts.

## Statistics, stop rules and interpretation

Each primary comparison uses one Bernoulli event per independent fresh world.
The reference assumes a conditional uniform assignment among the presealed
eligible candidates: p_i = 1/K_i. This is an explicit model, not a proven
distribution of actual transcripts or an upper bound on adversarial knowledge.
Compute the exact Poisson-binomial upper tail with rational arithmetic. Family
alpha is **0.01** for six primary comparisons; each threshold is **1/600**.
At p0=1/2, the 128-world six-comparison threshold first flags 82 successes;
power is about 94% for a true 70% success rate and only 20% for a true 60% rate.
These are design calculations, not observed outcomes. Per-cell counts and
calibrated uncertainty are descriptive. No new strategy is
tuned against held-out scores. A lucky correct guess is a success in the
statistic, not automatically a deterministic privacy break.

Any verified direct ownership certificate or safety violation fails its
candidate scope immediately, irrespective of significance. Continue retaining
all planned outcomes; do not stop sampling because a score looks favorable.
Missing, duplicate or incomplete worlds prevent a cohort statistic and retain
the original denominator. Evidence classes never pool. Runtime failures remain
INCOMPLETE; privacy/soundness checks do not weaken for a retry.

Without excess success, report only **NO_EXCESS_DETECTED for these frozen
strategies, declared observers, model and evidence class**. Never call that an
anonymity score, indistinguishability proof or financial-privacy qualification.
Passive, active, network, amount/timing, financial, fee and availability verdicts
remain separate. An active roster-intersection FAIL survives any passive result.

## Selected executable interfaces

`observers.py:predict` consumes the complete actual artifact byte list and
permitted original owner/funding handle, selected final input, all three mixed
NFs and all six final Output CMs. The colluder passes only its own NF/two
created CMs, inside its own observer namespace. The fixed strategy attempts
explicit same-record participant/NF and owner-transport byte joins, otherwise
uses its frozen hash tie-break. It returns two guesses per observer and the
prior candidate cardinalities. A possible byte certificate is not a verified
leak until actual owner-local truth confirms it. The fixed strategy is bounded;
it does not pretend its hash tie-break analyzes an arbitrary ciphertext/MPC
cryptanalytic correlation.

`receipts.py:score_owned` receives one owner's own handle/NF/payment CM and
exactly six presealed guesses in public/coordinator/colluder order. It returns
six eligible/matched count pairs only. `encode_counts` makes the 148-B private
context-bound leaf. `aggregate_counts` sums exactly three distinct private
owner leaves and requires global eligible=1 for every query; its selected
colluder leaf must not be eligible for that observer's own-input target.

The runtime must authenticate all artifact/source selections and implement
one-use reservation before truth, whole-parent exclusions, private capsules,
single-owner namespaces and restricted aggregation. These cannot be inferred
from the pure functions or test counts. The source freeze covers those pure
strategies/statistics/encodings; the reviewed runtime manifest separately pins
the actual candidate/wallet/runner sources before candidate execution.
