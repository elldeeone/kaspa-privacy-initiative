# Prospective sticky OWNER-basket control 01

**Freeze-time status: NOT EXECUTED. Separate Root source review is required
before any import, compilation or execution of this control.** The original
baseline's source, inputs, expectations, failure and outputs remain immutable.
This control is a new finite hypothesis, not a revised baseline or architecture.

Question: after the first ABC candidate egress, can ideal honest threshold
servers preserve the remaining honest owners' NF/output ambiguity by pruning
only accepted-consumed intents, retrying **AB** after C exits, and refusing an
ADE replacement? No owner needs to return for head refresh or peer consent.

## Proposed policy inside the ideal oracle

1. After accepting the first owner-authorized intent from each of A/B/C, fix
   that OWNER basket and those exact intents. The threshold service privately
   retains their NF/output/fee bindings and a global pending-NF/session index.
   No individual server is granted the full map. Malicious-secure shared
   computation, authenticated admission and durable shared state are oracles.
2. Before **any** NF/CM/CF/proof egress, durably commit the complete basket and
   disclosure record. Compute current eligibility only from authenticated NFs
   consumed in **accepted current state**. Pending exits, dispatcher claims,
   clocks and local cancellation flags cannot prune an owner.
3. Keep every eligible original intent and its exact two outputs. Privately
   remove only consumed intents and their approved outputs. While any original
   intent is eligible, refuse additions, replacements, same-owner new inputs
   and modified recipient/CF/fee/nonce requests. Identical retransmitted intent
   bytes are idempotent; this is not a new authorization.
4. Preserve the original archive and all publication history through reorgs.
   Recompute eligibility against restored accepted state: a rolled-back C Exit
   restores C and its original outputs. Reorg cannot erase observer knowledge.
   Global history must be consulted by every new session/restore path.

This can prevent the **coordinator** from choosing ADE while unspent A/B are
pending. It does not reserve the native head, prevent independent exits, prove
fair output or guarantee settlement. C can still win its direct Exit race.
The subsequent AB proof must bind the new actual head and unchanged owner
intents. Aggregate native fee changes from three fixed intent fees to two;
no owner fee, change, recipient, or output tuple is silently altered.

The global history and publication ordering above are essential new oracle
assumptions. No existing Kaspa policy enforces them here. Source selection for
durability, admission, private pruning and cross-session completeness is open.
An unaccepted host queue is not a consensus reservation or native debit.

## Observer definitions and exact frozen fixtures

Reuse the pinned baseline fixture unchanged: every original input is
2,000,000,000 sompi, payment 100,000,000, change 1,890,000,000, fee 10,000,000.
All NF/CM/CV/CF/proof/nonce literals remain those public fictional symbols.
Every retry keeps A's exact complete output tuples. No rerandomization or
hidden owner reauthorization is used to improve a result.
Each table row is an independent fictional history; candidate sets from
different rows are not combined into an invented single observer trace.

* **O-public-egress:** every released private candidate, including unaccepted
  ABC and any orphaned disclosure. It retains all candidate NF/output sets.
* **O-coordinator:** that complete egress history plus known owner cohorts,
  client submission identities and C's own NF/output pair. Only C is a
  colluding wallet. D/E are additional honest owners.
* **O-confirmed-chain-only:** only the final **currently accepted** private
  batch and current accepted native exits. It does not receive older aborted
  private candidates or orphaned private/exit records. This is a different
  observation set; its results cannot justify claims against the coordinator.

The finite owner universe is the union of the represented private batches for
each observer. Granting that universe is an explicit finite-view assumption.
Each observer is given only its projection; a reader of the full public
fictional fixture already knows its assignment. No real secrecy is tested.

For the reorg case the valid schedule is: ABC candidate egress; C Exit accepted;
AB candidate egress; that C Exit orphaned; original ABC eligible again and
accepted at the restored current state. Egress/coordinator views keep ABC,
AB and the historical C payout; accepted-chain-only sees final ABC and does
not inherit the orphaned C Exit. This is separate from the original baseline's
already retained apparent-ABC-inclusion/reorg counterexample.

## Frozen enumeration and expected failures

Reuse the **unchanged** baseline exhaustive enumerator: all NF-owner bijections
and all disjoint two-output partitions consistent with the projected views.
Stable complete-output appearance signatures are constraints alongside NF
signatures. Retain every joint assignment and its digest. No guessing scores,
old 1/6/passive-128 result or actual trial input enters this control.

| Candidate release history / failure boundary | Public egress | Coordinator | Confirmed only |
| --- | ---: | ---: | ---: |
| ABC → AB after accepted C Exit | 36 | 12 | 12 |
| ABC → ABC after unrelated D Exit | 540 | 12 | 540 |
| ABC → AB → ABC after C Exit reorg | 36 | 12 | 540 |
| ABC → AC after honest B exits; C stays | 36 | **1** | 12 |
| ABC → ADE after server basket state is lost | 4,320 | 12 | 540 |
| ABC → ADE when restore consults only session history | 4,320 | 12 | 540 |
| ABC → ADE through a session bypassing global history | 4,320 | 12 | 540 |
| ABC escapes before durable commit; restart admits ADE | 4,320 | 12 | 540 |

Exactly **24 views / 21,277 complete joint assignments** are expected.
In the first three rows, O-coordinator must retain two NF candidates and six
complete output-pair candidates for A, conditional on A/B both remaining honest.
In every failure row, A must have one NF and one output-pair candidate. The
global 12 assignments in several failure rows come from D/E ambiguity; they
do not rescue A. Public-egress parties can also exploit stable output-set
intersections even when they cannot attach an owner's name.
Pruning one member exposes that departed member's original NF/output pair by
set difference. In the conditional AB case that member is already the colluder
C. This is a statement about the **remaining two honest owners**, not a claim
that pruning hides every former member's partition.

**Honesty is not observable to the service.** When honest B leaves and colluder
C remains, sticky AC has two owners but only one honest unknown owner. A is
exposed by colluder subtraction. Do not infer honesty from a departing NF or
owner count, add a special “C is dishonest” server branch, or adjust the basket
to manufacture a pass. With one eligible owner, publishing its input/output
set likewise exposes its partition. Refusing that publication loses private
batch progress; no minimum-count remedy or new policy is selected here.

The restore failure is conditional: with durable global service history present
and consulted, a restored A request attempting a new ADE session is refused.
The failure row explicitly removes/bypasses that oracle. Original backup can
restore funds authority; it does not recreate forgotten unconfirmed disclosure
history. Another financially valid prover/session can also bypass a purely
service-local sticky policy. General cross-session enforcement is unresolved.

## Policy, safety and liveness controls

Model refusals: omit eligible B/add D/E after C Exit; publish before durable
commit; replace A's CF/recipient, fee or nonce; add a new owner; restore A into
a second session while its NF is pending; and prune B from a merely proposed/
mempool Exit. Verify exact C NF/output removal, unchanged AB after harmless
head movement, idempotent identical requests, restored ABC membership after
reorg, monotonic publication history and the honest-B-departure failure.

The shared-state control also explicitly instantiates a fresh ADE basket after
removing/bypassing old history and checks that previously observed ABC and new
ADE intersect at exactly A's original NF and complete output pair. This does
not pretend that one corrupt server can erase ideal honest-majority storage.
It tests the consequence if the positive durability/global-index oracle fails.

Run each final accepted cohort through the baseline's existing **ideal**
consent/accounting kernel. NF spentness, actual modeled current head, exact
per-intent outputs and fees, reserve/liabilities, native payout and complete
sompi accounting remain mandatory. ADE can be financially valid while leaking
privacy. No operator key, queue flag or forgotten history gains reserve authority.

Conflicting user requests expose a liveness limit. The service can refuse a
different still-pending payment/fee without confiscating the original note;
the independently authorized direct Exit remains a separate route and may win
the NF race. A service-local refusal cannot prevent an owner using another
valid proving path. No all-wallet attendance, permanent private-note lock or
privileged Exit delay is proposed. This control does not test actual exit or
backup software again; those remain the baseline's explicit ideal oracles.

Stop on any unexpected count, disappearance of an expected failure, changed
baseline pin, silently modified output tuple, admission of a forbidden subset,
pruning from unaccepted state, lost disclosure on reorg, accounting mismatch or
undeclared oracle. Preserve the negative result; do not retune owner schedules,
amounts, observers or expectations. Expected privacy/liveness failures remain
separate from any overall expectation-check label.

## Execution boundary and open question

`run_sticky.py` has no I/O or automatic entry point. A later approved runner must
guarded-read the exact new source/control pins and unchanged baseline source/
fixture, then call `run_sticky(fixture, control, baseline_namespace)`. Source and
all expectations must pass separate Root review before execution. New outputs
belong only in this versioned directory; existing baseline outputs stay intact.

This is an unselected ideal finite control. It establishes no native privacy,
cryptographic composition, network anonymity, durable storage, fairness,
real recovery or fee result. The frozen 21-KAS 2% all-in FAIL is unchanged.

Future question only, **not modeled or selected**: additions retaining every
previously exposed eligible honest candidate might avoid forced replacement.
Whether general appearance-equivalence/disclosure history can be maintained
across services and sessions remains unresolved.
