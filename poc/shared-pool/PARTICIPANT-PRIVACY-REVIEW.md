# H16 adversarial second pass

Implementing agent's review, not an independent audit. This changes an offline
inference model and its evidence pipeline. No native transaction, key, proof,
covenant, parameter, fee or authorization implementation changes.

## Is the participant view legitimate?

The private projection reads the original synthetic plan and emits only one
account's positive receipts and authored transactions. Authored output values
and receive-address equality are known to their creator. An incoming receipt
supplies its own value/position, not the sender's inputs or sibling plaintext.
The view contains no participant index or other experiment owner identifiers.
Local recipient aliases record only addresses this sender actually used.

Zero outputs are not assigned to their nominal plan owner: the native helper
creates them for a fresh throwaway key. No dummy receipt or later real spend of
one is admitted. Real nullifiers depend on the spending secret, so knowing an
outgoing note's opening does not supply its recipient's later spend. H16 sends
neither those openings nor secrets to the observer; only the logical record
facts are needed.

Complete, truthful records and an uncompromised account are assumptions.
Internal contradictions and omissions that conflict with other records fail,
but a consistently omitted receipt is not generally detectable from the chain.
This experiment is not a protocol for authenticating third-party disclosures.
Changing an unrelated hidden input/value in a control leaves the projected view
unchanged. A receiver-only control retains multiple possible sender inputs.

The `wallet` profile assumes single-author inputs and fixed change ownership,
as this client constructs them. The circuit permits a wider set of ownership
arrangements. Controls accept a different client's slot-1 recipient and
cross-author merge under `records`, then exclude them under `wallet`. These are
conditional inference results, not protocol rejections. A client's private
coin choices or payment recipient schedule are never treated as public rules.

Distinct receive handles do not mean distinct people. Unknown owners have
enough possible labels to represent every partition of the note positions.
There is no four-person anonymity set or four-account limit in the model.
Without any disclosed labels, owner equalities can collapse to one unknown
authority and the control recovers H15 candidates.

## Could the solver create false confidence?

The H14 integer conservation/spentness relation and H15 client rules are reused
unchanged. CP-SAT and integer SMT separately encode the new amount, input and
ownership constraints. The tiny-ledger oracle walks integer values/input
histories and checks ownership by equality components, without either solver's
variables or the production view parser. All three engines are compared at
each tiny-ledger prefix, including known distinct recipient aliases.

The hybrid solver's rational search can establish infeasibility. Every positive
input graph needs an integer CP-SAT certificate under the same records and
ownership rules. Owner labels remain integers in both searches. Unsupported
statuses are errors, not extra alternatives. Candidates and their recency rank
are logical results, not posterior probabilities.

Each observation prefix receives only receipts already created and authored
transactions already observed. The backwards query order carries only positive
later witnesses to earlier prefixes; those witnesses restrict to a valid
earlier history. No future negative inference or disclosure is reused.
Independent direct-prefix checks exercise this boundary.

The main scorer requires the true input/source set to survive at every reported
horizon, including participant-owned transactions omitted from headline metrics.
Candidate sets must nest: `wallet` inside `records` inside H15, and saved inside
fresh. These checks cannot prove the entire model correct but can catch
inconsistent exclusions, timing mistakes and result contamination.

## Could the scoring boundary exaggerate the attack?

Own sends and receives are excluded using private scoring data only after all
observer jobs finish. The observer predicts all spend targets and is never
given an eligibility mask. Bootstrap and admissions are excluded from payment
metrics. Withdrawals belonging to the discloser are excluded.

A later spend of a note the participant previously sent remains eligible:
its later use is not in the disclosed record. This tests whether a sender can
follow a recipient's subsequent activity, as well as inference elsewhere.
The report must not call such a target wholly disconnected from the participant
in the historical graph. Newly forced links are compared with the same targets
under H15, so old singleton links cannot become new attack successes.

Rotating through four participants creates overlapping target observations.
Their aggregate denominator is not a count of independent economic payments.
The case/participant results and marginal source alternatives remain visible;
no confidence interval, anonymity percentage or population claim is inferred
from these rotations.

Metrics concern creating transactions and exact input-note sets. They do not
enumerate possible owner identities or hidden-amount ranges. Multiple feasible
source transactions could still belong to the same known counterparty.
Accordingly, a favorable source-link screen would not establish protection of
sender/receiver identity against this participant.

The inherited horizons include a payment's appearance and each later full
exit. For earlier payments, the first exit checkpoint also includes intervening
payments/partial withdrawals. A new link first observed there cannot be
attributed to that exit alone. Separate first-appearance links from later
reconstruction, and avoid calling all appearance-to-final narrowing a causal
withdrawal effect. The ownership ablation adds both input-owner equality and
fixed change ownership; it does not separately identify those two causes.

## Isolation, evidence and unchanged safety obligations

Each process sees the public input and one projected view, solver libraries and
observer modules. Full plans/truth, other participant records, the controller,
private projection code, host home and network interfaces other than loopback
are not mounted. The private scoring inputs are opened after all jobs finish.
The researcher's familiarity with the recipes is explicitly outside this
process-isolation guarantee.

A run-time second pass found that the inherited sandbox exposed host mount
paths in its supervisor command line and `/proc` metadata. Those paths contain
case/exit-policy labels. The observer modules do not read either surface, but
the access boundary was weaker than intended. The first attempt was stopped
without scoring, after 30 completed predictions; inputs, predictions, source
snapshots and interruption metadata were retained privately.

H16 now omits `/proc`, runs the observer as namespace PID 1, drops capabilities
and prevents nested user namespaces. Network isolation is checked through the
socket interface rather than `/proc/net/dev`. A probe checks metadata absence
and denial of namespace creation; both integer solvers work in that environment.
The first probe required explicitly adding `--unshare-user` for
`--disable-userns`, then passed. The repeat uses the same frozen public files,
participant projections and unchanged observer equations. H14/H15 source and
evidence stay intact: their code did not use these labels, but their sandbox
receipts should not be read as protection against arbitrary metadata inspection.

Participant records and complete predictions stay outside Git. The exporter
copies only eligible-target predictions/scores, hashes and isolation receipts.
It excludes raw disclosures, already-known activity, keys, note openings,
unspent capabilities and private parameters. Frozen source and evidence
hashes preserve the existing native calibration.

Inflation, double spending, unauthorized payout, stale/replayed state, reorgs,
setup trust, recovery, history availability and fee liveness are unchanged
obligations of the earlier prototype. No solver result can move funds or
weaken a native check. Solver/dependency failure leaves an incomplete analysis;
it does not become evidence of privacy. This experiment adds no privileged
participant or operator to the payment protocol.

Cryptographic byte attacks, network/RPC linkage, multiple colluding accounts,
malicious payments, compromised secrets, real traffic distributions and
externally identified counterparties remain outside the measured adversary.
The evidence concerns a bounded synthetic disclosure attack, not general or
real-world anonymity.

## Completed checks and interpretation

All 64 main observations complete with truth retained. The 28 initial controls
and two added partial-change controls pass. A separate post-observation process
fixes every original amount and full input graph at all nineteen prefixes for
each case/arm/participant/profile: 1,216 checks pass. It validates an integer
model realization, not a cryptographic witness or every original owner label.
All three nesting comparisons pass on 3,168 candidate sets each. All 64 corrected
isolation receipts pass; all 32 projected records are identical between attempts
and all 30 completed earlier predictions have identical candidate rows.

A direct CP-SAT check independently agrees with the hybrid on thirteen feasible
input sets at one full-size checkpoint, using 171 queries. A further optional
direct-CP diagnostic at the slow tail checkpoint was stopped without an answer
after 570.48 seconds; its two profile runs do not count as completed controls,
extra ambiguity or evidence for privacy. The full main run completed, including
that checkpoint, before this optional diagnostic was stopped. Receipts and the
diagnostic code are retained; failed or absent answers never enter scoring.

The first frozen clause fails on two startup source links already visible at
appearance, while the other clauses pass in all sixteen matched pairs. Treat
the startup diagnosis as post hoc explanation, not a revised threshold. Fresh
still provides more alternatives and fewer forced withdrawal sources.

Six distinct fresh full-exit sources and two partial sources are forced under
records alone; adding ownership rules forces one more of each. This supports
prioritizing withdrawal-amount policy over assuming that change-slot camouflage
alone fixes the measured problem. It does not establish an effective mitigation.
The proposed follow-up must count original-payment links and final remainders,
not reward extra self-change notes or ignore their fees. Immediate independent
exits remain a requirement when privacy is weak.
