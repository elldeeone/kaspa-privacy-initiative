# Common partial payouts: adversarial second pass

Scope: the author reviewed the H17 additions separately from implementation.
This is not independent review or cryptographic assurance. See the
[frozen specification](COMMON-PAYOUT-SPEC.md) and
[measured report](COMMON-PAYOUT.md) for the eventual execution verdict.

## Invariants and mechanisms

| Concern | Check and remaining boundary |
| --- | --- |
| Inflation or reserve theft | No change to circuit, covenant, parameters or `settle`. Each Q payout debits exactly Q plus its fee and retains positive private change. All original funding and every partial/final payout are reconciled. Native validation and the existing transaction mutations run on the genuine fixture. |
| Double spending and stale proofs | Original full exit and partial payout use the same real NF. The new harness checks both winner orders on cloned public states. After partial success the old capability is rejected; saved change exits and fresh alternatives also exclude each other through terminal state. |
| Unauthorized exits | The experiment calls existing owner authorization/proving. It introduces no withdrawal key, admin branch, signature bypass or fee subsidy. Wrong-domain/root/payout/binding defenses remain those of v6; H17 is not a re-review of its cryptographic composition. |
| Dependency loss | Saved exit workers get their own capability, VK and supplied public state only. They do not mount wallet keys or the proving key. Creating a new partial or a fresh fallback still requires the owner's witness and public parameters. Losing every authenticated copy of history remains a liveness failure. |
| Reorg and contention | Current state changes are handled by existing settlement witnesses; the native fixture is a synthetic linear accepted history. H17 adds no reorg, malicious-RPC or simultaneous-network validation. |
| Fee exhaustion | Each extra partial costs a real fee from that claim. Reject sub-floor remainders; do not assume extra deposits to pay them. Saved authorization has an exact fee, not a guarantee under all future fee rates. |
| Privacy regression | Public Q payouts, fees, sequence, destinations and final remainders remain visible. Test both the incomplete and drained histories, original payment links, and original cashout provenance. An input graph that merely changes which Q-change note is spent cannot count as a new original source. |
| Fake population | Four wallets are a hidden fixture fact; the observer is not capped at four owner labels. No extra deposits/users/cover payments are generated. A repeated common payout may come from an earlier common-change note in an alternative graph; the observer has no hidden fixture instruction that each wallet participates once. |
| Disclosures and truth leakage | Each H16 participant view is separate. Own receipt values, authored inputs and address aliases are explicit extra knowledge, never described as chain-only. Views are cut at each horizon. The observer has no `/proc`, host paths, private plan, claim/leg matching, other views or network. |
| Unsound solver shortcut | A relaxed result is positive only after the entire selected graph is certified with integer-sompi constraints. Original provenance is a deterministic function of that graph and checked against the query. Rejected integer graphs are blocked; unknown is an error. The independent tiny oracle also enumerates provenance and participant constraints without these solver encodings. |
| Misleading success | Primary targets are the original seven claims, not the eleven resulting payout events. Leg candidate sets are never intersected using their secret grouping. Separate-participant distinct counts do not represent one colluding observer. Zero singleton coverage is not hidden ownership, amount secrecy or statistical anonymity. |

## Limits and issues found during review

The size was chosen using the previously visible fixture, then frozen before
the new analysis. This is a bounded policy screen, not a blind holdout or an
estimate of general users. The fixed interval makes complete withdrawal 40
minutes later. The existing 30-minute target is knowingly not met; it must
not be rewritten to manufacture a pass.

The first small floor-control fixture accidentally emptied the whole reserve
in normal mode, so the existing parser correctly rejected it before reaching
the intended change-floor test. The control was corrected to retain an
unrelated funded note; no protocol/parser check was relaxed. This happened
before the measured observer run.

Whole-crate `cargo fmt --check` finds historical formatting differences in
unrelated source files. Only the changed harness files are formatting-checked;
historical protocol/evidence sources remain byte-identical to their pins.

The public-body calibration verifier mounts only its executable, one selected
public trace, system libraries and an empty result directory. It receives no
private plan or unused exit requests. Its `/proc` is not used as an observer
blinding boundary; the inference workers use the stricter no-`/proc` sandbox.
Partial-payout destinations are fresh synthetic native scripts in the inherited
calibration harness; their temporary native keys are not retained. Saved final
exits instead bind wallet-derived payout keys. The test verifies authorized
native outputs and accounting, not a later spend of those native outputs.

The model treats cryptographic bytes as opaque and does not prove hiding,
soundness, recipient anonymity or resistance to implementation fingerprints.
Preserving usable exits is intentionally independent of achieving a privacy
screen. A participant may choose its old fallback when normal policy is
unavailable, even if publishing it leaks its earlier anchor.

There is also a simple necessary amount constraint on a chain of these
single-input common cashouts. If a note of value V undergoes k Q withdrawals
at constant fee F and is then fully drained for native payout T, then
`V = T + F + k*(Q+F)`. Its final payout preserves V's residue modulo Q+F.
A participant who already knows V can test possible k values against the
visible remaining payouts. This is not sufficient to identify a source by
itself; spentness, intervening payments and unknown values still matter.
It explains why matching the first payout sizes cannot establish lasting
privacy. It applies to the declared constant-size/fee, single-input cashout
chain, not to every use of the two-input protocol.

The first inference attempt was stopped before scoring after four observations
finished. Slow exact searches repeatedly rediscovered that cashout arithmetic.
The replacement adds an entailed finite amount domain: an unspent note entering
the cashout-only suffix must equal a final payout plus its fee plus k visible
common debits. Notes already spent before that suffix are exempt; partial
histories and varying common fees disable the shortcut. It does not constrain
which wallet paid, how many wallets exist, or which final leg belongs to which
Q payout. The integer certificate model remains unchanged.

The justification is value conservation plus zero terminal reserve: every
positive note still live in that suffix must eventually be consumed. A
single-input Q step has exactly one positive successor; a full drain has none.
Thus each remaining positive chain ends at a visible drain, and summing its
debits gives the formula above. The domain allows every later drain and every
possible count of intervening Q steps, rather than choosing a hidden tail.
This argument does not apply across an intervening two-input payment or a
different partial-payout amount; the suffix stops there.

Two additional controls compare these bounds with independent enumeration,
including repeated cashouts from one note chain and intervening unsupported
operations. The original predictions are retained for comparison with the
replacement run. Input bytes, native calibration, payout size and thresholds
are unchanged; unfinished old searches are not counted as privacy.

The first termination attempt did not stop every sandbox child: namespace PID
1 ignored SIGTERM. Four surviving workers were identified by their stderr
paths into the interrupted run and stopped with SIGKILL. Two further old
observations had finished in that interval, giving six retained comparisons.
Neither the native run nor replacement workers were stopped. Interruption and
cleanup receipts preserve this operational failure; it does not turn the
uncompleted searches into negative inference answers.

The finite domains do not speed up every query. A later resumption reuses seven
completed predictions, retains active searches and schedules the remaining
jobs with either pinned implementation of the same relation. The two completed
plain/bounded overlaps agree row-for-row. Per-job source pins identify the
engine actually used; no result is relabeled as coming from a newer build.
Choosing the bounded engine for a disclosed initial-note owner uses a fact
already in that participant's view. It adds no observer knowledge.
All twenty logical observations must finish before any truth-based scoring.
Resumption resource counters cover that controller's lifetime and children,
not the earlier work or the adopted processes.

Three individual-query observations exceeded an hour. An additional batch
query implementation leaves those searches running and asks for any remaining
candidate at once. Each positive graph still passes the same integer check;
only exact UNSAT eliminates the remaining candidates. Its independently
computed graph provenance must satisfy the pending origin query. A tiny
integer oracle checks all input sets and origins across both horizons and
participant views, including cached repeats and empty candidate lists.
This changes search order and grouping, not the feasible relation. Completed
same-input runs must agree before a batch result is used.

Two optional H16 diagnostic processes were also still consuming CPU after an
earlier attempted stop. Their stderr paths and retained script digest matched
the unfinished diagnostics, and neither had produced a result. They were
stopped; the H16 evidence, scores and manifest are unchanged. This cleanup is
recorded separately from the twenty H17 observations.
