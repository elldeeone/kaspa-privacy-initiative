# Exact private-change arithmetic observer v1

Selected by root on 2026-10-23 before implementation. This supersedes
PLAN-PROPOSED-01.md. Existing public source comparisons and every older corpus
remain unchanged. The API and solver inventory are bound in SELECTION-01.json.

## Frozen scope

Only complete synthetic public ledgers, explicit legitimate integer value priors
and one global known wallet-policy arm enter the observer. Each private action
uses exactly one real input. Public actions disclose P/R/fee, positioned CM births
and opaque NF labels; they never disclose partial/full intent, the chosen input,
change slot, owner identity or a private receipt map.

Notes are identified by public append POSITION plus CM bytes. Repeated CM bytes
at different positions are allowed; each positioned liability can be consumed
once. A continuing private action's two newly appended CM bytes remain distinct,
as the native policy requires. This corrects the draft's blanket duplicate-CM
rejection. No equality-of-hash preimage relation is claimed by the arithmetic
model. Duplicate/nonzero NF checks remain public replay framing.

The whole-claim arm permits no positive private output when P>0. The
change-capable arm permits zero or one such output. Either arm permits one or two
positive outputs when P=0. Slots have no fixed meaning. These are assumed wallet
policies, not all possible Auth528 behavior.

Owner links are NOT_MODELLED. There are no input owner maps or identity guesses.
SAT alternatives are ARITHMETIC_ALTERNATIVE_ONLY: they are not guaranteed valid
hash openings, authorized ownership assignments, delivery histories or equal
probabilities. UNSAT alternatives prove a forced fact only under the declared
integer relaxation and supplied priors. UNKNOWN is INCOMPLETE.

## Relation and decisions

Use Z3 Int and Bool only. Values are0 or60,000,000 through
2,870,000,000,000,000,000 sompi. P is0 or at least10,000,000. Private fees are
positive. Ordinary ingress fees do not reduce the backed note value twice.
Each private action selects one earlier positive positioned CM; use is at most
once. Every action conserves value and every prefix's unspent value equals R.
Terminal R=0 cannot leave an unspent positive liability.

Check baseline SAT first. Baseline UNSAT is INCONSISTENT, never ambiguity.
For every public note value and every private event's consumed sum, new-output
sum and input position, block the baseline value/selection. UNSAT alternative
means FORCED_VALUE or FORCED_POSITIONED_CM_TO_EVENT (TO_PAYOUT if P>0).
SAT alternative requires a separate integer certificate checker and only proves
an arithmetic alternative. Stop on the first UNKNOWN and mark unqueried rows
NOT_EVALUATED; overall result INCOMPLETE. No probability or aggregate privacy
score is produced. All queries are public and exhaustive within the frozen bound,
never selected from hidden truth.

The certificate checker independently checks the public bounds, policy, chronology,
positioned single-spend, prefix reserves and priors using Python integers.
The observer imports no generator or old attack module, reads no files through
its API, and its CLI reads one strict JSON request from stdin only.

## Fixed public analytical cases and required outcomes

Amounts below use M=1,000,000 sompi; this notation is only documentation.

1. WHOLE_CLAIM: ingress1000M; P0 fee20M creates2 CM slots/R980M;
   terminal P961M/fee19M/R0. Consumed cashout sum980M is forced; either shuffled
   positioned CM may be that input, so each CM amount/selection has an alternative.
2. SINGLETON_PARTIAL: ingress1000M; private P400M/fee19M/R581M creates2slots.
   Consumed1000M and aggregate new581M are forced; each new CM can be0 or581M.
   This is a negative privacy control.
3. MULTI_INGRESS_CHANGE: ingress1000M and800M; P0 fee20M/R1780M creates2slots;
   private P200M/fee19M/R1561M creates2slots. Input sum and new-output sum at
   the latter action have distinct integer explanations, and positioned-input
   selection has alternatives. No owner anonymity follows.
4. ALL_BUT_ONE: ingress1000M; P0 fee20M/R980M creates2slots; explicitly supplied
   legitimate value prior fixes first new slot400M. Second slot580M is forced.
5. TERMINAL_VALID: ingress600M and400M; continuing whole-claim P581M/fee19M/R400M
   creates2zero slots; terminal P381M/fee19M/R0. First/second input positions
   are forced to the600M/400M ingresses; new zero slots are forced zero.
6. TERMINAL_LEFTOVER: ingress600M and400M; one terminal P981M/fee19M/R0.
   One-real-input relation is INCONSISTENT, not a zero-balance success.
7. LARGE_INTEGER: ingress9,007,199,254,740,993; partial P400M/fee19M.
   Input and remaining sum retain exact units above2^53.
8. REPEATED_CM: two600M ingresses share the same CM bytes but have different
   positions; successive whole-claim P581M/fee19M exits drain them. This is valid;
   positions are interchangeable and cannot be collapsed into one liability.
9. NF_REPLAY: repeat an earlier public NF in TERMINAL_VALID. Reject framing.
10. PRIVATE_FIELDS: add hidden operation intent, selected-input map, owner map or
    change-slot key at root/event level. Each variant rejects rather than ignoring.
11. BAD_AMOUNTS_AND_TOPOLOGY: reject bool/float/negative/aboveMAX amounts, wrong
    reserve delta, wrong CM/NF count, incomplete coverage and invalid terminal flag.
    A legitimate ledger outside resource bounds is INCOMPLETE_SCOPE, not ambiguity.
12. CERTIFICATE_NEGATIVES: replay an already spent position, select a future
    position, change a value to violate conservation, or collapse REPEATED_CM
    positions. Each candidate certificate must reject.
13. UNKNOWN_BACKEND: a test-only backend stub returns UNKNOWN. Result INCOMPLETE;
    no ambiguity/forced finding is fabricated. No production request can select
    a mock backend.

No hidden-corpus generation, old72-case evaluation, scoring or retuning is part
of this selection. Fixed public controls can expose implementation errors;
preserve failures and source versions if corrected.

## Fixed resource and stop rules

Existing Python3.14.4/Z3 4.15.4.0 only; no installs. At most12 positioned notes,
8 private actions,20 total events and12 explicit value-prior rows per input.
Each solver check has a fixed60,000ms timeout, seed0 and one solver thread.
At most1+N+3A<=37 checks per valid case. Independent public cases may use at
most4 worker processes. No retry after UNKNOWN, alternate solver/tuning, value
grid, floating relaxation or resource-bound enlargement for scored data.

Missing constraints include cryptographic preimages, actual note ownership,
correct ciphertext delivery, setup/proof soundness, accepted-chain membership,
data availability, network privacy and malicious-host resistance. This module
cannot qualify privacy/fees or turn the singleton live rehearsal into privacy
evidence.
