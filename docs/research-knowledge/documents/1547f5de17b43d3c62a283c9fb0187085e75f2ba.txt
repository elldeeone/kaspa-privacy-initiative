# 32-user/eight-adversary privacy test: first falsification stage

Date: 2026-10-20. Candidate: `aa6ed4947f7c25db128cd5d89b7c021d6b8fe690`.
Parent requirements: RFC-0012; experimental design: RFC-0014.
Freeze this specification, executable sources, dependencies and public calibration
identity before generating held-out histories. Preserve corrections as new attempts.

## Claim and result boundary

Test whether an observer can logically force an otherwise undisclosed internal
payment's sender, recipient or exact integer amount using the declared views.
This is the first stage of the 32-role test, not statistical qualification.
A reproducible supported counterexample can reject a claim. No counterexample,
few samples, unknown queries or unexecuted views cannot pass the early privacy gate.

This workload is modeled, not a new proof/native-acceptance experiment. Opaque
identifiers stand in for cryptographic hiding; they must contain no encoded role,
amount, choice seed or truth handle. Actual native-byte calibration remains the
separately preserved early-privacy experiment. Modeled timing is not observed
chain time. No real/test funds, new proofs, network access or broadcasts.

## Frozen workload

Four independent hidden request seeds, each producing matched persistent and
prompt-cashout arms: eight histories, four sampling units. Two request sets use
overlapping activity; two include a sparse interval. Development/known-answer
controls use separate, explicit fixtures; never tune on the held-out seeds.

Each history has 32 stable roles, numbered 0 through 31. Roles 0–7 are controlled
by one colluding adversary but retain distinct wallet keys. Owner variables name
these wallet/user roles, not measured independently controlled people.
Role 0 founds the pool and performs a self-bootstrap; the other
31 join with independently identified native funding parents. A public directory
maps every funding identity and receive-contact identity to its role. It supplies
no hidden transaction-author map and no payout-to-owner map.
This directory is hypothetical side information published at the start, not an
output of the current wallet. A funding association names the owner of the selected
funding output, not the creator of its parent transaction. Each modeled parent
provides exactly one selected funding output, so its unique identifier can serve
as that output's handle here. Do not generalize this shortcut to native parents
with outputs belonging to multiple owners.

Net starting balances are drawn independently and uniformly from 2,500, 5,000,
10,000 and 20,000 tKAS. Every role makes two internal payments; self-payments are
excluded. Honest requests choose uniformly among the other currently admitted
roles, with integer amounts sampled log-uniformly over 10–1,000 tKAS, including
sompi precision. The distribution is a research assumption, not observed usage.
The exact discrete sampling algorithm must be frozen in code before generation.

Admission and payments interleave: the initial cohort is roles 0–3 and 8–19
(four adversaries and twelve honest roles). Admit that cohort, execute one request
from each in a hidden shuffled order, admit the remainder, execute the first
request of each new role, then a hidden shuffled second round for all 32.
Recipient eligibility is restricted to roles admitted at request time.
Overlapping requests use increasing one-minute modeled slots; the sparse regime
adds a 60-minute gap before the second round. Order within each round is hidden.
Admission/bootstrap positions are public diagnostics, not scored payments.

Each of eight active roles authors two tag payments to independently chosen
admitted honest roles. Tag amounts are `100 tKAS + (role+1)*1000 sompi` in its first
request and `200 tKAS + (role+1)*1000 sompi` in its second. The attacker chooses
its own amounts, recipients and selected inputs; it cannot change honest requests,
see their future choices, censor them or reorder their transactions.
There are 16 attacker-authored versus 48 honest-authored requests; starting
capital follows the same public distribution. Report actual capital, payment-value
and operation shares, including cashouts, rather than call all shares 25%.
The active policy is nonadaptive; adaptive attacks remain untested.

For every payment, a modeled wallet chooses an owned unspent one-or-two-note
combination that covers payment plus the 0.4-tKAS fee and leaves zero or at least
the 0.6-tKAS note floor. Choose least excess, then fewer inputs, then lexicographic
positions. This is a declared modeled coin-selection policy: the real interface
accepts user-selected positions and has no such automatic selector.

Persistent recipients retain receipts for later selection. Prompt recipients
immediately exit the received note, paying the same 0.4-tKAS fee; their later
requests remain unchanged and use their remaining balance. Both arms start with
the same capital and requests. End with complete drainage: visit roles in a
hidden shuffled order, exiting one or two remaining notes per operation, ordered
by position. Record every fee and payout. Never erase small claims, skip an
unaffordable request, subsidize silently or regenerate a failed seed.

Use current v6 floors, integer sompi, range/capacity limits and current anchors.
One/two real inputs must have one owner. Output 0 is the positive payment;
output 1 is zero or positive sender change. ADMIT credits its funding owner,
followed by zero padding. The default view supplies no payout-to-owner association;
this is an input boundary, not a wallet anonymity guarantee. Real native scripts,
key derivation and their equality are not generated in this first model. Its
omission of address reuse is an explicit relaxation. The known funding/exit
derivation-namespace reuse risk remains an untested native-wallet case; do not
infer that it is harmless from opaque modeled destinations.

## Observer inputs and knowledge

Public inputs contain the stable directory, funding associations, ordered
mode/fee/deposit/payout/reserve/anchor/output-position data and independently
opaque commitment identifiers, together with declared synthetic timing.
Retain this complete modeled surface, with a field-to-native-source mapping.
Do not label modeled records native transactions or manufacture dummy proofs.

Views are C; C plus each of eight separate complete participant records; pooled
C+P; and C+P+A for the actual active history. Shared addressbook identities
provide the explicit linkage between pooled records. On this nonadaptive
workload complete pooled P already contains the attacker's actions and intentions,
so pooled P and P+A coincide; record this once, not as another sample.

An author discloses its exact selected positions, both output values and the
receive-contact identities it used, plus its own authored exit. A recipient
discloses its own positive note positions/values and recognized own spends.
It does not receive another sender's selected positions, sibling plaintext or
spending secret. Sending a note does not reveal the recipient's future nullifier.
Complete disclosure can rule out a controlled owner where its own records would
otherwise have contained the event/note. A note sent to an honest owner stays
honest even if the sender is an attacker.

All observers predict every public ordinary SPEND, without a private eligibility
mask. The primary uninvolved target predicate is: both endpoints are honest,
neither endpoint is in this view's disclosed member set, and all 32 roles were
admitted at creation. Apply it privately in the scorer. For the broader diagnostic
set, sender is directly known for a disclosed author's event; recipient and amount
are directly known for a disclosed author or a disclosed recipient's own receipt.
Apply these fact-specific exclusions separately. Do not remove an otherwise
eligible target because it becomes inferable.

Startup payments before all 32 admissions, adversary-controlled payments and
counterparty targets have separate, complete diagnostic strata. Startup does not
have 32 funded candidates: in the first cohort only twelve honest owners are
funded. No result there can be described as hiding among 32 funded users.
Sender anonymity from a recipient is not the primary RFC-0012 claim.

At each horizon use only the public prefix and disclosures available then:
creation, each subsequent cashout, and full drainage. Start execution with the
strongest pooled final view, then C and separate P, then earlier horizons.
Publish exactly which portions complete. Missing portions remain open.

## Ownership attack and certificates

Extend the integer relation with stable owner variables. Enforce common input
ownership, the declared admission/bootstrap conventions, positive change ownership,
and precise disclosed author/recipient facts. Equal nonzero commitments imply
equal value and owner under binding, while positions/spends remain distinct.
Never inherit the old observer's one-input-only exit constraint.

The first attack may relax modeled scheduling, amount distribution and automatic
coin-selection restrictions. List those omissions: more alternatives cannot
establish privacy, but an exactly forced fact in a valid relaxation is a candidate
counterexample. Never add a restriction that excludes the actual generated history.

For each sender, recipient and amount proposition, obtain a satisfying integer
model, then ask whether a different value is possible. A forced claim requires
SAT for the claimed value and UNSAT for its negation in both CP-SAT and Z3.
For ambiguity retain distinct satisfying alternatives; do not turn them into
probabilities. Reject inconsistent prefixes, solver disagreement and unknown status.
Relationship uniqueness requires both endpoints; one exposed endpoint is reported
separately. Verify generated truth satisfies the model in a separate scorer process,
after observer predictions are sealed, never by passing truth into inference.

## Controls, isolation and stopping

Before held-out inference, verify small ledgers by independent exhaustive
enumeration of owners/values/spends. Required controls cover common ownership,
two-input exit, fixed change order, recipient-only knowledge, complete pooled
records, identity permutation, equal commitments at distinct positions, prefix
isolation, schema poisoning, known forced disclosure and genuine ambiguity.
Include a 32-role sparse control with owner-linked payouts, and remove the payout
associations in its matched control: that extra information is not the default
public-chain view. Include an all-other-users-adversarial control.

Generate private seeds/truth outside Git. Freeze public views and run the observer
in an isolated process without private directories or external network access.
Keep observer predictions separate from scoring; pin all input/source identities.
Original seeds, failed histories and interrupted attempts stay preserved.

Execution may stop on the first scorer-confirmed forced disclosure on a primary
eligible target in the persistent arm, after adversarial second-pass review.
Prompt-arm failures are comparison results, not failures of the persistent-balance
claim. In particular, the declared immediate-exit schedule can reveal a receipt's
amount as payout plus fee. Startup/counterparty failures are reported in their
own strata, not silently promoted to a mature-pool result.
Record all unexecuted cases. A discrepancy
or resource problem is incomplete, not a privacy success. Do not weaken thresholds,
quantize private domains to speed a solver, change seeds or retune a completed run.

RFC-0012's identity, amount-guessing, selective-precision and advantage thresholds
remain unchanged. This stage scores no probability/rate pass. A separate frozen
qualification manifest must define strong priors, attacks, independent-session
sample size and simultaneous one-sided confidence bounds before rate scoring.
