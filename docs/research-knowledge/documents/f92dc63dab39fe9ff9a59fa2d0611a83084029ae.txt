# Native usage privacy: prospective specification

Date: 2026-10-21. Base checkpoint:
`9ae5b3efeb1698cf45d35e064c95f91c1ac5a54e`.
This implements the bounded experiment in
[RFC-0015](../../docs/rfc/0015-native-usage-privacy-screen.md), under the unchanged
[RFC-0012 requirements](../../docs/rfc/0012-useful-privacy-requirements.md) and
[security invariants](../../SECURITY-INVARIANTS.md).
The [source review](../../research/shielded-kas-native-usage-privacy-2026-10-21.md)
states the protocol and observation boundaries.

Freeze this specification, executable policy, generation/observation/scoring
sources, binaries, public parameter identity and dependencies before drawing the
fresh private seed or creating wallets. Development controls use explicit public
fixtures. Retain failures, original requests and sampled identities; do not
resample a difficult history or revise attacks after scoring.

## Question and evidence boundary

Can an observer expose internal payments when users have unequal activity,
repeat counterparties, spend receipts and withdraw during activity, including
transparent transfers back into the pool? Which information comes from genuine
transaction bytes, from public value-flow edges, and from declared usage priors?

Generate one history using 32 fresh v2 wallets, with eight colluding roles. All
pool operations use the unchanged circuit, covenant, note encryption, key scheme
and pinned parameters. Retain genuine proofs, ciphertexts, native signatures,
outpoints and transaction bodies. Independently replay the whole native history
and validate each ordinary bridge against its actual input UTXO.

Synthetic funding ancestry and the supplied accepted history remain assumptions.
No chain acceptance, broadcasts, real funds or measured network behavior follow.
This is varied synthetic usage of genuine wallet transactions, not representative
human activity. One local generation process may hold all fresh fixture wallets
and amortize loading the public proving key; this does not test independently
operated wallets or provider confidentiality. Observers remain separately isolated.

## Fixed usage policy

All 32 users are admitted before ordinary payments. Initial **net shielded**
capital is independently selected from 350, 700 and 1,400 tKAS. The founder's
initial claim includes the bootstrap fee so its post-bootstrap capital follows
the same distribution. Native founding change and ordinary fees remain accounted
for separately; they cannot subsidize a missing shielded liability.

There are exactly 64 ordinary PAYs. Roles 0–7 each send twice. An independent
hidden permutation of honest roles 8–31 assigns four receive-only users, eight
one-send users, eight two-send users and four six-send users: 48 honest sends.
A second independent honest permutation assigns eight prompt cashout users,
eight users who accumulate two received claims, and eight who retain receipts.
Colluders retain receipts. These are workload assumptions, not hidden wallet
features or empirically measured user frequencies.

Four fixed bridge controls are included in the 64 payments. Colluders 0–3 send
their first payments to four distinct prompt users from the second permutation.
Each recipient immediately exits that received claim. The resulting native coin
is transferred to a funding address and admitted again in these four cases:

| Control | Native recipient | Funding index |
| --- | --- | --- |
| Self, reused | Same wallet as the exit | Its original index 0 |
| Self, fresh | Same wallet as the exit | New index 1 |
| Cross-user, reused | Fifth prompt wallet | Its original index 0 |
| Cross-user, fresh | Sixth prompt wallet | New index 1 |

Only actual ordinary transaction outpoints identify these cases publicly. Private
case labels, wallet indices and source/destination owners are withheld. The four
controls guarantee both true and false common-owner hypotheses; they are not
four randomly sampled observations. No additional bridge is selected after
examining results.
Each bridge funds output zero with its actual payout minus 1 tKAS; the remaining
native change after the ordinary fee stays outside the pool and is accounted for.

Shuffle the remaining 60 sender requests once. Each sender has a hidden preferred
nonself contact: choose that contact with probability 70%, otherwise choose a
uniform nonself recipient. Honest amounts use 60% uniform invoice choice from
10/20/25/40/50 tKAS and 40% uniform choice among the 4,001 cent-denominated
amounts from 10.00 through 50.00 tKAS, represented as integer sompi.
Colluder payment ordinal `j` from role `a` is
`20*100_000_000 + (a+1)*1000 + j` sompi, including the four controls.
All selections and sampler/tie details are frozen in the executable policy.

PAY selects the privately tracked capital claim, plus the lowest-position
unspent noncapital claim if one exists. Its positive sender change becomes the
next capital claim. This is an explicit experiment selector; the wallet itself
accepts caller-selected one/two-note positions. Prompt users withdraw received
claims after each receipt; accumulating users withdraw their earliest two
noncapital claims when two are available; retaining users do neither. Intermediate
withdrawals never consume the capital chain. Returned admissions are noncapital
claims. The four controlled bridges occur immediately after their designated
receipt exits; later public availability still follows the rule below.

The capital chain loses at most payment plus fee per authored payment, even when
a receipt is consumed alongside it. Six maximum payments cost 302.4 tKAS, leaving
at least 47.6 tKAS of the 350-tKAS minimum. Consequently no hidden top-up,
unfunded request substitution or resampling is needed for ordinary payments.
The bridge proceeds are actual recycled native value, not additional injection.

After all requests, shuffle the role order once and drain each wallet's remaining
positive claims in ascending position pairs, using one input for an odd tail.
No claim is erased because it is small. The native reserve and all shielded
liabilities must reach zero.

Initial operations have modeled minute zero. Each ordinary PAY advances a
separate modeled clock by a sampled gap from 1, 3, 10 or 60 minutes. Immediate
receipt exits and their bridge admissions share that modeled minute. Final
drainage starts 60 modeled minutes later. This clock is scenario metadata,
never fabricated block time or proof-generation timing. Dependency order remains
the actual transaction order.

## Public and participant observations

The raw archive contains exact descriptor, verification key, lineage transactions
and actual selected funding-parent bodies. Derive public fields from these bytes
after native validation. Bind canonical artifact digests and full transaction
hashes, not transaction IDs alone. Funding identities are exact `(txid, index)`
outpoints; equality of a parent transaction is not a common-owner fact.

The directory maps only the 32 initial funding outpoints to wallet pseudonyms.
Later bridge admissions receive no true owner labels. Reusing a known funding
script may support an association; a fresh funding script is not identified by
the private control setup. A native value-flow edge does not establish that both
ends have the same owner. Participant records disclose only that participant's
actual received notes and authored operations, including its own exits/admissions.

Evaluate ten profiles: `C` (explicitly C+D: public data plus the initial directory),
`P0` through `P7` (the same data plus one colluder's records), and `pooled` (all eight
records). Every observer receives one profile at one public prefix. It predicts
every ordinary PAY visible in that prefix, without a future target list or
private eligibility mask. The scorer selects the predeclared target/horizon rows.

For each ordinary payment, evaluate its creation prefix, the prefix ending at
the **next publicly visible DRAIN**, and the complete final history. The cashout
cutoff never uses the target's hidden recipient or true spent-note relationship.
If there is no subsequent DRAIN, use final history and record that fallback;
the declared complete drainage should make it unnecessary for this workload.

Cut lineage, modeled times, directory entries and participant records at the same
prefix. Publish a funding-parent body immediately before its consuming ADMIT;
earlier views must not receive future bridge transactions or unused parents.
Thus a prefix immediately after a receipt EXIT does not yet contain its later
ordinary bridge. This models accepted pool lineage plus published required
parents, not an observer of a complete hypothetical blockchain.

Withhold honest inspections, actions, selected inputs, backups, key indices,
hidden activity/cashout assignments, seeds, request plans, proof timings and
private native-owner labels. Full raw bytes remain available to the observer;
a projection does not replace omitted native fields.

## Frozen predictions and controls

The fixed variants are `prior`, `residual`, `split` and `native_graph`. Each makes
sender, recipient and integer-sompi amount guesses for every visible ordinary
payment, plus a four-integer relationship rank. The prior uses the published
policy and legitimate prefix observations; any empirical calibration must use
explicit development data only. It is not asserted to be the strongest possible
posterior. Local matches remain guesses, not logically forced facts.
The amount prior optimizes the primary **honest-target** amount distribution,
not the unconditional honest/colluder mixture or a complete ledger posterior.
Its fixed guess is 45 tKAS. Under the declared honest mixture its expected
within-10% success is `3/25 + (2/5)*(910/4001) = 21103/100025`, about 21.10%:
the public usage prior alone puts pressure on the unchanged 20% absolute cap.
Keep that result and distinguish scenario predictability from transaction leakage.

Rank relationships lexicographically descending by the frozen four-integer
evidence tuple, with event ordinal ascending for ties. Preserve fallbacks and
wrong predictions; never choose the best variant using truth. Separately report
native bridge common-owner guesses, abstentions and false positives, including
both cross-user controls. Raw byte length/equality/padding findings remain
surface diagnostics until a demonstrated relationship to protected facts exists.

Controls must exercise public prefix trimming, exact outpoint binding, future
parent/record rejection, per-field known facts, wrong plausible graph ownership,
sompi boundaries, complete target coverage, ranking/ties, exact rational caps and
empty groups. Retain published native positive/negative calibration separately;
it is development evidence rather than another fresh sample. No unbounded
whole-history reconstruction is a prerequisite for finishing this screen.

Seal every prediction and the complete prediction-batch manifest before any
scorer receives private truth. The scorer independently checks the declared
operation schedule, selector, note values/owners/consumption, actual wallet scans
and native source/bridge accounting against the public bytes. Actual truth
is tied to an author scan immediately after every pool operation, as well as all
32 final scans. Positioned-nullifier spentness must match the claimed input
chronology; equal-valued notes from the same owner cannot be silently swapped.
Fixed actual truth
must satisfy both existing arithmetic/ownership encodings once at final history;
do not build a reconstruction model for each of the 1,920 scored target/view/
horizon combinations.

Native accounting has two separate equations. Pool accounting includes all
admissions, including returns, and reconciles reserve, payouts and pool fees.
Whole-experiment accounting counts external synthetic source value once, then
reconciles final outside-native balances, remaining reserve and ordinary/pool
fees. A payout recycled through a bridge is not fresh money. Maintain one spent
native-outpoint ledger across founding, pool transactions and ordinary bridges.
Pool replay alone does not validate recursive funding ancestry or ordinary
external double spends.
For each of the 32 initial ordinary parents, the declared synthetic source UTXO
is output-zero value plus 1 tKAS. Its actual signature is checked against that
provided context; the context is not established chain history. Include these
parents' ordinary fees and change in the whole-experiment equation.

## Eligibility, metrics and prospective decisions

Primary targets have two honest endpoints outside the disclosed member set and
are created after all 32 users are admitted. Preserve all-undisclosed, startup
and adversary-endpoint diagnostics separately; overlapping groups are not added.
All 64 ordinary requests are predicted and accounted for, including known facts.
Report one/two-input payments, receipt-funded payments, cashout modes and bridge
counts so actual usage can be checked without publishing private target masks.
Distinguish spending a received PAY claim from spending a returned ADMIT credit
and from the broader noncapital-input count. Required activity includes at least
one PAY spending a received PAY claim, one one-input ordinary PAY and one
two-input ordinary PAY. If a sampled history misses any of these, finish and
retain the history, report the counts, and mark the screen incomplete without
resampling. Unobserved activity does not become a successful privacy result.

Exclude knowledge field by field and at the selected prefix: authors know sender;
authors and recipients know recipient and amount. A joint relationship is already
known only when both endpoints are known. Recipient-only knowledge does not make
the sender known. Guessed native associations never become ground-truth exclusions.
The public control schedule already identifies the first four senders and their
exact tag amounts, even to C. Exclude those specific fields as declared policy
facts, while retaining their unknown recipients and all control predictions.
Do not reclassify facts inferred from tested transaction evidence as already
known merely because an attack can recover them.

For each profile, horizon and variant, report correct/eligible counts for sender,
recipient, both parties, exact amount and amount within
`10*abs(guess-amount) <= amount`. For each eligible relationship group select the
top `ceil(q*N)` at q=5%, 10% and 25%, reporting actual rounded coverage. Empty
groups are undefined, never zero-success evidence. An empty primary group makes
its required comparison incomplete.

Use exact fractions for counts, rates, paired differences and strict cap tests.
The unchanged point-estimate caps are 10% sender/recipient, 20% within-10% amount,
five percentage points improvement over the frozen prior, and 50% selective
joint relationship precision. Exact amount and full-coverage joint accuracy are
additional diagnostics. Identify when the prior itself exceeds an absolute cap.
Do not attach population confidence intervals: this is one dependent history,
not 64 independent trials, and it does not inherit the previous 16 samples.

- **Observed finite-case cap warning:** a required primary rate, selective
  precision or prior difference is strictly above its unchanged cap. Identify
  the profile/horizon/variant and denominator. Treat this as a practical warning
  for the tested usage, not a statistically certified population failure or
  proof of cryptographic leakage. Investigate the cause before expanding the
  affected privacy claim; preserve all other results.
- **Demonstrated conditional disclosure:** a separate, reproducible public-data
  derivation uniquely exposes an otherwise unknown supported internal fact and
  is independently checked against the actual truth and stated assumptions.
  Stop expansion of that claim pending a redesign or explicit scope decision.
  A correct heuristic guess or an ordinary transparent payment edge is not such
  a certificate. The heuristic scorer never manufactures this status itself.
- **Completed native screen without an observed primary warning:** all planned
  operations, controls, prefix observations, predictions and checks finish,
  with no primary point-estimate exceedance. State exactly which tested attacks
  failed to expose which facts; do not call this a privacy pass. Keep diagnostic
  warnings and limitations visible.
- **Incomplete evidence:** missing required activity/observations, failed
  controls, contaminated prefixes, inconsistent native/private accounting,
  unresolved required checks, source drift or missing primary denominators.
  Preserve the attempt and identify the failed step; do not reinterpret it as
  anonymity or silently narrow the workload.

Every result leaves `qualification_pass` false. No outcome closes the early
privacy gate or authorizes milestone 3. Cryptographic review, chain behavior,
independent users, availability/recovery and network/provider observations remain
separate obligations. Export approved public inputs, predictions, aggregate
scores and provenance only; retain seeds, wallets, private truth and raw private
operational logs outside the public package.
