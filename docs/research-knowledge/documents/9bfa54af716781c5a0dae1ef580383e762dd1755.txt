# Actual-chain disclosure canary

**The current revealing exit links both selected historical PRIVATE outputs to
their native payouts and exposes both note values exactly.** One frozen C-only
evaluation read six actual accepted TN10 bodies, public input contexts and
accepting headers. No invoice directory, actor label, recipient backup, private
witness or payer information entered its sandbox.

This is a known, two-recipient pilot canary. It is not a blinded attack,
32-role qualification, human-identity inference or a cryptographic audit.

## Exact observation

| Public target | After revealing cashout |
| --- | --- |
| PRIVATE output position2, CM `1f4220ed…cbedadc` | Exact note value100,000,000 sompi; exact later exit output1 at `3f29dd0f…a4d809`, paying95,026,200 sompi |
| PRIVATE output position3, CM `0d2b8d19…c789530` | Exact note value100,000,000 sompi; exact later exit output0 at `bcef652b…07a99`, paying95,036,800 sompi |

The attacker recomputes each Note168 commitment from the public opening and
domain, checks the key commitment and original positioned HMAC nullifier, then
matches CM **and position** to the earlier PRIVATE output. It matches the native
payout script/key and verifies `note value = payout + fee`. Both targets are
logically forced by those public bytes under the accepted-transcript premise.
Hashes/binding and chain acceptance remain the implementation's assumptions;
the observer does not rerun Groth16 or native signatures.

Before reveal, the pilot's public arithmetic admits a necessary output-slot
outer relaxation `{0} ∪ [60M,140M] ∪ {200M}` sompi. This includes one-real plus
dummy and two-real private inputs, along with zero/positive output padding.
Two public NF insertions do not reveal real arity. These are necessary public
arithmetic bounds, not a claim that alternative cryptographic witnesses exist
for fixed hashes, and no probabilities are assigned. The later opening exposes
the actual value exactly. A note value is an economic payment amount only under
this separately declared direct-note pilot's semantics, not for arbitrary change.

Native payout scripts are public endpoints. Matching an output to one does not
infer a human identity without the corresponding permitted side information.
The scorer received no such identity mapping. There were no native-key equality
matches from this pilot's public ingress notes to its two later recipient exits;
that does not establish a general absence of key-equality channels.

## Design implications

An ordinary private proof EXIT must hide the input note's opening, commitment,
position and nullifier credential. It must bind an owner-chosen fresh payout
script in the proof authorization, rather than reusing note.nativePK: that key
is public in ADMIT and available in participant/directory invoices. The native
key bound in the note can remain the authorization for explicit REVEAL fallback.
This is a design requirement, not an executed new EXIT result.

Native payout amounts remain public. A proof-hiding exit does not automatically
hide amounts in a sparse or whole-note zero-change workload. Private change,
input/output shape, participant records, active scheduling, individual later
cashouts and complete drainage require independent measurement. Emergency
disclosures remain in ordinary historical targets' observation horizon; do not
erase them or relabel them after scoring. The rejected working-balance/delay
policy is not adopted.

The unchanged common-price prior remains `21103/100025 = 21.09772557%`, already
above the20% amount cap. A new cryptographic envelope cannot repair that prior
information limit by itself. This canary changes no target, case or workload.

## Freeze, controls and limitations

Independent review caught a format assumption before any actual evaluation:
the retained prior narrative said GN440, while the actual accepted founding
payload is536 bytes (`D@8, Note@40, CM@208, cipher@240, hash@504`). The parser and
synthetic controls were corrected; the original freeze/wrapper and a zero-run
cancellation are retained. The actual network recovery checker already used536.

Five synthetic byte/amount-control groups pass, including12 corrupt field
cases, payout substitution, three metadata-exclusion levels, arity/order cases
and a synthetic positive. These are not accepted native transactions. Revised
[freeze02](PRE-RUN-FREEZE-02.json) SHA256
`2f9e7d477494d17923b04fb2656827a1a98786b4c6e90407b61d78d5722f58e9`
pins all source, input and wrapper bytes. The independent reviewer rehashed
those pins and compared all six sanitized rows against the original accepted
public evidence before execution. The source map was not mounted for scoring.

Exactly one actual run completed. [Result](run-02/result.json) SHA256:
`18837fd94241296432c807133e70a25520e739a267c409842738b2bc5980d5d3`.
GNU time reports0.03s,21,792KiB RSS and zero swaps. The controller reports0.0645s.
The network-isolated process received only observer code and public data
read-only, with a fresh output mount. It requested one CPU/2GiB/swap0; the
transient unit finished before live cgroup sampling, so later infinity/default
properties are explicitly **not** runtime-limit evidence. There is no hardware
or wallet-resource qualification. Cleanup is inactive/dead/MainPID0.

Independent post-run artifact closure checks the exact result, unchanged seven
freeze members and scope without repeating the scorer. No private profile/key,
RPC, proof/native execution, funding, broadcast, GPU or semantic rerun occurred.
The [next comparison method](POPULATION-METHOD-DRAFT.md) lists the pending exact
new-format/cost inputs before a representative experiment can be frozen.
