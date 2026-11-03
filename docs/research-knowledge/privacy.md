# Privacy lessons

[Knowledge guide](README.md) · [Authoritative corrections](../RESEARCH-LESSONS.md)

## What earlier studies closed

| Study/mechanism | Lesson for the next study | Local source |
| --- | --- | --- |
| Repeated compact payments and saved exits | A small proof and successful native exits do not establish payment privacy. Historical anchors, repeated resources and withdrawal policy disclose structure. | [research journal](documents/a99d0c7618070857506be9bfaa31780dadf32d56.txt) |
| Independent funding and equal net deposits | Separate wallet funding and equalized net deposits do not by themselves erase later conservation/linkage information. | [research journal](documents/a99d0c7618070857506be9bfaa31780dadf32d56.txt) |
| Two-input payments, known spending rules and full drainage | Evaluate complete payment histories over the whole lifecycle; an early larger candidate set can collapse later. | [research journal](documents/a99d0c7618070857506be9bfaa31780dadf32d56.txt) |
| Participant disclosure | Legitimate counterparty knowledge is part of the observer model, not an attack excluded after scoring. | [participant-disclosure study](documents/bd8f75b9b970b58f9f777314514847c5e8999829.txt) |
| Native address reuse and separated keys | Ordinary script reuse discloses links; funding/exit key separation addresses that channel, not all timing/value channels. | [address-reuse diagnostic](documents/2571bc032d3c4d3c2c5e55d3264d482b887ca351.txt) |
| Native usage privacy | Distinguish hashing/commitment uncertainty from financial facts visible from native activity and wallet behavior. | [native-usage privacy study](documents/6bd0a18e12b5dc1ecffbae996e9d13b3f761517a.txt) |
| Common payouts and independent schedules | Keep overlap-cell improvements and timing-aware failures separately; do not promote one improved cohort to a policy pass. | [research journal](documents/a99d0c7618070857506be9bfaa31780dadf32d56.txt) |
| Working balances and partial withdrawals | The frozen selected policy failed; retain the mechanism and negative evidence without adopting the policy as a cure. | [working-balance screen](documents/c8f4c9560f157dce4e97190cadeba02133070b6f.txt) |
| Price guessing | A failed heuristic does not establish privacy. Preserve the prior-only baseline and the tension between the known prior and the unchanged absolute target. | [price-prior calibration](documents/567b363e0c6151c6d5754b7f79296cc81507a4ba.txt) |
| Owner-map construction and Tor delivery | Hiding an explicit map in one construction or using an owner-origin transport is narrower than network anonymity and completed-payment privacy. | [paused handoff](documents/8afbd3d859a68dc4d80194cbdc3f0cc36e5e9961.txt) |

## Current corrections override older pass language

The [current lessons](../RESEARCH-LESSONS.md) carry three distinct analyzer
corrections: inserted known answers, hidden-label ambiguity counted as privacy,
and a live observer's wrong contact edge excluding execution truth. They also
record why private change and common-reserve funding did not supply a durable
known-owner/full-drainage fix. Read those corrections before any old score.

The current corrected finite live model retains two complete gross histories,
while disclosing some payment facts. Neither general uniqueness nor a financial
privacy pass follows. Confidential on-domain activity and a later conversion
into ordinary transparent KAS are separate observation boundaries.

## Carry into the next experiment

Freeze the observer's legitimate knowledge, workload/truth commitment, target,
amount grid, priors, metrics and stop rule before scoring. Score observable
roles/events and verify hidden-label renaming leaves the financial score
unchanged. Require the complete candidate history to retain execution truth.
Separate value/relationship disclosure from commitment-position ambiguity.

Use fresh controls that remove a claimed privacy mechanism, challenge assumed
contact edges and expose participant knowledge. Report search/resource limits
as limits, not privacy evidence. Operational rules for new trials come from
current AGENTS.md, not superseded frozen approval procedures. These principles
carry forward [adopted payment requirements](documents/ebe24ffeae63c107e173773daa75e63cebf02b2e.txt) without silently retuning an adopted threshold.
