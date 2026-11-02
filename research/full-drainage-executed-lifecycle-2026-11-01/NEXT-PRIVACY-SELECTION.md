# Frozen reserve-lineage privacy experiment

**Freeze date:** 2026-11-02  
**Scope:** offline analysis of successful TN10 attempt 06; no network mutation.

## Attacker and evidence

The baseline attacker is an offline observer of the retained accepted TN10
transaction bodies. It may use transaction inputs, outputs, values, scripts,
covenants, payloads, accepted order and outpoint ancestry. It does not receive
wallet files, private execution truth, witnesses, orchestration filenames or
unmeasured IP/RPC origin.

Three views remain separate:

1. `chain-only` names deposits and exits by public identifiers only.
2. `known-owner` additionally receives the already-declared deposit-owner and
   exit-destination mappings.
3. `participant` receives only that participant's own mappings and own payment
   relationship/amount. It is not given other users' private facts.

Public withdrawal facts are not scored as reconstructed private payments.
Inference about other people's funding origins, relationships and amounts is
reported separately.

## Frozen hypothesis

`H-reserve-lineage`: the actual selected-reserve policy and payout transaction
shape preserve two observable deposit-reserve ancestry chains. Under the
known-owner mapping, those chains uniquely select the actual three-payment gross
history from the two corrected balance-compatible histories.

Cause classification, if confirmed: native UTXO/reserve-selection policy. It is
not a cryptographic commitment failure, fee-sponsor inference, participant side
information or MPC problem.

## One candidate mitigation

Model one value-conserving consolidation of the two authenticated deposit
reserves into a single common reserve before any exit. Every later payout spends
the common lineage and returns any reserve change to that same lineage. This is
a synthetic local replay because the executed chain cannot be changed and the
current covenant has no reviewed reserve-consolidation path.

The model adds no cover value, forced delay, withdrawal lock, retained user
balance, privileged withdrawal signature or MPC. All five exits remain
immediately payable in their observed order and the common reserve must drain
from 200,000,000 to zero sompi exactly.

## Predictions and stop rules

- Seal predictions from public evidence before reading `private/truth.json`.
- Baseline success requires one known-owner gross history, with execution truth
  retained after the seal.
- Candidate improvement requires at least two known-owner gross histories,
  execution truth retained, and ambiguity in an actual other-person relationship
  or amount—not merely an outpoint label.
- Chain-only and truthful-participant views must be reported even if unchanged.
- The corrected false `M -> S` evidence must remain unique-wrong, and the
  corrected sparse known-owner control must remain unique.
- A changed public amount, broken reserve conservation, missing payout,
  duplicated outpoint, or truth read during prediction rejects the run.
- Stop after this candidate. A positive model does not authorize covenant or
  protocol implementation; that would require a separate RFC/ADR and value-path
  security review.

Passing this experiment is bounded evidence about one retained transcript, not
production privacy, cryptographic correctness or a universal anonymity metric.
