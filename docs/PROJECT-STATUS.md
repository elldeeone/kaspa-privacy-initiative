# Project status — 3 November 2026

**Real native test-KAS payment and recovery experiments work. The complete
financial-privacy, cost and independent-recovery requirements remain unmet.**

This is the current entry point for the research fork. Read the
[lessons and corrections](RESEARCH-LESSONS.md) before interpreting an old result,
and the [prior-knowledge guide](research-knowledge/README.md) before extending a
researched component. It includes local source text, task guides and explicit
reuse decisions from every audited branch. The [history index](RESEARCH-HISTORY.md)
records the preserved lineages.
Upstream `main` remains a separate baseline at `7ffe8353`.
The fork's GitHub default is `research/native-kas-withdrawal-privacy`.
The [remote cleanup](research-history/remote-retirement-2026-11-03.json) retired
the 13 old branch names after verifying their pushed archive tags.

## What is demonstrated

| Capability | Strongest relevant evidence | Limit |
| --- | --- | --- |
| Proof-authorized native deposit, transfer and withdrawal | The [depth-four TN10 lifecycle](../research/full-drainage-executed-lifecycle-2026-11-01/RESULT.md) completed two deposits, three transfers, five owner exits/payouts and seven settlements. | One bounded trial; same-host wallet processes, experimental setup and retained chain observations. |
| Private receiving and re-spending | [Continued private spending](../research/wallet-local-private-spend-2026-11-01/RESULT.md) used genuine proofs and restored owner backups. | Offline fixtures; later cashout defeated some earlier privacy. |
| Recovery and independent exit mechanisms | [Upstream recovery](../poc/recovery-tn10/live-2026-10-20/README.md), finite [A1 physical-loss recovery](poc-a1-official-trial-2026-10-08.md), and later source-bound experiments in the history index. | These test different failures and profiles. None establishes the complete N-user/all-service-loss requirement for one current design. |
| Direct-L1 and Based App feasibility | Direct self-funded trials and the [scoped Based App conclusion](based-app-feasibility-2026-10-17.md). | Feasible components do not select the production architecture. |

Successful depth-four attempt 06 ended with zero user principal, private
liability, pending deposits, unpaid exits and permission rent. Its separate
100,000,000-sompi state rent remained. Earlier attempts are separate: the
retained 2 November inventory recorded 550,000,000 sompi of reserve principal
across halted attempts 02–05. No fresh balance check or recovery is claimed here.

## What still blocks the goal

1. **Financial privacy.** Known-owner transparent withdrawals can expose earlier
   payment amounts/relationships through conservation. Private change and reserve
   consolidation did not provide the required durable fix. The corrected live
   model retains two complete gross histories while disclosing some payment facts.
2. **Complete costs.** The 27 October six-payment/nine-exit benchmark paid
   264,166,000 sompi on 2,100,000,000 useful sompi: 12.5793%, against 2%.
   A different offline two-recipient layout had favorable costs; it does not
   qualify the matched lifecycle benchmark.
3. **Independence and availability.** A seed, state root and old valid proof do
   not replace the exact public parameters, ciphertexts, accepted history and
   independent infrastructure needed to recover and make a new exit proof.
4. **Reproducibility.** The 11 reproduced historical remote-tooling failures
   are repaired and the configured fast-check suite passes. Full independent
   availability and production qualification remain separate open requirements.

## Research decision

[ADR-0100](adr/0100-research-consolidation-and-privacy-boundary.md) accepts the
consolidation and preserves the existing strong privacy requirement. It does
not accept a production architecture. [RFC-0001](rfc/0001-state-architecture.md)
and [RFC-0004](rfc/0004-native-kas-private-payment-boundary.md) remain open.

Wallet-local proofs and direct inline-ZK settlement remain the minimum current-
Kaspa reference for confidential on-domain activity and independent transparent
exits. That reference does not meet the stronger known-owner/full-drainage goal.
Hiding a completed boundary requires a consensus-recognized confidential or
shielded native-value representation; changing a prover, MPC committee, relayer
or runtime does not change ordinary native output fields.

MPC/private-construction work remains frozen at `4d54dc02`, preserved by the
`archive/2026-11-03/research/shielded-kas-feasibility` tag. Its bounded
three-owner construction result is valuable, but its separate registered W1
aggregate path remains incomplete and constructor-visible. Preserve its rejected
vendor patch as rejected local work.

## Next deliverable

Produce a source-bound requirements/specification review for native confidential
or shielded KAS outputs: identify affected serialization, value conservation,
supply accounting, proof verification, fees, pruning/discovery and recovery
rules; reuse established protocol mechanisms; compare them with the current
transparent-exit reference. Clearly distinguish staying shielded from later
conversion into an ordinary transparent output.

Completion requires an explicit capability/assumption table and unresolved
questions suitable for specialist review. It requires no new application
framework, MPC integration, proof campaign or funded demonstration. A narrower
privacy claim would require an explicit owner decision; this consolidation does
not make that change.

## Consolidation verification

The [preservation receipt](research-preservation-2026-11-03.md) binds all original
branch tips and privately preserved unfinished files. The original research
results and corrections remain unchanged. Focused scoring controls were rerun:
11 live-scoring tests, 17 role-conditioned assertions, 20 correction controls
and 21 private-change controls passed.

The [final verification receipt](research-history/verification-2026-11-03.json)
records the configured fast-check result: 179 Python cases (177 passed, two
pre-existing native integration checks skipped because their explicit local
configuration was not supplied), 13 Node tests and the read-only/preparation
checks passed. The
[repair record](../poc/remote-cuda/CONSOLIDATION-REPAIR.md) explains the historical
source closures and real process-group deadline controls. Old proof/binary pins
and SECURITY-INVARIANTS.md remain unchanged.

The first consolidation [archived](research-history/consolidation-2026-11-03.json)
21 completed local branches and worktrees. The subsequent
[knowledge consolidation](research-history/knowledge-2026-11-03.json) brings
2,326 committed document revisions and 15 unfinished research notes onto this
branch, with a complete 369-commit ledger and offline coverage checks. The old
feasibility branch name is retired; its exact tag, paused detached/locked
worktree and rejected patch remain preserved. Two local branches remain:
upstream `main` and this active research line.
The [knowledge verification receipt](research-history/knowledge-verification-2026-11-03.json)
records standalone read/search checks, missing/corrupt coverage failures,
cross-checks of all 369 original document trees and the passing configured fast
suite. The documentation workflow validates the library without changing the
historically pinned fast-check script.
The [official source-head refresh](research-history/upstream-2026-11-03.json)
confirms the consensus/output boundary's reviewed source identity; it is not a
fresh runtime qualification.

No production-safety or cryptographic-correctness conclusion follows from tests.
