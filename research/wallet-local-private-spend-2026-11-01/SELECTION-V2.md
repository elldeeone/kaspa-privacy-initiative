# Frozen correction: continued-private-spending experiment v2

**Freeze date:** 2026-11-01
**Experiment identifier:** `wallet-local-private-spend-v2`
**Supersedes before execution:** `SELECTION.md` SHA-256
`27c148987324615e544380750ee0d80f11195eed34790d33f4ee776249df2e9c`

No fresh wallet, assignment, operation, observation or prediction existed when
this correction was frozen.

## Correction

The first freeze disclosed exact intended P1/P2 amounts. Because the selection is
public repository material, those values would be public observer evidence rather
than hidden payment amounts. The v1 amount rows are not executed.

Keep its public deposit values and every other capacity, arm, assignment,
observer, attack, metric, threshold, control and stop rule. Replace only the P1/P2
selection with this owner-local preregistration:

1. before wallet or observation generation, create a `0600` private workload file
   outside the repository;
2. for each pair, draw P1 uniformly in integer sompi from
   `[200,000,000, min(A deposit, B deposit) - 100,000,000]`;
3. draw P2 uniformly in integer sompi from
   `[50,000,000, P1 - 50,000,000]`;
4. require the two pairs' `(P1,P2)` values to differ; redraw the second pair only
   on exact equality;
5. publish only the workload file's byte length and SHA-256 before wallet creation;
6. pass the file to the runner as private runtime input; never copy its values
   into source, public observations, service captures, predictions or public-safe
   scores;
7. reveal it only to the post-seal scorer through the private truth boundary.

The observer knows positive-output/conservation semantics and the public deposits,
but not this study's sampling bounds or workload file. Candidate amounts must be
derived from protocol constraints and admitted exit evidence, not from either
selection document's example or private workload values.

This file and the superseded freeze together are the immutable v2 design. The
v1 exact payment values are explicitly invalid for v2 and must not be used as
predictions, controls or fallback values.
