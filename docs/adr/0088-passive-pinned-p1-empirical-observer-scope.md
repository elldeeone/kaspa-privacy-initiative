# ADR-0088: passive pinned-P1 empirical observer scope

**Status:** Accepted for the frozen unfunded privacy measurement only, with the
internal-state clarification in ADR-0098.
It does not authorize execution, funding, Testnet continuation, or a privacy
claim.

**Date:** 2026-10-29

**Related method:** [four-view actual privacy-improvement gate](../../research/next-session/local-private-payment/private-batch-2026-10-28/PRIVACY-ACCEPTANCE-GATE-FREEZE-2026-10-28.md)

## Context

The frozen gate names a `corrupt-server-plus-wallet` view containing “server
1's complete selected shares, MAC state, randomness and authenticated
transcript” plus owner 1's wallet knowledge. That wording needs one exact
observer boundary.

The v9 capture was designed to close the named application-level view of one
exact P1 protocol process: its local scalar and group shares/MACs, MAC-key
share, selected preprocessing state, owner frames, application peer messages,
openings, proof state, and captured execution metadata. It does not image every
byte or physical effect of a host. In particular, v9 does not capture internal
OT/VOLE/PRNG random tape, every query/MSM/checker temporary, arbitrary logs or
allocator copies, swap/core dumps, cache/page/scheduler/CPU/GPU state,
TLS/TCP/kernel/NIC metadata, or a covert channel added by a modified process.

ADR-0098 corrects the consequence of that inventory: P1-known protocol entropy
and state inside the pinned process are part of the frozen observer, not an
optional out-of-scope physical side channel. OT/VOLE/PRNG state, MASCOT branch
and cache state, preprocessing/Beaver material, pending MAC-check state,
proof-randomizer state, and named live query/MSM/checker state must therefore be
directly captured or covered by an independently checked, source-closed exact
replay/correspondence argument. Missing any required family makes the view
incomplete and the trial unqualified. Semantically duplicate allocator bytes
need not be recorded separately only when exact source-grounded correspondence
to admitted state is established. Host-wide physical effects and arbitrary
modified-process behavior remain outside this bounded experiment.

MASCOT's malicious-security theorem quantifies over arbitrary static malicious
computing-party strategies. A trace from one pinned binary is not the complete
view of every such strategy. Calling both things “corrupt P1” without a scope
distinction would overstate the empirical gate.

## Decision

For this empirical gate only, interpret the frozen phrase **complete selected
server-1 view** as:

> the complete admitted view of the exact source-, build-, launch-, role-, and
> attempt-bound instrumented P1 protocol process, following that pinned binary,
> combined with the declared owner-1 wallet view.

This is a **passive corruption measurement**:

- P1 and C1 follow their frozen instrumented binaries and schedule;
- the observer receives every admitted P1 lane, application peer frame,
  opening, abort/retry record, and metadata field required by the selected
  schema, plus C1's declared wallet knowledge;
- P0, P2, owners 0/2, truth scorers, and the observer retain their existing
  separation; and
- omission, unknown schema, incomplete receipt, unmodeled required field, or
  source/build/role mismatch remains `UNQUALIFIED`, never a privacy pass.

“Passive” limits only what this empirical result measures. It does not weaken
the protocol or production threat model. Active P1 deviation, P1+C1 selective
failure, arbitrary modified binaries, host administration, uncaptured or
substituted P1 random state, physical side channels, and covert channels remain
required threats and `UNQUALIFIED`. The candidate source assumptions for
MASCOT/OT, DDNNT, mixed scalar/group multiplication, and final Groth16 prove no
physical-host completeness and remain unselected.

The next immutable run selection must bind this ADR together with the frozen
gate, capture/decoder source, assumption ledger, and source/build/launch
closure. This ADR clarifies the observer population; it does not change the
frozen workload, four views, ambiguity thresholds, truth separation, pass
criteria, or stop rules.

## Active negative evidence remains controlling

The existing active abort/retry diagnostic is not reclassified by a passive
gate. With a changed overlapping known cohort it produced **3/3
owner-verified unique predictions**, while the same-cohort control produced
**0/2**. It is a bounded MPC-wire/admission result, not a financial or network
privacy result, but it demonstrates that active retry/intersection is outside
any positive passive-observer conclusion.

Therefore even a future `PASS_BOUNDED_ACTUAL_PRIVACY_IMPROVEMENT` may say only
that the hidden-mapping candidate improved ambiguity for the pinned passive
observer and workload. It cannot establish active malicious-server privacy,
host compromise resistance, general anonymity, production safety, native-KAS
privacy, or absence of selective-failure/retry leakage.

## Alternatives considered

### Call the captured process an arbitrary malicious P1

Rejected. A malicious host may change code, retain additional state, probe
physical effects, or exfiltrate through channels absent from the selected
capture. A finite trace of the pinned process cannot prove those views absent.

### Remove P1 from the empirical observer

Rejected. That would weaken the already frozen four-view question and could
turn missing cryptographic/server evidence into a false positive.

### Treat theorem simulation as capture completeness

Rejected. A protocol theorem and a source-assumption ledger can conditionally
explain recognized joint mathematical values. They do not prove that the
artifact contains every process/host observation or that metadata is harmless.

## Consequences and admission rules

1. Reports and code must use `pinned passive P1 process plus C1` (or an exact
   equivalent), not an unqualified `malicious/corrupt P1`, for this gate.
2. The global active-malicious-server threat remains unchanged. Any general or
   production privacy claim is blocked while active deviation, internal random
   tape, physical host, network-stack, and covert-channel rows are unqualified.
3. `SELECTED_SOURCE_ASSUMPTIONS` stays empty until the separately reviewed
   source-closed ledger is admitted. Even admitted cryptographic assumptions
   cannot qualify the physical-host rows.
4. Detailed timing, sizes, order, peers/forks, abort phase, partial transcript,
   and retry linkage remain measured observer inputs or explicit unmodeled
   leakage. High-level ideal-world abort does not erase them.
5. Schema v9 also binds the financial-model preimage, query-store preimage,
   scalar-callsite manifest, and each of the 22 selected scalar callsites.
   Those bindings establish source correspondence only; they do not make the
   group/query/MSM implications or mixed peer transcript harmless.
6. The deterministic empirical observer is a candidate-set filter, not a
   stand-alone privacy verdict. Its two structural hypotheses must be bridged
   to every candidate in the frozen four-view/two-round lattice before any
   opaque completion authority can be gate-authorizing. Zero, missing, or
   ambiguous joins retain candidates or make the row unqualified.
7. A future active experiment or stronger deployment boundary requires its own
   prospectively frozen method and ADR. It must retain, not overwrite, the
   active-retry negative result.

## Evidence and references

- [Frozen four-view gate](../../research/next-session/local-private-payment/private-batch-2026-10-28/PRIVACY-ACCEPTANCE-GATE-FREEZE-2026-10-28.md)
- [Prospective measurement method](../../research/next-session/local-private-payment/private-batch-2026-10-28/PRIVACY-METHOD-FREEZE.md)
- [Active-retry experiment record](../../research/next-session/sender-private-lifecycle/review/ACTIVE-RETRY-EXPERIMENT-RECORD.md)
- [Finite corrupt-P1 source-assumption ledger](../../research/corrupt-p1-finite-source-assumption-ledger-2026-10-29.md)
- [P1 MASCOT-view source review](../../research/mascot-p1-view-leakage-assumptions-2026-10-29.md)

