# Existing batching: useful alternative, not a measured cost pass

The direct route's six-verifier floor is not a lower bound for every current-L1
design. The old system already verifies public wallet proofs inside a RISC Zero
guest and submits one outer Succinct receipt. The
[real prior receipt](../../poc/private-note-proof/gpu-2026-10-18/RESULTS.md) and
[four-receipt lifecycle](../../poc/private-native-proof/gpu-2026-10-18-02/README.md)
are evidence of that mechanism, not receipts for this new common-set relation.

The current native `R0Succinct` tag costs 250,000 compute mass before proof-specific
and script/transaction overhead. As **hypothetical arithmetic**, one/two/three
such base checks at 100 sompi/mass cost 0.25/0.50/0.75 KAS. Against this workload's
30-KAS useful denominator and 0.60-KAS 2% ceiling, two base checks leave only
0.10 KAS for every other cost, while three already exceed the ceiling. This is
neither an achieved two-batch lifecycle nor a fee quote for a complete receipt.

There is a concrete integration blocker, not a missing cryptographic primitive:
the old native operation parser in `poc/private-note-chain/common/src/lib.rs`
requires `destination(key) == statement.exit_destination`, where `destination`
is SHA256 of the standard destination encoding. It exports individual permission
leaves. A common full-effects digest does not satisfy that contract. Reusing the
old image/receipt or dropping the destination check would be incorrect.

A shared-path adaptation must prove accepted prior state, current spentness,
all common-set authorizations and exact native payout/successor effects, while
retaining an independently executable exit. Its newly compiled guest needs its
own genuine complete receipt, native validation and full cost accounting.
Proving cost, availability, latency, funding/permission transactions and solo
cost must all be counted. Batching cannot be assumed to take two settlements,
erase service-origin links or provide independent honest participants.

Conclusion: **direct checking failed cheapness; existing batching is still a
plausible current-rule route, unqualified for this replacement.** It supports
contributing the ownership mechanism to the shared investigation. It does not
justify replacing the shared architecture, claiming that current L1 cannot be
cheap, restarting paused MPC, or building another general prover subsystem.
