# Proposed decision: ordinary1600, paired1700 operational budgets

Status: PROPOSED, subject to independent source-bound review and actual native qualification. This note does not change or accept a policy default. The historical S7 policy remains BUDGET1700 and all closed evidence remains immutable.

Problem: the genuine S7 ordinary bodies at1700 have compute/mining mass200,511 (bootstrap and either alternative SPEND fork) or201,631 (ADMIT). Their fixed40M authorization fails the rate200 scenario by102,200 or326,200 sompi. The paired body remains a separate80M authorization at1700.

Proposal: qualify an ordinary-only ComputeBudget1600 operational commitment while leaving paired1700, the24,576-byte immutable union,11-byte envelope, profile/VK/image, public statements, existing proofs, ciphertexts, values and40M/80M fees exact. First use an additive parametric checker over existing genuine public transactions; do not edit the factory or reprove anything. A later adoption requires its own reviewed source diff and validation against this prospective packet.

The candidate changes only transaction input0's typed version1 ComputeBudget. Source shows BUDGET is used in the two factory input constructors, not the redeem emitter. Native version1 ID and SIG_HASH_ALL exclude the compute commitment; full transaction hash includes it. Qualification must verify these properties on the actual transactions, including every unchanged ADMIT funding signature and storage commitment.

Expected consequences, still predictions for1600: compute mass falls exactly10,000; bootstrap/SPEND become190,511 and ADMIT191,631. Their rate200 necessary fees become38,102,200 and38,326,200, below unchanged40M. Rate500 remains negative. The fixed40M fee, note-floor/percentage economics, privacy limitations and existing pair500 failure are not fixed by this change.

Required evidence: re-derived source bound for every successful ordinary reserve-input branch; four actual genuine cases (bootstrap, ADMIT, two alternative same-predecessor SPEND forks); paired1700 unchanged regression; exact field/ID/signature/storage/redeem/SPK preservation and deliberate fullhash change; direct official isolation→Full, actual per-input metering and source-adapted mass/standardness/fee checks; typed semantic, meter and capacity/predecessor controls. Inputs/source/binary/resource plan must be frozen before execution and independently reviewed.

DRAIN remains source-bound-only in this fresh profile. No fresh DRAIN proof, owner CLI, public ledger replay or owner/exit workflow is introduced. The alternative SPEND forks are never combined into a claimed ledger. Native cases use declared public UTXOs, not accepted-chain ancestry. No funds, RPC, broadcast, setup or new proving is required.

Reject or defer adoption if any unchanged-body invariant, source bound or valid candidate case fails. Retain the failure and1700 history. Do not compensate by changing fees, authorization fields, proof material or guards. Resource limits and successful sample measurements are not substitutes for the source bound or native verifier.
