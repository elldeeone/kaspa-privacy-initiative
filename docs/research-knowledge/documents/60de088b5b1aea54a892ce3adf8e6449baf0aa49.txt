# Independent static review of the frozen finite model

Verdict: **no source or enumeration blocker within the stipulated ideal observer model**. The observer naming needs the append-only clarification below. Preserve the original inputs, source, expectations and retained run.

Reviewed through unchanged helper09:

- `privacy-next/model/run_model.py`: `fe89cee8847733f960407c3edf8e0bc64ff0f27cc7fd5d49e9fa8d7f5cb43a18`.
- `INPUTS-01.json`: `503d77c6250ad898e1aea5a38d019d2350d03e6b32205a292068d318180e3fc5`.
- `MODEL-FREEZE-01.md`: `cb42ca26f45a1925b0ff58708e40fff3c10d6ebdc65030465df12fdfd26452cc`.
- `SOURCE-MANIFEST-01.json`: `4d8e95975600dd91494cec901669cfccba61e0389f4e27a585fe2e77c2bcc3d6`.
- Design memo: `5825670bd730a4ff65c39e40068d1f6676c93a0a8a370d535f44cf9eede6fe2e`.

The reviewer and independent child did not import, compile, parse an AST from, run or test the model. The following counts are manual combinatorial derivations. No private content, network or financial operation was used. Root's separately retained run is not a reviewer rerun.

## Enumeration and the question measured

The solver exhausts NF-to-owner bijections and unordered, disjoint two-output assignments. Each complete world appears once: NF permutations are unique, output combinations are unique, owner order is fixed, and the recursion requires complete output coverage. Public tuple components are uninterpreted symbols; their contents supply no additional ownership constraints under this model.

For one hidden ABC release, the ledger-view count is `3! × 6!/(2!³) = 540`. Fixing C's NF and two outputs leaves `2! × 4!/(2!²) = 12` active-view worlds. Public pair/Delta links leave only the owner permutation: six ledger worlds or two active worlds. Plain active framing reveals all ownership, leaving one. The two-server reconstruction control also leaves one by explicit assumption.

With ABC followed by ADE, the intersection contains one NF and two complete outputs. The two first-only NFs each select a pair from four first-only outputs; the second-only group has the same structure. Thus the ledger-view count is `5! × 6 × 6 = 4,320`. Named cohorts plus C's disclosed material fix A and B; D/E retain two NF assignments and six output partitions, giving twelve active worlds. Same-cohort repetition preserves 540/12. Retained reorg knowledge gives the same changed-cohort counts.

The fifteen cells therefore total `575 + 1 + 552 + 4,332 + 4,332 = 9,792` worlds, matching the freeze. These are consistency counts, not measured probabilities or anonymity entropy. Counts across different owner universes are not directly comparable as privacy scores. The emitted marginals are necessary: twelve changed-cohort active worlds still leave A's NF and exact output pair unique. The ledger-view intersection links a particular NF to its pair without necessarily learning its owner's name.

Both channels are present. Source lines139–154 compare full appearance signatures for NFs **and** complete output tuples across every released batch. The enumerator receives only its view, rather than the fixture's private assignment or receiver/value openings. Distinct output tuples and exact durable reuse are explicit fixture assumptions; this does not impose global CM uniqueness on the existing protocol.

## Observer clarification required for claims

The compact name `O-ledger` must not be read as confirmed-ledger-only. `make_view` lines65–79 supplies every released candidate, including ABC rejected before acceptance and data retained after reorg. The design memo already includes public transactions/mempool and reorg history at lines31–35 and distinguishes public egress from acceptance at lines164–169.

Append this limitation to reports: **the modeled observer sees both released candidates, including rejected or orphaned candidates, and retains that knowledge**. Cross-attempt linkage is conditional on this visibility. The model does not show that a confirmed-ledger-only observer sees a rejected candidate that was never publicly disclosed. No source, schedule, expected count or baseline rerun needs changing to record that boundary.

## Authorization and control limits

`accept_batch` enforces the stipulated exact approved-intent oracle, current modeled head, unspent NF, two outputs, per-intent integer conservation and output-authority uniqueness. `direct_exit` checks the modeled authority, destination and current-head oracles before cloning and updating state. The stated backing equations are algebraically preserved by these finite transitions.

Most tuple, recipient, fee, anchor and range mutations reject first at the exact-approved-intent comparison. They demonstrate rejection under that ideal consent oracle; they do not independently isolate every downstream predicate or validate a cryptographic circuit.

`reject_case` snapshots and compares `initial`, including when the operation targets `accepted` or another post-exit state. Current transition code clones state before mutation, so no present mutation bug was found. Those assertions alone are not a comprehensive atomicity proof for every target state. Keep that test-coverage limitation explicit; do not retune the completed baseline.

Proof validity, share opacity, decryption, backup derivation, accepted-state authenticity and traffic suppression are ideal oracles. Recovery and server-loss results are conditional table-based statements. This review supplies no native, cryptographic, network, actual recovery, paid-fee or production validation. The old 21-KAS 2% fee failure and prior frozen privacy evidence remain unchanged.
