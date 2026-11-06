# ADR-0108: Bound the real-wallet withdrawal integration and cost test

Status: accepted for the owner-authorized offline test, not a product architecture.
Date: 5 November 2026.

Use the existing depth-four private-note wallet, recipient encryption/discovery,
economic nullifiers and Ledger kernel. Execute deposit credit, private payment,
recipient re-spend and terminal withdrawals. Preserve all old profiles/evidence.
No consensus change, new asset, custody key, funded trial or MPC work.

The old EXIT destination is publicly proof-bound. The replacement explicitly
interprets that field as the common complete-effects digest in a new finite
native policy; it is not an ordinary destination and cannot use old permissions.
All owners check their actual entire entitlement before proving. Solo branches
and exact smaller-subset backing remain mandatory.

Reuse the complete wallet circuit with one isolated input-packing change:
SHA256 of the canonical 410-byte statement, represented by two 128-bit limbs,
replaces its fourteen public limbs. The original statement is still public;
every original ownership, membership, nullifier, range, conservation and delivery
constraint remains. The native script must reconstruct and hash that entire
statement from its policy and actual transaction. New setup/VK; old engine and
sources remain untouched. Record an exact source transformation and differential
constraint controls. This is established digest binding, not a new primitive.

The finite reserve starts at the actual executed wallet kernel's final root and
three eligible nullifiers, with all prior nullifiers excluded. Its supplied
native UTXO is not an authenticated chain deposit. Test native predicates and
label global spentness as a local UTXO model. No full-node/chain claim.

Freeze workload, observers and cost stop rules before fresh generation. Test
actual registration messages with real wallet eligibility proofs. Keep all public
ledger operations and native bytes in the observation. Quantify complete-route
cost lower bounds separately from exact withdrawal quotes and paid fees. If even
the optimistic route floor fails the existing 2% target, report failure at that
price/workload; do not start a general aggregation/prover programme.
