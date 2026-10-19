# Compact-pool practical privacy: source review

Reviewed 2026-10-19 for Stage 2 of the
[branch plan](../docs/SHARED-POOL-PLAN.md#2-practical-privacy). This is a source
review and design assessment, not a new anonymity measurement. The accompanying
transaction audit must establish which deductions apply to the actual artifacts.

**Recommendation:** test the public constraints before simulating traffic.
Delaying an exit while retaining the same authorization cannot make notes created
after its anchor eligible inputs. If the remaining eligible notes share one
creating transaction, that source transaction stays identifiable regardless of
delay. More transactions elsewhere do not repair that particular exit.

## What is implemented here

The compact authorization explicitly serializes its historical commitment count
and root, one nullifier, two output commitments, mode, public payout, fee and
payout script. The proof commits to the complete authorization digest. Its private
position must be below the historical count and its note must belong to that
root. Transfers consume one note and create two notes, both at least 60,000,000
sompi; exits consume the whole note with no private change. Thus an accepted full
exit reveals the input value as payout plus fee. These are application choices,
not requirements imposed by Kaspa L1.
Sources: [format](../poc/shared-pool/src/compact/mod.rs),
[circuit](../poc/shared-pool/src/compact/circuit.rs),
[wallet construction](../poc/shared-pool/src/compact/experiment.rs).

Two deductions follow from these explicit constraints, without breaking the proof:

1. **Historical eligibility:** an anchor containing only the initial note and
   the first transfer's two outputs has only one possible creating transfer once
   the initial note's earlier spend is established. Two possible output notes
   from that transfer still mean one possible source transaction. This does not
   identify either private owner, the exact output commitment, or a real person.
2. **Amounts and topology:** each child of a private transfer is at most its
   parent's value minus that transfer's fee and the sibling's note floor. Along
   a candidate ancestry path, those public minimum losses accumulate. A public
   exit amount can therefore exclude sufficiently deep paths even if a fresh
   anchor includes their commitments. Candidate histories must also obey one
   spend per note and all observed payouts jointly.

An unchanged anchor imposes a ceiling on eligible inputs; delay can still alter
timing heuristics among eligible alternatives when more than one source survives.
Do not generalize the singleton counterexample into a claim that delay is useless
for every workload, or that every compact payment is identifiable.

The [H6 report](../poc/shared-pool/COMPACT.md) already records Bob's count-three
anchor surviving 100 payments. The useful additional decision is whether to keep
that behavior only as an exit fallback and require a different normal privacy
policy. Repeating “old anchors leak” without narrowing that decision adds little.

The [H2 comparison](../poc/shared-pool/README.md) used a different variant with
later deposits and partial withdrawals. It found greater amount ambiguity for
partial withdrawals, but no improvement in unique-source identification for its
selected exits. Those features and measurements cannot be silently imported into
the compact variant. Current compact pools have one initial deposit: an
independently funded multi-deposit workload would be a modeled protocol change;
separate pools are publicly distinguishable and are not one common candidate set.

## The two proposed mitigation policies

| Policy | What it might change | Assumptions, changes and limits |
| --- | --- | --- |
| Bounded randomized withdrawal delay | Reduces a simple immediate-payment/exit timing signal when several compatible sources exist. | Wallet scheduling only; no protocol change or extra native transaction. Requires actual compatible traffic, retained keys/history and sufficient fee validity. Does not enlarge the old anchor or remove exact full-exit values. A delay distribution is an explicit workload assumption, not an established efficacy guarantee. |
| Equal public payouts with private change | Makes a payout differ from its consumed note's full value, and may preserve several amount-compatible inputs. | Not implemented in compact state. Requires changed authorization/circuit, covenant conservation and commitment updates, proof parameters, delivery/scanning and tests. Repeated withdrawals and eventual change drainage add transactions and fees and may reveal constraints later. Cannot by itself repair a singleton historical source. H2 bundled change support with equal payouts; it did not isolate their separate effects. |

No fee estimate for the modified compact covenant is established by H2. The
existing compact transfer/exit fees are measured for the existing layout and fee
rate only. Count all extra operations through eventual drainage when applying
Stage 2's cost threshold; stopping the comparison before change exits is biased.

## Established designs and empirical work

| Primary source inspected | Relevant lesson and reuse boundary |
| --- | --- |
| [Orchard commitment tree](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/commitment-tree.md), [actions](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/actions.md), [ZIP 225](https://zips.z.cash/zip-0225) | Orchard uses a global append-only tree and past block-root anchors. The anchor and net public value balance are serialized; actions pair spend/output slots and hide real arity. Reuse the distinction between membership eligibility and actual anonymity. Our per-transfer historical roots, one real input/two positive outputs, public mode and one-deposit pool do not inherit Orchard's privacy properties. |
| [Kappos et al., USENIX Security 2018, sections 6.3–7](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-kappos.pdf) | Public entry/exit values, timing and distinctive usage can substantially narrow a shielded pool. Their amount/time links are heuristics; private splits/aggregation can invalidate an apparent match. Reuse timing, amount and joint-history attacks, and treat hidden ground truth as scoring data. The historical Zcash percentages are not estimates for Orchard today or this Kaspa experiment. |
| [Möser et al., PoPETs 2018](https://petsymposium.org/popets/2018/popets-2018-0025.php) | Historical Monero analysis demonstrates both elimination across transactions and biased input-age heuristics. Reuse joint consistency and a public-prior comparator rather than equating a raw candidate count with anonymity. Do not import ring signatures, old attack success rates, or a claim about current Monero. |
| [Aztec historical proofs](https://docs.aztec.network/developers/docs/aztec-nr/framework-description/advanced/how_to_prove_history) | Private functions use authenticated past state; historical membership is separate from current acceptance. Archive data remains necessary. Reuse the separation, not the sequencer/runtime or its expiration rules. This documentation is explicitly for Alpha v5.2.0, not a Kaspa capability statement. |
| [RAILGUN commitments](https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Commitments.sol), [wallet](https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunSmartWallet.sol), [unshield description](https://docs.railgun.org/wiki/learn/unshielding-tokens) | Historical roots and current nullifier records coexist; unshielding publicly specifies its destination and value-bearing preimage. A relayer does not erase these chain fields. Reuse that observation boundary; reject any inference that relaying alone guarantees relationship anonymity. No EVM administration, token or relayer requirement is imported. |
| [Litecoin MWEB kernels](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md) | Peg-out amount and destination script are public kernel fields matched to ordinary outputs; native fees are public too. Reuse the distinction between hidden internal values and visible exits. MWEB consensus/aggregation is not a drop-in current-Kaspa mitigation. |

These sources justify the attack families and caveats, not a claim that either
planned policy will meet this branch's numerical target. No RPC queries, IP
addresses, outsourced witnesses or private archive labels belong in the
chain-only attacker. Their leakage requires a separate observer model.

## Current Kaspa and initiative upstream

GitHub heads refreshed on 2026-10-19: Rusty Kaspa
`f7d7877363fb97c2ec6871be0e8cbc351d44df10`, KIPs
`e4ae2332117b5cb68bd6188e065ef885b6d17939`, vProgs
`f9b84a863a7c7c20586a9cf947550475e894f72e`, research
`c923faca11a49148fa7d912d27ce00197a5c5a4a`.
[KIP 16](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0016.md)
and [KIP 17](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0017.md)
are marked Active and specify proof verification and transaction introspection.
The branch's native/SDK pin remains
`01b532e8b553523216471682649693af92f0fd16`; its accepted TN10 experiments establish
the tested layout's execution separately. This review proposes no consensus
change. [vProgs](https://github.com/kaspanet/vprogs/tree/f9b84a863a7c7c20586a9cf947550475e894f72e)
and [Kaspa research](https://github.com/kaspanet/research/tree/c923faca11a49148fa7d912d27ce00197a5c5a4a)
have not advanced beyond the H6/H7 source review; an operator runtime is not needed
to change the anchor chosen by this wallet.

Initiative upstream advanced to
[`40b39a6`](https://github.com/olafweller/kaspa-privacy-initiative/commit/40b39a6503d2133da93b9dd7e77a5a1ee8652658).
[PR 54](https://github.com/olafweller/kaspa-privacy-initiative/pull/54) reports an
actual TN10 lifecycle with four outer proofs; it explicitly leaves production
privacy and independent custody/recovery unproven. Its
[wallet public statement](https://github.com/olafweller/kaspa-privacy-initiative/blob/40b39a6503d2133da93b9dd7e77a5a1ee8652658/poc/private-note-wallet/src/protocol.rs)
includes anchors, nullifiers, output commitments and public deposit/exit/fee
fields. This is a different pipeline, not validation of our compact candidate.

[P13](https://github.com/olafweller/kaspa-privacy-initiative/issues/13) remains open,
with no comments as of this refresh. It asks for timing, amount, RPC, network and
wallet correlation analysis with confidentiality separated from anonymity.
Current [RFC 0001](https://github.com/olafweller/kaspa-privacy-initiative/blob/40b39a6503d2133da93b9dd7e77a5a1ee8652658/docs/rfc/0001-state-architecture.md)
compares direct pools, shards and based apps, leaving low-activity privacy open;
[RFC 0002](https://github.com/olafweller/kaspa-privacy-initiative/blob/40b39a6503d2133da93b9dd7e77a5a1ee8652658/docs/rfc/0002-shielded-payment.md)
separates public intent, private witnesses and delivery/scanning. These are useful
comparison requirements, not authority to adopt that architecture or wait for a
maintainer decision.

## Narrower decision if the initial audit fails

**Can optional fresh authorization against a recent common anchor remove a
deterministic source link while keeping the old proof as an independently usable
exit fallback?** First evaluate compatible histories against the same public
trace with the two anchor policies. A new anchor requires a new private proof
under the current relation; it needs no extra native transaction or L1 change.
Record proving/startup work separately from settlement cost. Never pretend that
the exact old proof has acquired a larger candidate set.

If values and one-input split structure still force one source, stop that policy
study too. The next design question would concern the note/withdrawal relation
(for example, whether supported aggregation/change is required), with its own
RFC/ADR before code. Do not purchase a better-looking score with invented
background users or relabel self-generated notes as independent participants.
No further funded privacy run is justified until a bounded offline comparison can
actually select a design.
