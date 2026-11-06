# Reusable withdrawal approval: primary-source and reuse record

Reviewed 6 November 2026 against local `44d28516`. This is source/design evidence,
not an executed reusable-approval result or independent cryptography review.

**Recommendation:** test an owner authorization over a fixed withdrawal intent,
while generating a fresh state-transition proof for the actual current bank.
Unrelated activity may leave the economic notes and approved payouts unchanged;
it must not make an old state-transition receipt valid for a new predecessor.
No consensus change, token, privileged exit, admin lock or new cryptographic
primitive is needed for this bounded application experiment.

Read first: [project status](../../docs/PROJECT-STATUS.md),
[RFC-0005](../../docs/rfc/0005-common-set-withdrawals.md),
[security invariants](../../SECURITY-INVARIANTS.md), the
[proof guide](../../docs/research-knowledge/proofs.md),
[regression contracts](../../docs/research-knowledge/controls.md) and
[recovery guide](../../docs/research-knowledge/recovery.md). The preceding
[busy-state result](../withdrawal-request-and-busy-pool-2026-11-06/RESULT.md)
preserves the failure being addressed: unrelated activity invalidates otherwise
unspent owners' full-effect approvals. Its old guest/evidence must remain intact.

## Established mechanism, and what is only our design inference

**Kaspa fact:** ordinary signature hashing binds transaction input outpoints,
input amount/script, outputs, lock time, subnetwork/gas, payload and hash mode.
The function does not sign the chain's global tip. A transaction's economic
input is checked for current spendability separately. This is an analogy for
keeping economic input authorization stable under unrelated activity; it is not
permission to omit the actual reserve input from the final native proof. [K2]

**Zcash fact:** the Orchard transaction anchor refers to an earlier block's final
Orchard tree state; nullifiers must nevertheless remain unique in the valid
chain. Its append-only note tree establishes existence, not current unspentness.
The specification explicitly separates these obligations. [Z1] Orchard's bundle
also binds its anchor, actions/value and authorization; its transaction signature
digests must not be replaced by a cached proof-validity assertion. [O1]

**RAILGUN fact:** V2 validates a seen historical Merkle root and chain/adaptor
context, verifies its SNARK/bound parameters, then checks and inserts the current
nullifiers before unshielding. The current contract warns that validation and
nullification must precede token release. [R1] This is the clearest existing
application-state example for historical membership plus current spentness.

**Local fact:** the unchanged wallet Ledger already permits an operation's
accepted historical anchor and checks current economic nullifiers on every
application. Its EXIT proof authenticates note authority, anchor, nullifier,
value and an opaque destination/context hash. The current batched adapter uses
that hash for exact bank effects, which makes it depend on every state/outpoint
change. [L0], [L1], [L2]

**Design inference:** commit that existing hash field to an immutable intent
describing the authorized economic inputs and complete principal payout set.
The aggregate application proof must separately authenticate actual before/after
state, current reserve outpoint/value and every real native effect. This adapts
established authorization/membership/spentness separation; none of the sources
provides a ready-made Kaspa common-set intent protocol or a proof that this
particular composition is safe.

## Required intent and execution checks

The smallest defensible intent should canonically commit to:

- A distinct protocol/version/network domain and stable pool/config identity,
  rooted in the configured bank origin; the expected wallet verifier and fixed
  fee-refund destination belong to that immutable configuration.
- A round nonce, the complete distinct economic-nullifier set, equal principal
  denomination/count, and the complete distinct canonical payout-script set.
- One aggregate native-fee cap, paid only from the separately accounted allowance.
  Three authorizations of the same cap do not authorize three times that fee.

Each wallet checks that all its expected payouts and amounts are included before
authorizing. Each proof binds its note's own accepted anchor, nullifier, value
and the same full intent hash. Native execution must require exact equality of
the supplied operation/nullifier set with the approved claim set, all current
nullifiers unspent, and exact complete principal payouts matching the intent.
No operator credential substitutes for an owner proof. [L0]–[L2], [R1]

The fresh transition proof computes the remaining reserve, exact fee allowance,
continuation root and terminal/refund branch from current authenticated state.
It must bind its journal to the actual input and all outputs/payload. The native
script must still enforce the expected program image and exact successor policy.
This is required by the current Toccata description, which treats transition
proof validity and installing the proven successor as separate checks. [K1]

Canonical lengths, integer sompi, range/overflow checks and duplicate rejection
remain necessary. Independently canonicalize full claim and payout sets without
publishing a claim-to-payout ownership map. Any ordering flexibility must be
explicit: the intent can describe a set, but the final receipt still binds the
actual ordered transaction. The existing two-public-input wallet relation and
checked submitted-point decoder can be reused; no new setup/relation is implied
merely by changing which domain-separated 32-byte context the wallet approves.
The new application semantics still require a new guest image/new synthetic bank.

## I-6: do not silently change the invariant

I-6 says a proof for one state/lane/sequence/transition set must not replay into
another. Record the distinction explicitly in an ADR and prove it in tests:

| Object | What remains fixed | What must be checked anew |
| --- | --- | --- |
| Owner authorization predicate | Its intended pool/config, accepted historical membership root, economic note/nullifier, value and complete withdrawal intent | Whether that historical root is still accepted, that note is currently unspent, and current execution satisfies every approved constraint |
| State-transition receipt | Exact current before/after state, native predecessor/value, full effects and payload, expected guest/verifier | Native current-input/UTXO validity and the actual installed successor |

The reusable object is an owner consent predicate already anchored to its own
specific historical note state, not a cached assertion that a different current
state transition is valid. A fresh aggregate receipt is necessary after a state
change. Cross-pool/config/claim-set substitution must fail, and a final receipt
must fail against any different predecessor/effects even if those states would
individually satisfy the same owner intent. [K1], [K2], [Z1], [R1]

If the implementation requires weakening I-6 instead of preserving that split,
stop: the invariant's explicit review rule governs. This source review is not
independent approval of an invariant amendment.

## Revocation, fees, changed cohorts and history limits

1. **No off-chain cancellation promise.** A nonce is domain separation, not
   revocation or replay prevention. Dropping a request, changing a local nonce,
   restarting a coordinator or deleting a file cannot invalidate a released
   authorization. An accepted owner spend/rekey consumes the same economic
   nullifier and thereby invalidates the old intent. Until one competing spend
   is accepted, the ordinary race remains. Do not add an admin cancellation key.
2. **Material changes require fresh consent.** A changed payout address/value,
   changed claim/cohort set or fee above the signed cap requires new approvals.
   If one cohort member spends its note, all-participant completion must refuse;
   the other owners may rebuild a group or independently exit. Preserving a
   subset of old approvals for a different group is not authorized by this design.
3. **Repricing is bounded.** Actual native fee may change within the approved cap
   and available fee allowance; owner principal and payout addresses may not.
   Low allowance/cap may reduce liveness, never subsidize fees from principal.
4. **Continuation can become terminal.** Unrelated owners may exit before the
   group. Reusing the same payout intent must safely recompute whether a bank
   successor remains. Pin the refund recipient/config, not a stale reserve value,
   old successor root or old exact output count. Tests must cover both branches,
   zero unused allowance and unexpected/missing/extra outputs.
5. **Accepted anchor retention matters.** If pruning, an epoch policy or a reorg
   removes the approved historical anchor, fresh membership authorization can be
   necessary even for an unspent note. An orphaned note/root is not rescued by an
   old valid proof. Preserve authenticated history/parameters and state rollback
   rules; do not promise indefinite approval validity from a seed/root alone.
6. **Outer proving can still race.** This change saves owner reapproval work. It
   does not permit reusing an old aggregate receipt, remove the single-bank UTXO
   serialization or establish liveness under sustained/adversarial contention.
   Keep discarded outer-proof time and queue/inclusion delay as separate metrics.

These are security/design obligations inferred from the existing current-NF,
historical-anchor, exact-transition and independent-exit contracts, not executed
results. [K1], [Z1], [R1], [M1], [W1], [L0]–[L2]

## Existing-work reuse decisions and fresh upstream pins

All nine official default-branch heads below were resolved read-only via the
GitHub commit API on 6 November 2026 and matched the preceding source record.
The decisive Kaspa signature, Toccata, Zcash protocol, RAILGUN, Aztec, Monero and
MWEB files linked below were read at exact pins. The earlier
[five-protocol review](../native-kas-shielded-value-sources-2026-11-03.md) and
[request/proving sources](../withdrawal-request-and-busy-pool-2026-11-06/SOURCES.md)
retain wider implementation and availability analysis; unchanged heads do not
imply a new audit of every file, deployed version or independent recovery path.

| Upstream / head | Reuse or adapt | Exclude |
| --- | --- | --- |
| Kaspa docs `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` [K1] | Exact program/current-state/native-successor checks | New verifier/output rules |
| rusty-kaspa `4863866fce8439d0305b410fc4d802e7261d54d0` [K2] | Existing native verifier/transaction ABI and ordinary economic-input authorization analogy | Any consensus patch |
| vprogs `f9b84a863a7c7c20586a9cf947550475e894f72e` [K3] | Ordered execution, rollback and batched verification references | Assuming its prototype runtime is mandatory or already production |
| kaspanet/research `c923faca11a49148fa7d912d27ce00197a5c5a4a` [K4] | Ordered authenticated state/accounting references | Treating a research runtime model as deployed code |
| Orchard `616a669df8c9a59c33d47064d3ce04b25d026b2e` [O1], protocol pin [Z1] | Historical note membership plus current nullifiers, separate full-effect authorization | Native Halo2/Pasta/Orchard consensus or a reusable transition receipt |
| Aztec `c03bf6c776bcef428e9247fff8a5c385ab7ae994` [A1], [A2] | User-local private authorization followed by sequencer state/nullifier checks; domain/version context | Its L2, account/PXE/kernel or sequencer trust/runtime |
| RAILGUN `36bcf5ed7cf94bfafb6e1a303e1832c769c16780` [R1] | Seen historical roots, bounded effects/context, validate/nullify before release | EVM custody, admin powers, token asset model |
| Monero `b14fae7bca4099cea56205e44c1005602834b7bd` [M1] | Current spent-image checks within block and chain, separated from authorization | Native RingCT/CLSAG consensus and decoy assumptions |
| Litecoin `ec1b6489a900d09cf5991e220dce089c77a232a2` [W1] | Current unspent input checks, explicit supply/peg-out accounting | MWEB extension-block consensus, confidential native outputs and forced maturity |

No mature source hides ordinary Kaspa output amounts or supplies the missing
independent-user/known-owner financial-privacy qualification. Stable intent
reuse also makes published approvals live longer: retain cohort/nonce/claim-set,
timing, expiry/retry, known-ownership and later-disclosure observations. Do not
assign a larger anonymity score merely because fewer messages were sent.

## Primary references

[K1]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx#L25-L70
[K2]: https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/consensus/core/src/hashing/sighash.rs#L250-L284
[K3]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md
[K4]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex
[Z1]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L4322-L4402
[O1]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/bundle.rs
[R1]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunLogic.sol#L420-L509
[A1]: https://github.com/AztecProtocol/aztec-packages/blob/c03bf6c776bcef428e9247fff8a5c385ab7ae994/docs/docs-developers/docs/foundational-topics/transactions.md#L33-L61
[A2]: https://github.com/AztecProtocol/aztec-packages/blob/c03bf6c776bcef428e9247fff8a5c385ab7ae994/docs/docs-developers/docs/foundational-topics/advanced/storage/indexed_merkle_tree.mdx#L40-L60
[M1]: https://github.com/monero-project/monero/blob/b14fae7bca4099cea56205e44c1005602834b7bd/src/cryptonote_core/blockchain.cpp#L2853-L2880
[W1]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/consensus.md#L73-L107
[L0]: ../../poc/private-note-wallet/src/ledger.rs
[L1]: ../../poc/batched-payment-costs/common/src/lib.rs
[L2]: ../../poc/batched-payment-costs/host/src/proof.rs
