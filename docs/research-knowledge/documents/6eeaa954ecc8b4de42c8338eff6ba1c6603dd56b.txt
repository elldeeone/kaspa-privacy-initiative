# Common payout policy: source refresh

Read before H17 implementation, 2026-10-20 UTC. The change is a wallet-policy
experiment on the existing v6 partial-withdrawal relation, not new cryptography.

- Kaspa KIPs head `e4ae2332117b5cb68bd6188e065ef885b6d17939`;
  [KIP-17](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0017.md)
  supplies the covenant context. Rusty Kaspa head is
  `4edcbbccb449f84832afb1ca157904b35f37d006`. This experiment continues to
  validate against Cargo's pinned `01b532e8b553523216471682649693af92f0fd16`,
  not an assertion about all current deployments.
- [vProgs covenant](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/script.rs)
  and [research design](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex):
  no runtime/operator component is needed to vary this existing payout field.
  Reject a runtime migration as unnecessary to answer this bounded question.
- Initiative head `05ea24a5cdb89ba5dd2cfec1041b1e69fa8de68d`;
  [P13](https://github.com/olafweller/kaspa-privacy-initiative/issues/13)
  separates confidentiality from chain/amount/timing/network leakage.
  [PR55](https://github.com/olafweller/kaspa-privacy-initiative/pull/55)
  adds local user recovery and a terminal-policy fixture; its description
  explicitly does not establish general custody, archive availability or an
  integrated new terminal permission proof. It does not answer H17.
- [Orchard actions](https://zcash.github.io/orchard/design/actions.html):
  reuse the motivation for padded spend/output shapes, without equating that
  shape to anonymity. Existing v6 padding and conservation remain unchanged.
- [Aztec notes](https://docs.aztec.network/developers/docs/foundational-topics/state_management):
  reuse owner-held encrypted notes and unlinkable nullification as the intended
  private boundary; inference still exploits public cashouts and known records.
- [RAILGUN wallet](https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunSmartWallet.sol):
  unshielding and nullification coexist with private retained commitments.
  Adapt the observation boundary, not its token/EVM/admin infrastructure.
- [Monero RingCT](https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/ringct/rctSigs.cpp):
  confidential amounts inside a domain are a different property from hiding a
  visible native boundary payment. Do not import decoy rings or make a
  comparative anonymity claim.
- [MWEB peg-outs](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md):
  the native boundary exposes amount and destination. Retain that limitation;
  no consensus extension is proposed.
- [Kappos et al., USENIX 2018](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-kappos.pdf):
  amount/timing and known wallet behavior can identify shielded-pool usage.
  Adapt the demand to test complete histories and client assumptions. H17
  tests this particular compact design, not a new general privacy theorem.

Existing [v6 specification](../docs/rfc/0011-two-input-private-payments.md),
H14-H16 observations and immutable local evidence provide the exact fields,
fee/floor conventions and baseline. Common payouts are established policy
ideas; the unresolved local decision is whether their private remainders and
extra fees leave any benefit after this pool is fully drained.

Follow-up during execution: the
[SDK comparison](https://github.com/kaspanet/rusty-kaspa/compare/01b532e8b553523216471682649693af92f0fd16...4edcbbccb449f84832afb1ca157904b35f37d006)
contains nine commits, including client compute-commit/mass changes, paginated
UTXO APIs and `no_std` refactoring. It is not merely the latest TLS commit.
H17 deliberately does not upgrade its native dependency during a frozen
comparison. Its fees are exact selected debits under the pinned v6 profile,
and its native validation result applies to that pinned build. Qualification
against a newer SDK or live relay policy remains separate work.
