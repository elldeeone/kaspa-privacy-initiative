# Native-KAS privacy under unchanged consensus

**Date:** 5 November 2026 (Australia/Sydney). **Status:** primary-source design
comparison, not a privacy qualification or implemented new protocol.

The owner requires the strongest practical privacy **without any Kaspa consensus
change**. This supersedes consensus-native implementation as the active product
direction. Preserve the recent native-v2/Orchard work as comparative research;
it is not an available current-network transaction/verifier interface.

## Finding

The leading candidate to investigate is a **wallet-held confidential note ledger
backed by native KAS in proof-enforced covenants**, using existing proof hooks.
Compare direct inline-ZK settlement with a based app only where shared-state
contention/batching justifies the additional machinery. Add separately tested
protection for fee funding, recipient delivery, address reuse, transport and
optional cooperative exits. This is an architectural hypothesis, not a claim
that it is globally optimal or already satisfies the full privacy requirement.

Application-confidential claims and confidential native outputs are different.
Current programmable covenants can enforce hidden state transitions while the
reserve remains an ordinary public-value UTXO. They do not require adding a
native shielded output format. Conversely, no application can erase the amount
and script of an ordinary payout it publishes. The useful research question is
how much payment/ownership information remains hidden over the complete
lifecycle under explicit observer knowledge—not whether a published field can
be made secret afterward. [K1], [K2], [K3]

## Current Kaspa source checkpoint

Official HEADs were read on 5 November; no live node, RPC, funds or broadcast
was used:

| Repository | Exact inspected revision |
| --- | --- |
| kaspanet/rusty-kaspa | `4863866fce8439d0305b410fc4d802e7261d54d0` |
| kaspanet/docs | `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` |
| kaspanet/vprogs | `f9b84a863a7c7c20586a9cf947550475e894f72e` |
| zkSNACKs/WabiSabi | `1e6deb989f58bc6edce91bc300252d2bed18db30` |
| bitcoin/bips | `a0c977f3755da6476b955677ca9318334a2432c4` |
| lightning/bolts | `191462825ae341f0a27098765c075f01ca9bc6c2` |
| Railgun-Privacy/contract | `36bcf5ed7cf94bfafb6e1a303e1832c769c16780` |
| cashubtc/nuts | `1363de413294e2ef3a57b16950f9506af38fffc2` |

The official Toccata guide explicitly reports mainnet activation on 30 June
2026 at DAA `474_165_565`. That is a source statement, not a fresh network
qualification or permission for mainnet experiments. It also distinguishes the
consensus features from younger developer tooling. Existing experiments remain
unfunded/testnet-only under repository instructions. [K1]

Rusty Kaspa advanced one commit from the preceding `af6ff23a` checkpoint:
`rpc: add GetTransactionsByAcceptingBlock (#1164)`, changing 28 paths. The delta
adds accepted-transaction discovery and changes UTXO-inquirer/RPC plumbing; the
reviewed output type, proof tags and network-parameter file are byte-identical
between these two commits. This is not a confidential-output feature. [K3], [K4]

The actual supported ZK dispatch remains **Groth16 `0x20`** and **RISC Zero
Succinct `0x21`**. There is no native full Orchard/Halo2 tag. Reusing the recent
Orchard packet unchanged is excluded. A current-rule implementation needs an
existing supported proof path and complete relation/authorization/state/effect
bindings, with genuine end-to-end verification and practical cost evidence.
The past experiments provide bounded starting mechanisms, not a drop-in
complete repaired-Orchard wrapper. [K2], [K5], [H1]

## Candidate comparison

| Candidate | Privacy worth pursuing | Material limitations and disposition |
| --- | --- | --- |
| Wallet-held notes + direct inline-ZK covenant | Hidden note openings and internal value-conserving transfers; local spend authority; no operator withdrawal key. Existing hooks can bind predecessor, successor and actual payout. | Public deposits/reserve value, nullifiers/commitments, activity, fee inputs and exit value/script remain. A shared state UTXO serializes updates. **Leading minimum-trust candidate**, requiring complete privacy/cost/recovery evidence. [K2], [H1] |
| Same private semantics in a based app/vProgs | May amortize proofs and coordinate shared state; batching can reduce per-operation settlement exposure. | Runtime choice supplies no anonymity by itself. Public lane operations must not expose plaintext private facts. Settlement cadence, current-state access, availability and independent settled exits need explicit proofs. vProgs remains a prototype. **Conditional scaling alternative**, not assumed required. [K6], [K7] |
| Equal-output CoinJoin with blind output registration | Can remove an explicit input-to-output assignment from a transaction coordinator and create equal-value output ambiguity for an observer lacking ownership mappings. | Public amounts, recognizable structure, change, Sybils, intersections, timing, later spending and known owners constrain ambiguity. WabiSabi does not itself specify privacy-preserving transaction structure and assumes network privacy. Multi-user coordination can abort. **Boundary-unlinkability comparator**, not a cure for full mapped drainage. [W1] |
| PayJoin-style cooperative payments | Receiver-contributed inputs can undermine common-input ownership and change heuristics using ordinary signed transactions. | Both parties know their payment; public amounts remain; probing, metadata, unavailable receiver and future wallet use matter. Bitcoin PSBT/BIP78 is not Kaspa wire compatibility. **Useful ordinary-wallet comparator**, not confidential note accounting. [P1] |
| Lightning-style payment/state channels | Individual intermediate payments can remain off-chain; onion routing restricts what a forwarding hop learns. | Counterparties see channel state, hops see local forwarding data, traffic analysis persists, and opening/closing outcomes are public. Standard unilateral channel resolution involves monitoring and delayed outputs; liquidity and routing are additional assumptions. **Not a drop-in fit for the retained no-forced-delay/independent-exit requirement**; a distinct Kaspa construction needs source-bound validation. [L1], [L2], [L3] |
| Custodial blind ecash | Blind minting can hide issuance-to-redemption linkage from the issuer under its protocol assumptions. | The mint issues and validates spendable promises and supplies redemption service. Native backing, unilateral exit and authority after mint loss do not follow. **Reject as the product architecture** under current custody/no-new-token constraints; study the unlinkability pattern only. [C1] |
| Native confidential UTXOs or native shielded transaction/header rules | Could move private representation into consensus. | **Excluded by the owner's constraint.** Preserve the previous work; do not spend the next implementation cycle on its importer, transaction versions, header fields or activation. [H2] |

RAILGUN's Solidity contract design is a useful application-layer
analogy: contracts accept shield requests, validate proof-bearing transactions,
insert commitments and mark nullifiers. Its unshield path exposes destination,
asset and amount. That demonstrates the distinction between internal private
accounting and a public boundary; it does not make Ethereum code/Kaspa circuits
interchangeable. Do not import its asset contracts, owner-controlled fees,
upgrade model or tree-scoped spentness as Kaspa decisions. Reuse concepts only
after examining this project's own invariants and exact note identity. [R1],
[R2], [R3]

## The observer models must remain separate

1. **Chain-only observer:** output ownership may be unknown. A private ledger,
   coinjoin structure and cooperative exit registration may hide different
   relations. Measure real financial facts, not merely permutations of unnamed
   commitments or hidden test labels.
2. **Coordinator or infrastructure observer:** include actual messages, input
   registrations, fee funding, network/contact order and data availability. A
   blinded output-registration protocol does not automatically blind every
   other message or eliminate malicious coordinator/Sybil attacks.
3. **Counterparty disclosure and mapped full drainage:** retain legitimate
   knowledge of owners, deposits, payouts and fees. If A deposits 100, withdraws
   59, pays fee 1, retains nothing and has exactly one unknown outgoing payment,
   that payment is 40. No rerouting or witness encryption removes this arithmetic.
   This counterexample does not say every gross payment history is uniquely
   reconstructible. [H3], [H4]

The former private-change/working-balance screen failed its frozen overall
criteria. The later common-reserve mitigation altered funding-origin candidates
but retained the same two gross histories; it was rejected as a payment-privacy
fix. Do not present either mechanism again as a solution without a new,
specifically different hypothesis. The paused MPC construction hid one explicit
map in a bounded case while leaving wider constructor/metadata limitations.
It remains paused; no MPC spending authority is introduced. [H1], [H3], [H5]

The matched historical lifecycle also paid 12.5793% all-in fees against its 2%
target. A different supplied-UTXO layout at approximately 1.85% does not qualify
that lifecycle. Extra exit rounds, larger output sets and credential exchanges
must earn their privacy benefit against total paid costs and participant
availability; none is a free improvement. [H1]

## Next decisive work

**Do a privacy-first comparison before another verifier subsystem.** The leading
architecture already has bounded settlement evidence; the missing product fact
is its best achievable complete-lifecycle privacy under unchanged rules.

- Freeze the same integer-sompi workload, ground truth, allowed disclosures,
  observation surfaces, success metrics and stop rules before evaluation. Keep
  chain-only, coordinator and counterparty/mapped-drainage results separate.
- Compare the existing direct-exit private-ledger baseline with one concrete
  cooperative equal-output/blinded-registration boundary hypothesis and a
  PayJoin-style ordinary-payment control. First reject any design needing new
  consensus rules, custodial authority, mandatory waiting or retained principal.
- The cooperative path must be optional. A user must still be able to authorize
  an ordinary immediate exit without a specific coordinator. Report the privacy
  of that fallback separately; optional waiting for peers is not free privacy
  or guaranteed inclusion.
- Measure payment amount/relationship inference, marginal leakage beyond the
  prior, repeated use, change/recombination, fee linkage, participant disclosure,
  full drainage, actual cost and independent recovery. Report exact failure
  modes and minimal honest-participant assumptions; no generic anonymity score.
- Keep the retained absolute targets unchanged. The existing 21.10% prior-only
  floor against the 20% amount ceiling still disqualifies that population; an
  incremental-leakage comparison is additional research evidence, not a silent
  replacement qualification criterion. [H4]

This note selects a useful comparison, not a proven winner. It authorizes no
funding, broadcasts, rentals, implementation of new cryptography, mainnet action,
new token or restart of paused MPC work. Source facts and historical failures
bound the search; they are not a reason to abandon current-rule privacy work.

## Primary sources

[K1]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/index.mdx#L6-L61
[K2]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx#L5-L94
[K3]: https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/consensus/core/src/tx.rs#L176-L192
[K4]: https://github.com/kaspanet/rusty-kaspa/commit/4863866fce8439d0305b410fc4d802e7261d54d0
[K5]: https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/crypto/txscript/src/zk_precompiles/tags.rs#L5-L21
[K6]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/decision-guide.mdx#L98-L141
[K7]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md#L1-L7
[W1]: https://github.com/zkSNACKs/WabiSabi/blob/1e6deb989f58bc6edce91bc300252d2bed18db30/protocol.md#L1-L95
[P1]: https://github.com/bitcoin/bips/blob/a0c977f3755da6476b955677ca9318334a2432c4/bip-0078.mediawiki#L12-L60
[L1]: https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/00-introduction.md#L24-L47
[L2]: https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/04-onion-routing.md#L1-L30
[L3]: https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/05-onchain.md#L57-L100
[C1]: https://github.com/cashubtc/nuts/blob/1363de413294e2ef3a57b16950f9506af38fffc2/00.md#L12-L45
[R1]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunSmartWallet.sol#L15-L115
[R2]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunLogic.sol#L23-L74
[R3]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Commitments.sol#L23-L53
[H1]: ../docs/RESEARCH-LESSONS.md
[H2]: ../docs/spec/native-shielded/README.md
[H3]: ../docs/rfc/0004-native-kas-private-payment-boundary.md#what-the-completed-run-provesand-does-not-prove
[H4]: rfc0004-privacy-feasibility-review-2026-11-03.md
[H5]: ../docs/research-knowledge/privacy.md
