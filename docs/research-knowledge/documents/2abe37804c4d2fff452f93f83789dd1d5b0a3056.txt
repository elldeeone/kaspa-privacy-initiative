# Next native exit-delivery benchmark: proposed frozen scope

**2026-10-26 UTC. Source/design only; await Root implementation GO.** Existing
ADR-0039/RFC-0019 cover this bounded offline research. No native architecture,
financial profile, circuit, key, live trial or fee/privacy target is selected or
changed. The completed finite model and its results remain unchanged.

The useful next measurement is a real native two-ticket claim comparison, with
an **ideal, legitimately preauthorized and fully funded checkpoint**. Current
primitives do not disprove it. Shared-outbox should not be the default: a
checkpoint paying ordinary P2PK outputs completes withdrawal immediately, and
isolated funded tickets avoid a shared head/paid map. The shared candidate asks
one narrower question: can compact batch escrow support later owner-by-owner
redemption, preserve the other liability, and pay fees from the claimed gross?
It must earn its extra state/witness/transaction cost against those baselines.

## Current source check and what is already known

Official HEADs freshly resolved read-only on 2026-10-26:

| Repository | Exact commit |
| --- | --- |
| rusty-kaspa | `4edcbbccb449f84832afb1ca157904b35f37d006` |
| kaspanet/docs | `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` |
| kaspanet/kips | `e4ae2332117b5cb68bd6188e065ef885b6d17939` |
| kaspanet/vprogs | `f9b84a863a7c7c20586a9cf947550475e894f72e` |

Current [amount/script introspection](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/opcodes/mod.rs#L1099-L1174),
[native signatures](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/opcodes/mod.rs#L827-L857)
and [bounded covenant successors](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0020.md#L283-L319)
support investigating this predicate. CheckSig permits several hash modes, so
the candidate must enforce exact SIGHASH_ALL `0x01`, excluding ANYONECANPAY.
The [Toccata state-layout guide](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/decision-guide.mdx)
supports comparing covenant layouts before choosing runtime infrastructure.
These are capability/source facts, not an accepted ticket implementation.

The old [terminal native probe](../../exit-fee/native-claim/RESULTS.md) measured
4,987 mass at its fixed budgets, with Native Full acceptance and an external fee
payer. It cannot withhold a positive fee from its 60M principal, and continuing
roots were explicitly excluded. Reuse its native validator/metrics and public
fixture practice, **not** the unchanged permission emitter. Its two independently
supplied Merkle walks do not supply the required same-siblings/index binding.
No upstream hostile continuation or exploit validation is proposed.

The lower-rate shortcut is negative under default standard relay. Current
[config](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/mining/src/mempool/config.rs#L17-L20)
stores **100,000 sompi/kg = 100 sompi/gram**, and [the check](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/mining/src/mempool/check_transaction_standard.rs#L67-L104)
uses normalized compute/transient mass. Standardness is [separately gated](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/mining/src/mempool/validate_and_insert_transaction.rs#L157-L168)
from consensus validation. Thus underfee calibration `db4fcedd…` passing Native
Full does not support a 1/5/10-sompi public-relay trial under that default.
`95a568fe…` retained its original paid fee while testing lower committed budgets;
its smaller quotes are potential pricing, not paid savings or chain admission.
No new RPC or submission is needed to repeat these already retained findings.

## Selected minimal comparison, before any measurements

Exactly two public synthetic owners and two distinct synthetic original NFs.
Each gross entitlement is **60,000,000 integer sompi**. No sponsor, rent credit,
treasury, second fee input, admin authority or resident balance. A prospective
exact fee of **1,000,000 sompi per claim** leaves **59,000,000** to that owner.
All six claim bodies use the same prospective compute budget **20 per input**
(209,999 SU allowance under the pinned units); measure actual SU and retain any
budget failure rather than raising it after observation. No Groth16/zk opcode,
proof bytes, VK, PK, setup or proving dependency occurs on the claim path.
Claims use transaction version 1, native subnetwork, SPK version 0, sequence
`u64::MAX`, lock time/gas zero, empty payload, exactly one input and only the
specified outputs. Owner A/B use the old public test scalar patterns `[0x11;32]`
and `[0x22;32]`, with native library-derived Schnorr keys: DO NOT FUND. This is
test-vector construction, not a wallet/backup or new key derivation scheme.

1. **Common hypothetical checkpoint output comparison.** With one matched
   input/context/authorization-size envelope and the same gross principal,
   calculate native/SDK masses for two P2PK payouts, two isolated funded-ticket
   outputs, and one funded-outbox output. Identify all placeholder/common-prefix
   assumptions. These are output-layout/storage deltas, not valid checkpoint
   creation or its measured authorization fee. P2PK delivery is already a paid
   withdrawal; never count a later ordinary wallet spend as another protocol
   claim. Compare complete cost expressions `creation(layout) + later claims`,
   keeping unknown creation/proof/consent costs visible. Do not assume equal
   storage mass or infer nine-ticket economics from this two-ticket result.
   The mass-only envelope is fixed prospectively: version 1, one synthetic
   noncoinbase P2SH input of 121M sompi at DAA 0, budget 1800, 8192 zero
   signature-script bytes, sequence MAX, native subnetwork, empty payload,
   lock time/gas zero; output principal totals 120M, leaving a hypothetical 1M
   settlement fee. Recompute committed storage mass for each output vector.
   Its zero authorization is deliberately invalid and never Full-qualified;
   its length/budget are a controlled common placeholder, not a genuine R0
   checkpoint size. Report component deltas and their dependence on that
   placeholder, with no claimed absolute checkpoint quote or eligibility.
2. **Four shared claim transactions:** A then B, and B then A, from separate
   copies of the same ideal initial state. Each first claim consumes 120M escrow,
   pays 59M, pays exactly 1M fee, and creates the same-policy 60M successor. Each
   second claim consumes 60M, pays 59M plus 1M fee, and creates no escrow output.
   Independent accounting checks escrow equals unpaid gross liabilities at
   every step, including an empty private reserve beside unpaid escrow.
3. **Two independent-ticket claims:** one 60M input per owner, the same exact
   59M destination/1M fee and budget, no shared root/head/path dependency. Use
   the simplest owner/destination/fee covenant, with native UTXO consumption
   supplying single use. Membership is redundant once exact ticket creation is
   an ideal accepted premise. This is the required simpler redemption baseline.

Shared state commits the closed immutable entitlement root, current paid root,
unpaid gross amount, domain/profile/batch and authenticated covenant lineage.
Each immutable record binds its stable economic ID/original NF, legitimate
owner key, exact destination, gross and exact fee. IDs remain identical across
claim ordering, paid-root changes and outpoints. Initial distinct-NF correctness
and atomic private-note consumption are checkpoint-oracle obligations, not
proven by the claim script. An arbitrary caller root/signature is insufficient.

Use established SHA256/hash/Merkle/signature primitives with a fixed two-leaf
tree. Claim authenticates an unpaid leaf against the **current** paid root and
changes only that leaf to paid. Old/new computations must use the **same
authenticated siblings and index**, with different old/new leaf values. The
successor retains the immutable records, lineage/policy and exact remaining
backing. No independent old/new path inputs or historical paid-root reset.
All amounts use checked integers; native Script numeric bounds are explicit
(these amounts fit signed 64-bit introspection), with no float sompi.

## Frozen metrics, negative controls and stop rules

For each of six bodies retain exact canonical SDK/native bytes and supplied
UTXOs, input/output amounts/scripts, actual fee, Script bytes/SU/committed budget,
compute/transient/storage masses, TN10-normalized relay and mining masses,
official-source default relay quote and full-mass quote at **100 sompi/gram**.
Record SDK roundtrip/mass agreement, native isolation, Native Full and every
input ScriptEngine separately. SDK success/source-adapted standardness metrics
are **not remote mempool admission**. At 100/g, 1M covers at most 10,000 normalized
mass grams; exceeding either selected quote is a retained economic failure even
if Native Full accepts. Report exact net payouts. No whole-system 2% claim.

Freeze these meaningful controls before executing the prepared fixtures:

- wrong owner and wrong hash modes; changed destination/gross/exact fee with
  otherwise valid owner signatures, so signature failure cannot hide policy;
- already-paid ticket against the current head, stale paid witness, remapped
  ID/index, wrong domain/profile/root/lineage, and mismatched old/new update paths;
- short/long/noncanonical witness, bad sibling, invalid index, negative/oversized
  native number, overflow, zero payout; predicate errors stay separate from
  malformed-fixture/transport/resource errors;
- missing/underfunded continuation, altered other owner record, extra payout or
  sponsor input, forbidden terminal successor, and duplicate input;
- old outpoint replay checked against the evolving synthetic current UTXO view.
  Reinjecting its old supplied entry and observing Full acceptance is not a
  global-spentness test. Record current-context script rejection and view lookup
  failure as different checks.

On our own candidate only, require counterexamples for omitted paid check,
root-local identity, disconnected old/new paths and omitted remaining-backing
check. An independent per-origin ledger must detect double payment or loss of
the other owner's right. No upstream attack fixture. Freeze exact expected
error categories with final source/body hashes before runtime; a generic error
never counts as the intended rejection. Stop on a correct-candidate accounting,
authorization or preservation mismatch. Preserve economic/budget/operational
failures without retuning; interrupted/incomplete is not qualified.

## Minimal reusable source/executable closure

Use the existing generic engine's `validate-transaction` path and its public
ValidationCase input, not any private/reveal/prove mode. It accepts arbitrary
supplied native transaction/UTXO bodies without loading a PK. Construct scripts
with the existing SDK ScriptBuilder and reuse only pure transaction codec and
public synthetic signing patterns. Do not import submission/RPC launch paths.
No new Rust target tree or 591MB key copy is needed.

| Existing public artifact, freshly guarded-read | Bytes | SHA256 |
| --- | ---: | --- |
| Native engine, `/var/tmp/kpi-local-private-payment-01/assets/verification/native-engine` | 13440808 | `077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061` |
| SDK `kaspa.js` | 560116 | `6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf` |
| SDK `kaspa_bg.wasm` | 11463668 | `c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5` |
| SDK `package.json` | 372 | `8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0` |
| `poc/private-exit-native/src/main.rs` | 6132 | `73196654305d6c755232a583561df71fb46700db15e7c3fca642f49ea649bb13` |
| `poc/private-exit-native/src/native.rs` | 21893 | `0a5a535b6baaa86e719d0becacf611129da7a825e3190f632baa9b0cf58f7857` |
| `poc/native-terminal-claim-cost/src/main.rs` | 19822 | `16003552e9168444484e7e7627fadfa9077cea3e098df7dceb49bde7b944f5af` |
| `poc/native-terminal-claim-cost/src/native.rs` | 5295 | `4c701280b797ea4f8b69e9c3a6a76a5425fc0370ef81d9cf6af86957a3b979db` |
| `poc/local-private-payment/chain/wire.mjs` | 8053 | `0dbcf847cbf3e7ef16ca2d6b3428eac227fe09023d95aa795ac18e98b399277c` |

SDK files are under `/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/`.
The retained engine/SDK execute selected official revision
`01b532e8b553523216471682649693af92f0fd16`; current upstream HEAD is separately
identified above. No source-to-binary rebuild attestation or automatic upgrade
is claimed. Any relevant version discrepancy must remain visible before
qualification. The pure codec is a source reference, not permission to import a
live submission workflow. Future prototype source, canonical fixtures, exact
errors and this closure must be frozen and reviewed before measurements.

Current source-byte anchors independently read from pinned official raw files:
`config.rs` SHA256 `862f3161f6561c300de83a6d97f2b1ede25e7c2a30117f78737fb44502a23bf7`;
`check_transaction_standard.rs` `9de15e3df1d932520c3051712c0a0cbcd66fd734b4727e82f7722d996656e571`;
`opcodes/mod.rs` `b85e7827d3ae5cab6eb6c44c1a93f8a6f523c04229d95f2d6f0ba5a411d7b2ae`;
`mass/units.rs` `5880e8edea9d193989cad7bb6d1497f05f504b8748713b2aefb78fc327e31098`;
KIP-20 `94610881c7ef905fe5346c7514b920f21a0e1a10e462776ba45eda73ac179cc8`.

The [completed finite model](../exit-liability-model/REPORT-01.md) is prerequisite
accounting evidence only. Even successful native claims would leave genuine
checkpoint creation/consent/NF consumption, original-backup recovery, durable
witness availability, chain inclusion/reorgs and complete lifecycle costs open.
No system fee saving, privacy improvement or architecture winner follows.
**The existing 2% FAIL and current 100/g trial remain unchanged.**
