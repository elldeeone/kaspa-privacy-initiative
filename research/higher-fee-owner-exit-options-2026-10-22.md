# Higher-fee independent owner exits: source/design options

**An external native fee input is compatible with the unchanged v6 DRAIN
statement at the conservation level, in a separately versioned immutable
native branch. It is not supported by the existing v6 covenant and does not
make a 60M-sompi singleton economical at500sompi/gram.** Owner funding needs
additional transparent KAS; a subsidy needs an actual willing payer. Neither
meets the unchanged cashout/cost requirements by itself.

Status: research and conditional design only,2026-10-22UTC. No implementation,
proof, setup, funding, private input, privacy experiment or RFC decision. The
adopted RFC0012 targets and failed RFC0016 withdrawal-policy result remain
unchanged. The current integration factory adopts budget1600; the observer
baseline remains ec6aa15. This note does not change either source tree.

## What the current statement permits and forbids

v6 authorization A commits to domain, count/anchor, two NFs, mode, payout P,
fee f, payout script and ciphertext hash. Its two Groth16 public inputs are
the two little-endian128-bit limbs of SHA256(A). In DRAIN mode the private
outputs are zero; the circuit enforces selected private value `V=P+f`, at
least one real input, distinct positions if both are real, nonzero/distinct
active NFs, positive payout and the same value ranges. Adding a native fee
input outside A does not change that mathematical statement or its proof
bytes. This is a **source inference about proof compatibility**, not an
executed new covenant result. [Circuit, fixed ec6aa15](https://github.com/elldeeone/kaspa-privacy-initiative/blob/ec6aa15d586bcc8a90f7232b433fd48d8c73d509/poc/shared-pool/src/two_input/circuit.rs#L110-L278),
[authorization](https://github.com/elldeeone/kaspa-privacy-initiative/blob/ec6aa15d586bcc8a90f7232b433fd48d8c73d509/poc/shared-pool/src/two_input/mod.rs#L23-L112).

The existing native covenant expressly requires one input for non-ADMIT,
enforces exact payout/continuing reserve outputs, and subtracts P+f from the
reserve. Its builder/replay require actual native fee==f. Sending an extra
input to this old branch fails. New builder/replay framing and a new immutable
covenant would be necessary; changing the interpretation of a.fee is invalid.
[Input-count and metadata rules](https://github.com/elldeeone/kaspa-privacy-initiative/blob/ec6aa15d586bcc8a90f7232b433fd48d8c73d509/poc/shared-pool/src/two_input/covenant.rs#L207-L253),
[reserve and payout rules](https://github.com/elldeeone/kaspa-privacy-initiative/blob/ec6aa15d586bcc8a90f7232b433fd48d8c73d509/poc/shared-pool/src/two_input/covenant.rs#L543-L621),
[builder](https://github.com/elldeeone/kaspa-privacy-initiative/blob/ec6aa15d586bcc8a90f7232b433fd48d8c73d509/poc/shared-pool/src/two_input/mod.rs#L158-L263),
[replay fee comparison](https://github.com/elldeeone/kaspa-privacy-initiative/blob/ec6aa15d586bcc8a90f7232b433fd48d8c73d509/poc/shared-pool/src/two_input/replay.rs#L264-L320).

No old reserve can be upgraded by this note. Existing successor checks preserve
its immutable script. A future pool would need its chosen branch from genesis,
an authenticated parameter/exit plan and independent pool-domain separation.
An old A/Q cannot be relabelled under a different domain or used to bridge two
independently spendable reserves with separate NF trees. Reusing the unchanged
circuit family differs from reusing a historical funded instance. The destroyed
development PK does not supply fresh DRAIN capabilities.

## Conditional optional fee-input branch

Let R be the authenticated reserve input, E one ordinary external fee input,
C its external change (zero means no change output), and P/f the unchanged
proof-authorized payout and **claim-funded fee component**. Preserve:

```text
V = P + f                    # unchanged DRAIN private conservation
R' = R - P - f               # reserve output; E is not an admission
M = (R+E) - (R'+P+C)
  = f + E - C                # actual miner fee
```

Use integer sompi, checked operations and explicit bounds:
`R >= P+f`, `0 <= C <= E`, and **R+E<=MAX_SOMPI**. The native validator caps
the sum of all input amounts, not just each input; it separately checks output
ranges and total output<=total input. A full reserve already at MAX cannot
accept an extra fee input. Signed64-bit script arithmetic is checked, not
wrapping. [Native input/output validation,01b532e](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs#L98-L123),
[nonzero/ranged outputs](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs#L145-L169),
[checked script arithmetic](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L635-L648).

If initial liabilities are L and the consumed claim is V=P+f, then
`L'=L-P-f` and `R'-L'=R-L`. Thus an **initially authenticated** backing gap is
preserved. External money neither creates a private claim nor credits the
reserve. Require C<=E: allowing an extra output to exceed its funding would
route some claim-funded f away from the miner under this profile. Authentic
backing/reachable predecessor state is still an independent prerequisite.

The smallest candidate would retain the ordinary one-input DRAIN branch and
add exactly one optional ordinary fee input, with no named sponsor key:

1. Reserve input0 still performs the real unchanged proof, historical-anchor,
   current-NF and successor checks. DRAIN inserts both active NFs, adds no CMs,
   preserves CM/history roots, and binds the original payout amount/script.
2. Fee input1 is a non-coinbase ordinary P2PK UTXO with zero covenant ID,
   canonical signature framing, required sequence and SIG_HASH_ALL. Its own
   native script must actually verify. No second reserve or deposit mode is
   inferred merely from an added input.
3. Continuing output0 is exactly R' under the same new immutable policy;
   payout and optional positive C have fixed, unambiguous indices. A terminal
   reserve has no reserve output and still pays exactly P. The simplest change
   rule returns C to input1's exact SPK. Exact output counts and metadata reject
   extra outputs, diverted reserve, mixed branch selectors and fake zero outputs.
4. Reconstruct M from actual input/output amounts, not a host fee flag, and
   verify M=f+E-C. Full native validation, all mass caps and ordinary inclusion
   policy remain necessary. Existing1600 script-unit bounds cannot qualify a
   changed script; recompute the bound and complete transaction mass.

These conditions are a review candidate, not a selected format/version. Native
introspection returns actual populated input amounts/SPKs and actual output
amounts/SPKs, so the required equality handles exist at the pin.
[Introspection implementation](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L1100-L1173).

SIG_HASH_ALL commits all previous outpoints, sequences, outputs and payload,
plus the signing input's amount/SPK and transaction metadata. For v1, compute
budgets are not included in this signature hash. A contributor signs the final
body; adding/replacing the external input or changing C requires its fresh
signature. This does **not** require a new Groth16 proof if A is unchanged.
Current public witness/root updates also change the payload, so stale sponsor
signatures cannot be assumed reusable after another reserve transition.
Do not weaken signature mode to avoid coordination.
[Exact signature hash](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/sighash.rs#L140-L220),
[v1 composition](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/sighash.rs#L245-L279).

## What this buys, and what it cannot buy

An owner with a precomputed genuine DRAIN may raise M by changing E-C and
signing a fresh ordinary fee input, while retaining A/Q/P/f. A willing sponsor
can instead contribute its own native KAS; its signature authorizes that input,
not reserve withdrawal. Because no sponsor identity is pinned, the owner can
replace it or self-fund when able. Any exclusive sponsor, allowlist, operator
approval, special reserve key or compulsory other claimant is rejected.

This separates **protocol permissionlessness** from **additional funds**. A
user controlling only the shielded claim still cannot pay the shortfall alone.
A sponsor can withhold its own contribution and learn request metadata. A
market is an availability assumption, not a guarantee after service loss. A
grant remains a subsidy even if the recipient receives their full payout.
Ordinary native fee liquidity and fresh signing ability must appear in the
recovery assumptions; no privileged service may become the sole exit route.

For owner funding, the net native receipt after paying the extra contribution is

```text
P + C - E = (P+f) - (f+E-C) = V - M.
```

The unchanged two-input Groth16 verifier floor is147,500grams. At the adopted
500sompi/gram research case, **M>=73,750,000sompi before other costs**. A60M
singleton therefore has owner net<=-13,750,000sompi. Moving some fee payment
outside the reserve cannot reverse that inequality. Actual extra input,
covenant/payload and storage costs require whole-transaction measurement; more
inputs can also affect storage mass, so do not estimate by adding only a
signature charge. [Fixed Groth16 base](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs#L29-L34),
[three-IC tariff](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L18-L59).

RFC0012 still requires exits at100/200/500, includes supported small change,
counts all actual costs and rejects an undisclosed subsidy. This proposal may
improve **fee flexibility**, but supplies no success on the unchanged minimum
claim, cost, latency, recovery or privacy requirements. The1600 adoption was
operational resource qualification, not a minimum-note fix.
[Adopted requirements](/home/luke/projects/kpi-intensive-2026-10-22/observer/docs/rfc/0012-useful-privacy-requirements.md:178),
[integration delivery](/home/luke/projects/kpi-intensive-2026-10-22/integration/research/intensive-2026-10-22/evidence/native-budget-integration-delivery.json).

## Established analogous mechanisms

| Primary source | Reuse / limit |
| --- | --- |
| Zcash ZIP317, active Revision0, pinned `2bdf39494320e5e04057ac93b1794031ebfb00b5` | Logical-action fee policy separates network-cost selection from transaction conservation; it is not a consensus sponsorship right. It warns about unusual-fee fingerprinting. Zcash's transaction value pool includes real transparent inputs and shielded balances; residue pays miners. This does not establish unchanged Zcash proof/signature reuse when adding an input. [ZIP317](https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/zips/zip-0317.rst#L120-L226), [privacy](https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/zips/zip-0317.rst#L497-L525), [protocol accounting](https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/protocol/protocol.tex#L4070-L4090) |
| Aztec v5.2.0, commit `49a592109ec4f18d79212b43d621891aaf36f7b6` | Explicit fee payer distinct from application authorization; fee payer needs actual balance and must be selected during non-revertible setup. Its SponsoredFPC source is explicitly testing-only. Reuse this separation of authority/accounting, not its fee asset, runtime, quote operator or code. Current official docs distinguish testing sponsorship and third-party fee contracts; an older generic FPC recipe must not be assumed current. [Fee-payer API](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/noir-projects/aztec-nr/aztec/src/context/private_context.nr#L537-L550), [test sponsor](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/noir-projects/noir-contracts/contracts/fees/sponsored_fpc_contract/src/main.nr#L3-L18), [current official guide](https://docs.aztec.network/developers/docs/aztec-js/how_to_pay_fees) |
| Litecoin MWEB, commit `ec1b6489a900d09cf5991e220dce089c77a232a2` | Closest concrete mixed-funding analogue: wallet permits ordinary LTC inputs with an MWEB pegout; external input net of LTC fee/change enters its pegin accounting, while its MWEB builder balances inputs+pegin against pegouts+outputs+MWEBfee. Kernel signatures bind fee/pegout fields. This is real added value/authorization, not free withdrawal or a Kaspa proof-compatibility result. [Classification](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/mweb/mweb_transact.cpp#L26-L47), [accounting](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/mweb/mweb_transact.cpp#L130-L164), [builder](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/src/wallet/TxBuilder.cpp#L16-L36), [kernel](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md#L21-L53) |
| Monero, commit `8340be5e920d881edc006e0896d6074cd06dfb2e` | Actual input commitments jointly balance outputs plus the public fee; each actual input has authorization. Decoys contribute no fee funds. Multi-owner contribution is a consensus-level inference, not a stock-wallet sponsor API. Reuse joint accounting and contributor authorization; do not assume adding inputs preserves existing signatures. [Balance](https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/ringct/rctSigs.cpp#L1406-L1432), [authorization](https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/ringct/rctSigs.cpp#L1252-L1266), [constructor](https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/cryptonote_core/cryptonote_tx_utils.cpp#L363-L385) |

No new privacy token, crypto primitive or based-app runtime is selected. The
Kaspa native input/signature plus introspection route is the smaller candidate
for this narrow question; a paymaster system would need a demonstrated reason.

## Owner claim consolidation and privacy cost

One owner may use both real-input slots of a genuine v6 DRAIN to withdraw two
owned, unspent notes for one proof/native verification, retaining normal anchor
membership and distinct-position/NF checks. This is fee amortization without
another user's permission. It requires those two claims and an appropriate
genuine proof or local proving capability; a singleton owner cannot assume a
second claim. More than two selected notes need other transitions and their
fees/data/latency. A PAY-merge followed by DRAIN adds work and cannot be counted
as free consolidation. Cross-user batching is not a replacement for direct
owner exit. No fresh proof or economic fit is established here.

DRAIN adds no CM/history leaves and inserts two NFs even with one real input.
External fee funding does not recover NF capacity, CM positions, missing
parameters or unavailable authenticated history. Preserve and separately
qualify capacity/reachability guarantees of every new branch; sponsorship is
not a way around an exhausted current NF tree.

Native E, C, payout scripts, ancestry, M and transaction shape are public. An
owner fee input can link an identified transparent wallet to the exit; a sponsor
adds quote/request/coordination observations. Common-input ownership is an
inference, not proof when sponsoring is possible. The aggregate selected claim
`V=P+f` remains public, and `E-C=M-f` is also derivable. Additional funding does
not hide payout/claim totals or repair RFC0016's failed privacy result. Two-note
consolidation changes grouping, not the obligation to measure later cashout and
all-in costs. No new privacy score or study is proposed.

## Candidate rejection criteria and next research boundary

Reject a future candidate if it:

- accepts unverified/stale/wrong-domain authorizations, duplicate NFs, wrong
  historical membership, incorrect reserve decrease, arbitrary C>E, diverted
  payout, extra outputs, false terminal state or changed successor policy;
- makes sponsor/operator approval, another user, a special key or private
  export mandatory; claims self-contained singleton recovery without external
  liquidity; or silently enables this branch on an old immutable reserve;
- treats proof f as total M without a new profile, ignores total-input MAX,
  weakens SIG_HASH_ALL, accepts a host-supplied fee assertion, or assumes the
  old1600 bound/full-transaction mass carries over;
- calls a subsidy an economic improvement under RFC0012, drops costly small
  claims from the eligible set, raises the cashout minimum retrospectively, or
  reopens the failed privacy screen by relabelling external liquidity.

Before any RFC decision or prototype, resolve whether the optional extra-funds
assumption belongs in a supported owner-exit profile and how it coexists with
the unchanged small-claim target. A later reviewed design would need its own
fixed branch/framing/domain policy, exact integer/native composition argument,
direct owner exit, authentic parameter/recovery plan and complete resource/fee
qualification. This note supplies the source-level feasibility distinction;
it supplies no execution authorization or readiness claim.

## Source identities and independent check

Scientific baseline is ec6aa15d586bcc8a90f7232b433fd48d8c73d509. SHA256:
v6 circuit `59071901c3abc25daab68c982ef065f8755c09abbb2ce30e6010d821813dd2a7`;
baseline covenant `3b6d73c1ebada11d156f3020b444c881160e2f4d8eb7ae629a23ac267bf0d96d`;
integration budget1600 covenant `52f11865f8a6fd92cd0046c859c9e49e501c6fe1bda6cc27adbf0c6ef2c17abe`.
Native pin is01b532e8b553523216471682649693af92f0fd16; sighash source SHA256
`a1f300f5925155a7e32c2b262502427cd0c9c1f5fb04c73b511b72747a92f89f`,
input-UTXO validator `8e6f22b0f0280df9c3baad39654e3ce15c0b25cc5a97b720add1bbdc721e6786`.
Aztec v5.2.0 release resolves to the commit above; SponsoredFPC SHA256 is
`2c3780b249da3a7984a65e63929aaaafaefd7a40a382e0596548b8b2013a5326`,
PrivateContext `29a0032aa88697997495a7ef73498d920d29bea222b48bdb3dcff170c2a9ab86`.
Live documentation was consulted2026-10-22, not treated as a fixed deployment.

An independent source/accounting review agreed that R and liabilities fall by
P+f, that owner net is V-M, and that the existing actual-fee==f branch cannot
be reinterpreted as fee sponsorship. This is a second source/design check,
not a cryptographic audit or native qualification.
