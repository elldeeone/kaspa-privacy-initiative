# Replacement withdrawal: primary sources and bounded feasibility

Reviewed 5 November 2026 (Australia/Sydney). This note supports the owner's
authorized **offline replacement-design investigation**, with no consensus
changes. It records source facts and proposed composition; execution results
belong in the accompanying experiment report. No funded or accepted-chain
qualification follows from this source review.

## Decision supported by the sources

Current L1 has the needed proof-verification and output-inspection interfaces
to investigate a finite contract in which each claim owner authorizes **the
same complete payout transaction**, rather than publishing a selected payout
destination. The native predicate must bind those authorizations to the actual
reserve input, all output values/scripts, active claims, fees and any successor.
It must still verify all required spending authorities. [K1], [K2], [K3], [K5]
(design inference).

There is also an executable existing primitive for separating identified
issuance from output registration: RFC 9474 RSA blind signatures. A coordinator
can issue a coordination credential without seeing its recipient message;
redemption verifies under the common issuer key. This does not supply network
anonymity or native spending authority. The experiment must exercise the actual
library calls and retain their real observation surfaces. [B1], [B2], [B3]

Neither source fact rescues the old public EXIT proofs: their per-request
destination remains public. The replacement changes the application relation
and messages. It does not change Kaspa output fields, opcodes or consensus.
[H1], [K1], [K2]

## Source checkpoint

Official GitHub heads and decisive files were read during this investigation.

| Repository | Inspected revision |
| --- | --- |
| `kaspanet/rusty-kaspa` | `4863866fce8439d0305b410fc4d802e7261d54d0` |
| `kaspanet/docs` | `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` |
| `kaspanet/vprogs` | `f9b84a863a7c7c20586a9cf947550475e894f72e` |
| `kaspanet/research` | `c923faca11a49148fa7d912d27ce00197a5c5a4a` |
| `jedisct1/rust-blind-rsa-signatures` | `640084d82abd5bbe48c65c3d8e6f647c8963ec73`, Cargo version `0.18.0` |
| Library version-bump commit | `45d0abfa829c3623389daae30bc35e9b2f3b550c` |

An exact source revision is not the deployed network or an audit. The prototype
must separately record the actual compiled Kaspa source, Cargo lock identities
and library version/checksum. vProgs continues to describe itself as prototype
infrastructure; adopting its runtime is not required for this native predicate.
[K4], [K6]

## L1 obligations

- The inspected proof tags are Groth16 `0x20` and RISC Zero Succinct `0x21`.
  Native full Orchard/Halo2 verification is not an available tag. [K2]
- Ordinary outputs contain public integer `value`, `script_public_key` and an
  optional covenant binding. Their values and recipient scripts remain visible
  in the replacement. The target is **owner-to-payout assignment**, not hiding
  the output bytes. [K3]
- Inline ZK verifies a particular relation; native script must separately
  enforce that the actual spend installs the authorized effects. Existing A0/A1
  harnesses inspect output count, amounts and complete scripts, and A0 uses the
  native Groth16 hook. They are reusable interface examples, not the new
  withdrawal protocol or proof of its safety. [K1], [K5]
- A common key/relation may prove knowledge of each predeclared claim opening
  and bind an HMAC authorization to one complete effect context. Input claim
  identities may be public in the minimum test. That tests payout ownership
  even when claim owners are known; it does **not** implement a shielded-note
  ledger, hidden membership or a new nullifier scheme. [H2] (proposed scope).

For a finite three-claim diagnostic, explicitly enumerating all seven nonempty
active-claim subsets can provide joint and individual-exit branches without a
new generic runtime. Every branch must pin the exact active set and backing.
For denomination `D` and dedicated per-claim fee allowance `F`, a state with `n`
claims has backing `n*(D+F)`: joint exits pay `n` outputs of `D` and fee `n*F`;
one individual exit pays `D`, preserves `(n-1)*(D+F)` in the exact smaller-set
successor and spends fee `F`. These are **proposed checked equations**, not paid
fees, economic qualification or a general scalable pool construction.

A terminal contract that requires every owner but has no individual-exit branch
cannot satisfy the optional-joint/independent-exit requirement. The old pool's
fallback does not remain available after moving backing into a different
contract. An implemented finite fallback must use the same underlying spent
outpoint/current active-state restrictions so competing joint/individual spends
cannot both release principal. General DAG/reorg recovery and repeated-pool
integration remain separate requirements. See [security invariants](../../SECURITY-INVARIANTS.md)
I-1, I-4 and I-7 through I-10 (design inference).

## Blind-registration implementation

Use the published `blind-rsa-signatures` library rather than implementing RSA
blinding, PSS encoding or unblinding locally. Its `0.18.0` source exposes the
recommended SHA-384/PSS/randomized configuration; the README has a complete
blind/sign/finalize/verify example. [B2], [B3]

Relevant API names are `KeyPair::<Sha384, PSS, Randomized>::generate`,
`PublicKey::blind`, `SecretKey::blind_sign`, `PublicKey::finalize` and
`PublicKey::verify`. `BlindingResult` contains `blind_message`, private `secret`
and `msg_randomizer: Option<MessageRandomizer>`. The wire wrappers are public
byte-vector tuple structs with `AsRef<[u8]>`; `MessageRandomizer` wraps 32 bytes.
Public keys have DER import/export. The finalizer verifies the resulting
signature before returning it. [B3]

The library's current dependencies include RSA `0.10.0-rc.18`, rand `0.10.3`
and digest `0.11.3`. Their exact built versions belong in the prototype lock.
The repository's maintenance or passing tests are not an independent audit.
[B2]

RFC 9474's randomized mode uses SHA-384, PSS with 48-byte salt and a fresh
32-byte preparation prefix. The RFC explains its blindness/unforgeability
assumptions, recommends randomized preparation when determinism is unnecessary,
requires exclusive signing-key use for the selected protocol/encoding and
requires verifiers to use the expected issuer key. These obligations govern
the chosen library mode; successful signatures do not establish application or
network anonymity. [B1], sections 5 through 7.

### Required message and authority separation

1. All participants check one expected issuer key **and mode** for the round.
   A DER fingerprint alone does not bind Rust's generic hash/PSS/preparation
   configuration. Dedicated per-round keys can prevent a signature obtained
   for another round being accepted as current registration.
2. The signed application message has exact canonical domain, round, denomination
   and recipient-key fields. Redemption checks their intended context, exact
   lengths and replay status. Eligibility proof and issuance quota are checked
   separately: the signer cannot inspect a blinded message's structure.
3. Identified issuance receives only the fixed-size blinded message and the
   required claim-eligibility evidence. **Neither the blinding secret nor the
   message randomizer goes to the issuer at issuance.** Sending the randomizer
   then and again at redemption would expose an exact linking identifier.
4. Redemption carries the message, final signature and message randomizer over
   a separate logical registration interface. No owner alias, issuance-session
   handle or correlated index may be echoed. A local interface with those fields
   omitted still does not establish protection from IP/timing/global observers.
5. Credentials only control coordination/admission. Extra or forged credentials
   cannot release KAS: every active claim still needs its owner's complete-set
   authorization, and each honest wallet checks the **sum of all** its expected
   payments before authorizing. A malicious issuer may prevent completion or
   inject nuisance registrations; it gains no privileged spending key.

Items 1–5 are application-design obligations derived from the source interfaces,
not already implemented guarantees of RFC 9474. The program must not serialize
the whole `BlindingResult`, log its `Debug` output as a service transcript, or
carry controller truth into coordinator/scorer inputs. [B1], [B2], [B3]
(design inference).

## Established-protocol reuse and exclusions

The existing [five-protocol review](../native-kas-shielded-value-sources-2026-11-03.md)
was read; decisive mechanism sources below were rechecked at its exact pins.

| Source | Reuse or adapt | Exclude from this test |
| --- | --- | --- |
| Orchard | Separate spending authorization, effects binding and conservation. | Native Halo2/Pasta pool, new consensus formats, hidden note-ownership claim. [M1] |
| Aztec | Treat service/network/query metadata separately from proof confidentiality. | PXE/kernel/runtime/portal as an existing Kaspa interface. [M2] |
| RAILGUN | Authorize complete transaction effects; distinguish private accounting from public unshield destinations. | EVM token custody, upgrade authority and verifier as a native KAS implementation. [M3] |
| Monero | Separate bounded-value balance from spending authorization and duplicate-spend checks. | RingCT/CLSAG/native confidential outputs or decoy assumptions. [M4] |
| Litecoin MWEB | Preserve reserve accounting and explicit public peg-out boundaries. | Extension-block consensus, confidential output format and forced maturity. [M5] |
| WabiSabi | Separate input participation, output registration and approval of the whole transaction. | Treating Bitcoin credentials/wire format or assumed network privacy as a ready Kaspa port. [W1] |

RFC 9474 registration is a smaller selected coordination primitive, not an
implementation of WabiSabi's credential system or its complete protocol.
No new asset is created; the credentials are not native value or transferable
private money. Paused MPC work is neither needed nor restarted by this test.

## Privacy claims and falsification controls

For three independent equal-denomination owners with no output mapping,
`3! = 6` owner-to-distinct-recipient assignments are structurally possible. One
participant's legitimate output knowledge leaves two; two such disclosures
leave one. These count **real payout-owner assignments**, not commitment-label
permutations. Counts assume the exercised blind-signature property and admitted
observation interface; they are not a proof of cryptographic blindness or equal
posterior probabilities. [B1], [W1] (logical inference).

Retain controls for unblinded registration, randomizer/session-tag leakage,
different issuer keys, equal versus identifying amounts, duplicate/replayed
credentials, absent/substituted/underpaid owner outputs, changed whole-set
contexts, wrong/stale state/outpoint, missing/duplicate claim authorization,
individual fallback, and outsider knowledge of every payout owner. Equal values
do not supply honest peers or conceal known-owner full-drainage arithmetic.
Later spends can reveal a recipient mapping and shrink the surviving assignments.

A finite supplied-UTXO proof/native test can establish local authorization and
an observed absence of a direct map in specified messages. It cannot establish
funded backing, accepted ancestry, full-lifecycle payment privacy, production
security, real participant independence, global network anonymity, practical
fees, public proving-artifact availability or general recovery after reorg.
Those limits must accompany any positive local result.

## Primary sources

[K1]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx
[K2]: https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/crypto/txscript/src/zk_precompiles/tags.rs
[K3]: https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/consensus/core/src/tx.rs#L176-L192
[K4]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md
[K5]: ../../poc/a1/src/script.rs
[K6]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex
[B1]: https://www.rfc-editor.org/rfc/rfc9474.html
[B2]: https://github.com/jedisct1/rust-blind-rsa-signatures/blob/640084d82abd5bbe48c65c3d8e6f647c8963ec73/Cargo.toml
[B3]: https://github.com/jedisct1/rust-blind-rsa-signatures/blob/640084d82abd5bbe48c65c3d8e6f647c8963ec73/src/lib.rs
[M1]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/bundle.rs
[M2]: https://github.com/AztecProtocol/aztec-packages/blob/3c25bee4cffc3d5f95990c95425cc9f983eb65cf/docs/docs-developers/docs/resources/considerations/privacy_considerations.md
[M3]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunLogic.sol
[M4]: https://github.com/monero-project/monero/blob/b14fae7bca4099cea56205e44c1005602834b7bd/src/ringct/rctSigs.cpp#L1358-L1540
[M5]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/consensus.md
[W1]: https://github.com/WalletWasabi/WabiSabi/blob/1e6deb989f58bc6edce91bc300252d2bed18db30/protocol.md
[H1]: ../joint-withdrawal-feasibility-2026-11-05/RESULT.md
[H2]: ../../poc/a0/src/circuit.rs
