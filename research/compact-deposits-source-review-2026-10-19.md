# Compact independent deposits: source review

Reviewed 2026-10-19 at branch commit
`d67e174712f5ddf3d7a8d4d841bd33adfcaabe4d`. Scope only: no implementation,
experiment, chain action or assertion of security. This note informs the separate
RFC/ADR and experiment scope; it does not authorize them.

**Conclusion:** current Kaspa primitives appear sufficient for atomic deposits
into a new immutable compact pool. The smallest candidate can retain the exact
v4 private circuit, authorization encoding and verification key by admitting two
notes per deposit. A new covenant branch and pool identity are still necessary.
Existing deployed v4 reserves and proofs cannot silently migrate to that pool.
The proposal below remains unimplemented and requires adversarial validation.

## Source snapshot

| Repository | Current head checked |
| --- | --- |
| Kaspa rusty-kaspa | `f7d7877363fb97c2ec6871be0e8cbc351d44df10` |
| Kaspa KIPs | `e4ae2332117b5cb68bd6188e065ef885b6d17939` |
| Kaspa vProgs | `f9b84a863a7c7c20586a9cf947550475e894f72e` |
| Kaspa research | `c923faca11a49148fa7d912d27ce00197a5c5a4a` |
| Initiative upstream | `40b39a6503d2133da93b9dd7e77a5a1ee8652658` |
| Zcash Orchard | `616a669df8c9a59c33d47064d3ce04b25d026b2e` |
| Aztec packages | `660f5f5b51333d9616b5160931a101b23840789c` |
| RAILGUN contract | `36bcf5ed7cf94bfafb6e1a303e1832c769c16780` |
| Monero | `8340be5e920d881edc006e0896d6074cd06dfb2e` |
| Litecoin | `ec1b6489a900d09cf5991e220dce089c77a232a2` |

Keep the experiment's native/SDK pin
`01b532e8b553523216471682649693af92f0fd16`. Comparing it with current Rusty Kaspa
found unchanged relevant signature-hash semantics and introspection logic;
the inspected differences were no-std imports/feature gates and debug formatting.
Signing, transaction-isolation validation and mempool-standardness files were
byte-identical. This is source compatibility evidence, not execution or relay
evidence for a proposed deposit transaction.

## What Kaspa actually provides

[KIP 17](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0017.md)
is Active. Input count/index, outpoint transaction ID/index, input amount/SPK,
input signature bytes, output amounts/SPKs and payload introspection support
the proposed two-input binding. The
[pinned opcode implementation](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs)
reads input amounts/SPKs from the populated UTXOs, not a caller's payload claim.
Every input still needs valid native authorization; the reserve covenant does
not authorize spending somebody else's ordinary input.

The pinned [signature hash](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/sighash.rs)
with `SIG_HASH_ALL` commits to all input outpoints, all outputs, the signing
input's outpoint/SPK/value/sequence, version, locktime, subnetwork, gas and payload.
The native payload hash is zero only for an **empty** native payload. A deposit's
nonempty authorization/state/witness payload is therefore signed. ScriptSig
bytes are excluded; version-1 compute budgets are not included either. This is
not a byte-for-byte commitment to every transaction field. Native execution and
canonical construction must separately enforce the expected script/budget shapes.
The [signer](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/sign.rs)
serializes a P2PK Schnorr signature as a 65-byte push containing 64 signature
bytes and its hash-type byte. The proposed deposit branch should require this
66-byte form with hash type exactly `0x01`, not merely rely on the demo wallet
usually selecting it.

Native [UTXO validation](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs)
computes the fee as total inputs minus total outputs and checks input scripts.
[Isolation checks](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs)
reject duplicate inputs, zero-valued outputs and out-of-range totals. Thus an
empty zero-value reserve UTXO is not a shortcut to genesis. Native validity and
[relay fee policy](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/mining/src/mempool/check_transaction_standard.rs)
remain separate checks; fees for a larger covenant must be measured before exit
authorizations are frozen. No new L1 feature or consensus change is identified
as necessary for this candidate.

## Existing code and minimal proposed reuse

The current [compact covenant](../poc/shared-pool/src/compact/covenant.rs) allows
one input, private transfers and full exits only. It preserves its immutable
code/VK/domain and uses odd commitment counts with history index `(count-1)/2`.
The [private circuit](../poc/shared-pool/src/compact/circuit.rs) accepts domain
and anchor as statement values, proves a positioned input note, and when
`bootstrap` is nonzero equates that note's value to `bootstrap`. For a transfer,
it proves two distinct positive output commitments and
`input value = output value 0 + output value 1 + fee`.

The earlier [array-state covenant](../poc/shared-pool/src/covenant.rs) and
[circuit](../poc/shared-pool/src/circuit.rs) already have an externally funded
deposit mode binding input 1's outpoint, amount and P2PK script into a private
transition statement. Reuse the atomic backing and native-signature lesson,
not that complete state-transition proof: it binds changing state and would
discard the compact design's retained private-proof property.

**Proposed two-note admission:** a new immutable outer deposit branch, distinct
from ordinary transfer/exit, uses the existing private proof with `mode=1`,
`count=1`, `bootstrap=D>0` and zero payout. Here `D` is the actual value of the
ordinary input at index 1. The virtual input note/root/nullifier prove existence
of an exactly valued private input to the relation; they are **not** existing
pool membership, a new pool claim, an accepted history anchor or a spent-pool
nullifier. Append only its two output commitments/ciphertexts. Leave the current
nullifier tree/count unchanged and append the resulting note root to history.
For old reserve `R`, require exactly one successor reserve of `R + D - fee`, with
the unchanged new-pool code/VK/domain and exact new state.

This makes the new private liabilities exactly `D-fee`, preserving all existing
liabilities. Two appended commitments retain the odd-count/history convention.
The actual private input position is zero because the unchanged circuit enforces
`position < count`. No separate virtual-input commitment field or extra deposit
context hash appears necessary: the circuit binds `bootstrap`, output commitments
and ciphertext digest, the covenant equates `bootstrap` to the actual funding
amount, and the depositor's native signature binds the pool outpoint, outputs
and complete nonempty payload. This composition is an inference to validate,
not an implemented result.

Reject widening the spend circuit merely to add a one-note admission: that
changes its VK/setup and increases the proof-compatibility problem. Reject an
unchecked deposited commitment: an attacker could commit to more private value
than the actual deposit. Reject publishing its full note opening as a convenient
native-hash check: that changes the intended privacy surface. Two-note admission
instead costs a proof and requires `D >= 120,000,000 + fee` sompi. Each individual
note value remains cryptographically hidden by the existing construction, while
the pair's total, deposit funding input and creation event are public. This is
not a claim that inference cannot recover individual values.

## Bootstrap, replay and proof-compatibility boundaries

Preserve the existing first-depositor bootstrap gate. Before other deposits, the
initial owner must complete a private self-split that proves its sole initial
note value equals the native reserve. Joining wallets must independently validate
the pinned public pool descriptor, initial commitment, canonical singleton-root
construction, empty initial nullifier tree, singleton history and accepted funding
ancestry, then replay every accepted transition. This replaces reliance on an
operator assertion with reproducible public checks. Merely observing `nf>=1` is
not enough to authenticate an arbitrary creator-chosen pool. The current native
bootstrap checks initial value, NF state and history but does not reconstruct
the initial commitment root from a supplied singleton commitment; retain the
descriptor/lineage checks explicitly. No empty-genesis, rent/refund or public
dummy-claim mechanism is needed for this bounded extension.

The new branch must forbid deposits before that gate; require exactly reserve
input 0 plus ordinary P2PK input 1; enforce the deposit envelope and positive
`bootstrap`; preserve the ordinary spend branch's zero-bootstrap rule after
initialization; and reject changed domain, VK, immutable suffix or successor
accounting. The native signature authorizes the external funds. It need not
prove that their key equals the virtual input's private spending key: those
funds may deliberately pay notes to another private recipient.

Replay of the same spent funding outpoint is rejected by native UTXO rules.
Reusing an admission proof with a different, freshly signed funding input of the
same value creates separately backed notes at new positions; it is not inflation.
The existing positioned-nullifier derivation distinguishes those positions.
Such reuse publicly repeats commitments/ciphertexts and is poor wallet practice,
but banning identical proof bytes is not the economic replay rule. A changed
reserve outpoint requires a new depositor signature even if the admission proof
can be reused. The wallet must verify its intended output commitments and locally
decrypt/check delivery before signing: the current circuit binds the ciphertext
digest, not the correctness of encryption.

Retaining the exact VK preserves the **relation**, not pool identity. New exit
proofs must be created for this new pool's domain before later deposits occur.
Their count/root, payout, fee, nullifier and proof bytes can then remain unchanged
while public settlement paths track deposits. Proofs for already deployed v4
domains cannot be imported as claims in another domain. Preserve old variants
and evidence; this extension is a new pool, not an in-place upgrade or migration.

## Mature protocols and upstream requirements

| Primary source inspected | Reuse or rejection |
| --- | --- |
| [Orchard ZIP 224](https://zips.z.cash/zip-0224), [transaction format](https://zips.z.cash/zip-0225), [positioned tree](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/commitment-tree.md) | Reuse explicit public pool inflow/outflow accounting and private note conservation. Separate pools/versions do not share anonymity or spending rights automatically. Do not import Orchard consensus, Halo2 or security claims. |
| [Aztec portal messages](https://docs.aztec.network/developers/docs/foundational-topics/ethereum-aztec-messaging), [claim example](https://docs.aztec.network/developers/docs/aztec-nr/framework-description/ethereum_aztec_messaging) | Reuse binding backing to exact credit and distinguish repeated independently funded messages by position. Reject inbox/outbox, pending claims, token minting and an operator runtime: this candidate credits atomically in the same native transaction. |
| [RAILGUN shield](https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunSmartWallet.sol), [actual-transfer checks](https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunLogic.sol) | Reuse validating actual received backing before inserting commitments and separating fees. Reject ERC20 transfer machinery, governance fees and upgrade controls. |
| [Monero RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html) | Reuse value/range-conservation discipline. Monero has no separate native-KAS admission bridge; ring selection and its cryptography are not required for this extension. |
| [MWEB kernels](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md) | Reuse matching public peg-in amounts to actual native backing, and explicit fee deductions. Reject importing the extension-block consensus mechanism. |
| [vProgs covenant](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/script.rs), [Kaspa research](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex) | Retain immutable verifier/state-continuity binding and explicit native outputs. No source requirement was found to introduce based-app sequencing for this atomic two-input deposit. Broader runtime merits remain a separate question. |

Upstream [P06](https://github.com/olafweller/kaspa-privacy-initiative/issues/6),
[P07](https://github.com/olafweller/kaspa-privacy-initiative/issues/7) and
[P13](https://github.com/olafweller/kaspa-privacy-initiative/issues/13) remain open
with zero comments. Current
[RFC 0002](https://github.com/olafweller/kaspa-privacy-initiative/blob/40b39a6503d2133da93b9dd7e77a5a1ee8652658/docs/rfc/0002-shielded-payment.md)
requires range/fee accounting, authenticated deposits and replay protection; its
pending-deposit lifecycle is a different architecture. Our atomic candidate has
no accepted-but-uncredited intermediate deposit. An arbitrary unsolicited payment
to a script is not a valid admission. These sources inform requirements, not an
obligation to adopt upstream's pipeline or wait for a maintainer decision.

## What a later test must establish

Use four independently controlled funding wallets, including the first depositor,
not eight users inferred from eight notes. The bounded main path is funding,
first-owner self-split, three later two-note admissions and eight full exits.
Each wallet retains both exit authorizations immediately after receipt; all
provers stop before drainage. Verify every original authorization/proof remains
byte-identical, every payout is exact, all liabilities reconcile, and the final
reserve drains. A separate genuine private-transfer regression checks that the
new branch has not changed normal spend behavior. Exact transaction/script mass,
fee sufficiency and payout floors must be settled before freezing those proofs.

Required negatives include deposits before validated bootstrap, unsigned/wrong-key
or weak-hash-type inputs, substituted outpoints/SPKs/amounts, changed ciphertexts,
wrong domain/VK, cross-mode replay, stale update paths, existing-note/nullifier
mutation during admission, overstated credit, overflow and duplicate funded-input
replay. Include legitimate repeated-proof/new-funding behavior as a positive
control. No new tests were run during this scoping review.

Even success would establish bounded independent admission/exit mechanics, not
useful privacy. Funding ancestry, public pair totals, timing, repeated commitments
and the old-anchor ceiling remain observable. Existing exact-fee proofs still
depend on a sufficient fee envelope and available public history. Single-party
setup, unreviewed cryptography and correct-node assumptions remain unchanged.
