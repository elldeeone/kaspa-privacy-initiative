# Native transaction version 2

[Draft scope and common encoding](README.md) govern this proposed format.

## Canonical commitment form

The following is a new canonical **consensus commitment form**. P2P/SDK/RPC
representations must map to it bijectively and reject unknown fields/variants;
this is not a claim that current protobuf/Borsh/JSON has these bytes.

| Order | Field | Encoding |
| --- | --- | --- |
| 1 | Version | U16(2). |
| 2 | Ordinary input vector | List64, count <=16; each input below. |
| 3 | Ordinary output vector | List64, count <=16; each output below. |
| 4 | Lock time | U64, existing absolute-lock semantics; validated in origin/current accepted context. |
| 5 | Subnetwork and gas | 20 native-subnetwork zero bytes, U64(0). Other lanes/subnetworks reject. |
| 6 | Payload | V64, <=4096 bytes, uninterpreted and fully authorized. |
| 7 | Storage mass | U64, exact amount calculated by the activation-bound schedule. |
| 8 | Bundle header | U16(1), domain_id[32], profile_id[32], U64(F), U64(anchor_tree), U64(anchor_count), anchor_root[32], U8(3), U8(2). |
| 9 | Two ordered Actions | Each: cv_net[32], nf[32], rk[32], cmx[32], epk[32], encCiphertext[580], outCiphertext[80]. |
| 10 | Public balance | I64(b), positive from shielded pool toward ordinary outputs/fee. |
| 11 | Proof | U64(7264), exactly 7264 proof bytes. |
| 12 | Shielded authorizations | Two ordered SpendAuth signatures[64] then binding signature[64]. |

Each input is:

```text
previous_txid[32] || U32(output_index) || V64(signature_script)
|| U64(sequence) || U16(compute_budget)
```

Each output is:

```text
U64(value) || U16(script_version) || V64(script) || U8(covenant_present)
[if present: U16(authorizing_input) || covenant_id[32]]
```

Widths for compute budget and covenant authorizing input are the actual
current-Kaspa **U16** widths. The earlier local packet modeled wider fields and
is not copied. Input **amounts are not transaction fields**: fetch them from the
actual current UTXO entries. No claimed amount, root or predecessor overrides
that lookup. Duplicate input outpoints reject before summing or scripts.

The first profile requires script version 0 and no covenant binding for both
actual ordinary inputs and new outputs. Allowed locking scripts are exactly
`0x20 || x-only-secp256k1-pubkey[32] || 0xac` and
`0x21 || compressed-secp256k1-pubkey[33] || 0xab`, with valid canonical keys.
No arbitrary/P2SH/OP_TRUE/contract input, alternate unlocking program or new
signature mode is accepted. Values of ordinary outputs are nonzero and <=M;
all individual values and checked totals obey native ranges. Existing coinbase
maturity, sequence and absolute-lock checks still run where applicable.

`signature_script` is exactly `0x41 || signature[64] || 0x01` (66 bytes) for
both supported types, using Schnorr or canonical low-S compact ECDSA respectively.
The final byte is exactly SIGHASH_ALL. NONE/SINGLE/ANYONECANPAY and nonminimal
pushes reject. This intentionally bounded first profile avoids silently changing
old covenant assumptions about fees, public outputs or signing messages.

Unknown profiles/versions/flags, noncanonical fields/points, identity rk/epk,
wrong counts/proof size, unsupported script/tag, over-limit vectors and suffixes
reject. Identity value commitments and canonical zero nullifiers are not
blanket-banned; use upstream role-specific checks. All published nullifiers,
including dummy slots, must be unique and currently unspent.

## Economic ID, full hash and authorization

Let `Wire(tx)` be the entire canonical form. Define `Q(tx)` by encoding the
same fields through order 10, with each ordinary signature script replaced by
`V64(empty)`. Orders 11–12 are absent. All compute budgets, storage mass, fee,
domains, anchor coordinates, public balance, commitments and delivery bytes
remain in Q. No authentication bytes or length placeholders for absent proof/
signatures are inserted. Encoding/order/counts are otherwise identical.

```text
txid = H("TxID", Q(tx))
txhash = H("TxHash", Wire(tx))
```

Outpoints and accepted-ID bookkeeping use txid. Block-body Merkle commitments
use txhash under the existing Kaspa Merkle algorithm. Two valid authorization
representations for one Q have the same economic ID but different full hashes;
duplicate txids in a block reject. Current version-0/1 ID/hash algorithms remain
their existing algorithms. The current source's `version==0 ? v0 : v1` dispatch
MUST gain an explicit v2 branch, not silently apply the v1 payload/rest rule.

Build actual input context in input order from the UTXO view:

```text
InputContext = U64(input_count)
  || for each input: outpoint[36] || U64(actual_amount)
      || U16(actual_script_version) || V64(actual_script) || U8(0)
input_context_hash = H("InputCtx", InputContext)
S = H("SigMsg", txid || input_context_hash)
```

The final `0` states the first profile's absent actual covenant ID. Reject a
present binding rather than encode it as absent. Block DAA score/coinbase
maturity metadata is checked against consensus, not signed as if immutable
across alternate acceptances. No exact current-state-root hash is signed:
the eligible anchor tuple identifies proven history, while spentness, actual
inputs and balance are rechecked against current accepted state. This avoids
turning each unrelated pool update into a global wallet re-signing barrier.

Both RedPallas SpendAuth signatures and the binding signature verify **S**.
The binding validating key is the unchanged upstream sum of cv_net minus the
commitment to exact signed b. Verifying Halo2 alone checks neither signature
role, current spentness nor ordinary authorization.

For each actual ordinary input i:

```text
input_schnorr_hash = H("InputSig", S || U32(i) || U8(1))
input_ecdsa_hash = SHA256(SHA256(ASCII("TransactionSigningHashECDSA"))
                          || input_schnorr_hash)
```

Run the corresponding secp256k1 verification against the actual locking key.
The ECDSA outer construction is the current Kaspa ECDSA domain convention.
All mutable economic fields and every real input context are authorized.
Wallets must sign the v2 dispatch; old ordinary signatures over legacy hashes
do not authorize v2. Input/signature caches include the exact message and key.
Shielded verification caches additionally key exact proof bytes, fixed profile
and all public instances. No cache bypasses current-state validation.

## Contextual validity and independent fees

1. Decode/canonical-check and determine consensus-configured domain/profile.
   Validate byte/compute/resource bounds before expensive operations.
2. Look up every actual ordinary input; reject duplicates, missing/spent inputs,
   unsupported policy, immature coinbase, sequence/lock violations and bad native
   ranges. Calculate Tin/Tout from real entries/outputs, not supplied JSON.
3. Require the [integer equations](accounting.md), exact F and calculated mass.
   Check current anchor tuple and every marker against native state; ensure room
   for both complete outputs/markers, including any automatic tree rollover.
4. Verify the complete fixed-key Halo2 proof, both spend signatures, binding
   signature and all ordinary input signatures. No host verdict or arbitrary key.
5. Stage all ordinary/native/event/fee effects and commit atomically according
   to [accepted ordering](state-header.md). Failure changes nothing.

A transaction without ordinary inputs is allowed through the new v2 path when
the full shielded construction/balance is valid; a dummy bundle is not native
mint authority. An all-zero/no-effect dummy transition cannot create value, but
still pays/obeys the resource rules. Existing `NoTxInputs` remains for old formats.
Coinbase bundles, queued exits and implicit old-note credits are forbidden.

The owner may rebuild/re-authorize F/change/payout and regenerate a proof when
its relation/public inputs change. An optional authorized ordinary contributor
can pay. No designated sponsor, fixed branch fee, admin rescue or hidden
principal haircut exists. Replacements spending one note use its same nullifier;
at most one commits. Mempool replacement/relay policy is distinct from consensus
validity; affordability and timely inclusion are not guaranteed.

## Exact source differences to review

Current transaction/hash/input/output types and hash dispatch:
[tx.rs](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/core/src/tx.rs),
[hashing/tx.rs](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/core/src/hashing/tx.rs).
Current signing omits new bundle fields and some mass commitments:
[sighash.rs](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/core/src/hashing/sighash.rs#L250-L297).
Actual ordinary fee is currently Tin-Tout:
[contextual validation](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs#L30-L65).
Supported old key-script patterns:
[standard.rs](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/crypto/txscript/src/standard.rs#L18-L30).
