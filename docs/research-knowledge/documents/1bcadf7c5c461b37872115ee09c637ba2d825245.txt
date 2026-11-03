# P1 recovery authorization and deposit binding source check

Date: 2026-10-18. Scope: selected primary-source inspection and public primitive
interoperability, not a deployed private protocol or independent audit.
The [manifest](private-payment-recovery-binding-2026-10-18.json) pins source
commits, paths and hashes. The prior [mature-protocol comparison](private-payment-source-review-2026-10-18.md)
still governs reuse/alternatives; this does not add a new primitive or token.

## Findings

| Verified source fact | Implication for this candidate |
| --- | --- |
| vProgs example deposit policy derives a P2SH from the covenant's 53-byte delegate-entry script. Its bytes contain the covenant ID, not a per-deposit recovery key. | Reusing the address does not authenticate our independent Ed25519 recovery key. That binding needs an accepted funding registration or actual script commitment. |
| The deposit action parses the referenced output from the same transaction, checking script version, exact script bytes and actual value. | Reuse that source-of-funds pattern; never accept later host metadata as proof that a key owns an earlier funding output. |
| Current native sighash commits the payload hash, subnetwork and outputs according to the sighash mode. Native v1 identity binds payload digest and rest digest. | Study stable terms carried in the funding payload and derive the reference after native ID computation. Wallet construction must bind its intended payload/output with the appropriate actual input authorization; this source result is not a live signing/consensus experiment. |
| Ed25519-dalek's key constructor accepts ZIP-215 decoding and preserves compressed input bytes; `to_bytes` need not normalize a point. | Explicitly compare decompressed/recompressed bytes. Candidate input policy additionally requires non-small-order, torsion-free key and R plus canonical S before strict verification. |
| The published strict verifier uses established Ed25519 arithmetic and checks signature validity and small-order conditions. | Reuse it; do not implement another signing, hash or curve algorithm. Additional validation profile choices need composition review. |

Putting the funding transaction's own ID into a descriptor inside its payload
would create a hash cycle. A candidate design separates stable funding terms
from the later derived outpoint. Likewise a wallet guest must not embed its own
image ID; the immutable outer verifier policy must bind the actual artifact.
These are design deductions from the dependency structure, not successful
native implementation claims.

## Candidate and alternatives

The leading research candidate is one shared covenant entry script plus stable
recovery terms in the **same accepted funding transaction**. A per-deposit
script commitment is the alternative. Shared address plus unrelated later
metadata is insufficient and rejected. Do not add an owner-key native bypass:
it could compete with credit after the deposit is already spent privately.

Both viable candidates require reviewed current-state credit/refund exclusion,
exact native outpoint/value/key authentication, stable unsupported-inner-proof
recovery, reserve recognition and confirmed terminal payouts. Neither is
implemented or accepted by this source note. The final descriptor/rent/refund
bytes and bootstrap identity graph remain open in RFC-0004.

## What was reused and checked

Use plain Ed25519 APIs from pinned ed25519-dalek 2.2.0 / curve25519-dalek 4.1.3,
with published RFC 8032 data. Five exact signing/verification vectors pass,
134 altered/malformed cases reject, and nine candidate CREDIT tuples match an
independent byte encoder and libsodium signing/detached verification. The
[results](../poc/private-payment/RECOVERY-AUTH-RESULTS.md) retain exact scope.
The compiled curve crate is from its own release commit
`5312a0311ec40df95be953eacfa8a11b9a34bc54`, verified byte-for-byte, rather than
the later curve source colocated in the Ed25519 2.2.0 release checkout.
The host libsodium is 1.0.18; its point-validation API is not used or qualified.
Current upstream documentation records subgroup-validation limitations in that
API through 1.0.20, so independent signature agreement must not be reported as
independent qualification of the candidate point policy.

No wallet relation, refund implementation, native registration, custody path or
funding transaction was built. No external review or message was sent. Human
composition review and the actual proof/native implementation remain gates.

## Primary sources

- [RFC 8032, section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1).
- [Pinned Ed25519 verifier](https://github.com/dalek-cryptography/curve25519-dalek/blob/8016d6d9b9cdbaa681f24147e0b9377cc8cef934/ed25519-dalek/src/verifying.rs).
- [Pinned compiled Edwards point validation APIs](https://github.com/dalek-cryptography/curve25519-dalek/blob/5312a0311ec40df95be953eacfa8a11b9a34bc54/curve25519-dalek/src/edwards.rs).
- [Pinned vProgs deposit policy](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/runtime-processor/src/deposit_policy.rs).
- [Pinned vProgs funding-output checks](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/runtime-processor/src/action/deposit.rs).
- [Pinned delegate-entry bytes](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/abi/src/delegate_script.rs).
- [Pinned native sighash](https://github.com/kaspanet/rusty-kaspa/blob/f7d7877363fb97c2ec6871be0e8cbc351d44df10/consensus/core/src/hashing/sighash.rs), [native v1 identity](https://github.com/kaspanet/rusty-kaspa/blob/f7d7877363fb97c2ec6871be0e8cbc351d44df10/consensus/core/src/hashing/tx.rs).
- [Libsodium point API scope and version caveat](https://libsodium.gitbook.io/doc/advanced/point-arithmetic#point-validation).
