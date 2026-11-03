# ADR-0080: Fresh owner-derived Exit destinations

Date: 2026-10-28.

Status: Implemented. Twenty-seven focused wallet, authorization and recovery
checks passed. Two genuine existing-key AuthExit proofs passed independent
Arkworks verification and actual NativeFull execution, with changed destination,
fee, head and stale-signature controls rejected. Those controls use public
synthetic inputs; private Original linkage measurement and accepted-chain
recovery remain separate, unqualified requirements.

## Concrete privacy failure

The current Invoice208 gives a payer the recipient's `native_pk`. The wallet
then forces an independent Exit to that same key in `prepare_exit` and
`authorize_exit`. A payer can therefore match a later transparent payout to the
invoice without breaking encryption, commitments or proofs. Publishing complete
owner-labelled Invoice208 records in a common catalog would spread this lookup
to everyone. Do not publish that catalog as a privacy repair.

This differs from the pair-tag negative control: the current aggregate format
already omits public pair tags. No pair-tag relation change is needed.

## Decision

Derive a fresh self-controlled native payout key inside the owner's isolated
wallet. Use the existing HMAC/KDF and secp256k1 implementation with an explicit
new purpose label, the wallet's secret, and the public note/Exit identity. Pin
the exact byte encoding, scalar rejection and retry counter before execution.
The identity must distinguish the note's NF, selected head and Exit nonce.
The same Original plus authenticated public Exit data must reproduce the key;
no private payout journal or sender state may be required.

New authorization must compare the actual payout script with this internally
derived fresh script. It must also retain the exact owner-approved integer
amount and fee, current head/NF, membership, ownership and complete signed Exit
statement. An arbitrary caller script or `approved` Boolean cannot replace that
check. Reject the invoice-known destination rather than silently falling back
when fresh derivation fails.

The existing AuthExit relation already binds the destination through the exact
effects digest and AK-bound signature. Its circuit does not require payout to
`Note.native_pk`; that equality is a wallet policy. The independent source review
traced statement SHA limbs, all AK bytes, the signature join, actual native
output reconstruction and Exit-VK verification. Reuse that contract unchanged:
no new primitive, D/ProfileID, proving key, verification key, public ABI or native
withdrawal authority is introduced for this repair. Keep `Note.native_pk` in the
existing commitment encoding; do not reinterpret old notes or proofs.

Historical scans must still recognize authenticated old payouts to invoice
keys. They must also rederive fresh payout keys from public Exit identity and
the Original. Historical compatibility is not a fallback for creating new
invoice-linked payouts. Do not label a valid protocol-authorized historical
destination invalid merely because a newer wallet would choose differently.

## Reuse and alternatives

Reuse the existing purpose-separated wallet KDF, canonical scalar/X-only key
derivation, native payout script, signed effects and Original-only recovery.
The [source refresh](../../research/next-session/local-private-payment/privacy-next/PRIVATE-BATCH-SOURCE-REFRESH-2026-10-28.md)
already compares Kaspa, vProgs/research, Orchard, Aztec, RAILGUN, Monero and MWEB.
The relevant mature-design principle is separate spend authorization from
output discovery and transaction routing; none of those protocols' security
claims transfers to this implementation.

Removing a route log does not remove the observed route. A common clear
publisher still sees an owner-to-candidate correspondence. Tor/common submission
and recipient-oblivious invoice retrieval remain separate concrete transport
work, with their own actual-view tests. They cannot repair a destination that
the counterparty already knows.

Changing AuthExit or regenerating parameters is unnecessary for this wallet
repair. Mandatory withdrawal batching, a working-balance requirement and
privileged withdrawal approval are rejected: independent Exit remains available.

## Required decisive evidence

1. Freeze the observer inputs and attack before execution. The baseline observer
   receives legitimate invoices and actual public payout scripts; exact address
   lookup must recover the known linkage. Test the same direct lookup against
   fresh privately generated destinations, retaining amount/timing and the
   colluder's legitimate knowledge. Count edges and compatible assignments;
   do not turn them into posterior probabilities.
2. Produce a genuine existing-key AuthExit proof for a fresh destination and
   validate the actual native candidate. Changing destination, amount, fee or
   head without fresh owner authorization must refuse. Wrong-key, malformed
   scalar, NF replay and wrong-state checks remain mandatory.
3. Reopen from the Original and authenticated public data only; reproduce the
   payout key and demonstrate that it controls the actual payout script. Test
   deterministic replay, distinct notes/nonces/heads and old-history recovery.

The old frozen cyclic workload/H1 failure remains unchanged. This repair removes
one direct invoice-address join; it does not hide public amounts, times, cohorts,
known social counterparties or all terminal inference. Complete corrupt-server
and terminal views remain required for broader privacy claims. Passing these
bounded controls is not a proof of cryptographic privacy or production safety.

I-1 through I-16 remain unchanged. In particular, the exact authorized payout
binding, single spend, native backing, independent Exit and recoverability stay
mandatory. No mainnet or real funds are used.
