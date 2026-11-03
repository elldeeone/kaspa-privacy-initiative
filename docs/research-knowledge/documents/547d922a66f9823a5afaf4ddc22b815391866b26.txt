# ADR-0015: Direct, self-funded native-KAS trial

Status: accepted for a bounded testnet experiment on 2026-10-19; no production architecture selection.

The owner authorized implementation and TN10 transactions after reviewing the
direct-fee layout, and provided a 200-tKAS ordinary funding UTXO. Earlier
planning-only restrictions do not block this trial. No mainnet, publishing,
committing or upstream posting is authorized by this decision.

## Decision

Implement one covenant reserve, one hidden-membership Groth16 circuit, one
private payment, and two whole-note native exits. Miner fees reduce the consumed
note's entitlement and native reserve together. No sponsor input, relayer
payment, operator signature, admin escape, new token, vProgs runtime or L1 change
is needed for this hypothesis. Preserve SECURITY-INVARIANTS.md unchanged.

Reuse the local private-note experiment's SHA256 commitments, HMAC-SHA256
nullifiers and crypto_box sealed delivery, adapting the domain and adding actual
native transaction binding. Four public commitment slots and four nullifier
slots intentionally replace a scalable tree for this bounded test. Private
membership is constrained equality to one active commitment. The circuit
validates complete old/new states, authorization and nonwrapping u64 balance.

Use the current native BN254 Groth16 verifier (128-byte proof), two public
128-bit halves of a SHA256 transition digest, and a 328-byte VK fixed in an
immutable redeem-script suffix. Start with a 2,048-byte redeem and input compute
budget 1,600; measure the actual script and adjust these operational estimates
if necessary. Never weaken a security predicate to meet the estimate.

The genesis case proves the sole private liability equals the actual reserve.
The terminal exit proves the last note equals the remaining reserve and creates
no successor. This prevents stranded final change and avoids a privileged close.

## Research and alternatives

The current source review and reusable patterns are in research/kaspa-toccata-vprogs.md,
existing-kaspa-privacy.md, zcash-orchard.md, aztec.md, railgun.md, monero.md and
litecoin-mweb.md. The Kaspa v2.0.0 (90dbf074275d60c1fe74a3491883196f110970c0)
Toccata paths and v2.1.0 (01b532e8b553523216471682649693af92f0fd16) validation
and fee paths agree for these transaction shapes. The live node reports v2.0.0,
TN10, sync and a DAA score beyond activation 467579632; that is not a binary hash.
The vProgs suffix-propagation example at f9b84a863a7c7c20586a9cf947550475e894f72e
is adapted without importing its runtime or fee accounting.

Orchard motivates separate membership, authorization, conservation and spentness
constraints; no Orchard code or primitives are transplanted. Aztec and RAILGUN
illustrate fee-service alternatives and artifact/data availability requirements;
no service or privileged upgrade dependency is imported. Monero and MWEB inform
public-fee conservation and public exit boundaries; their native protocols are
not assumed to be Kaspa-compatible. No restricted RAILGUN circuit code is copied.

Permissionless relaying remains an optional transport service. It does not need
to finance this reserve spend. A large based-app system or new consensus rule
would add dependencies before the direct path has been falsified.

## Assumptions and limits

Fresh single-party Groth16 setup is experimental, unaudited and unsuitable for
real funds. Public proving parameters, VK, exact code/lockfile, manifest, accepted
transactions and ciphertexts must be retained. Loss of these can prevent recovery;
the native UTXO root alone is insufficient. Separate Alice/Bob keys and processes
must demonstrate Bob's exit without Alice's private files or a cooperative prover.

Instance identity includes TN10 genesis, fresh domain and canonical funding
outpoint. Wallets follow that outpoint's accepted descendants, never arbitrary
UTXOs matching an address. Additional deposits are unsupported and uncredited.
Recipient acceptance requires successful decryption and commitment/owner checks.
Malformed ciphertext can burn the sender's output; it is not a received payment.

This tiny trial demonstrates confidentiality mechanics, not useful anonymity.
Fees, reserve lineage, timings, ciphertexts, commitments, nullifiers and native
withdrawal amounts/scripts are public. RPC/network metadata is a separate exposure.

## Validation and completion

Require actual proof generation, native Full validation, measured script units,
canonical SDK round trips, default relay checks, and adversarial invalid cases
before experimental funding. Prepare the complete sequence before broadcasting.
Use test KAS only, fresh trial identities on retries, durable single-submit
records, and chain UTXO confirmation of both payouts and reserve exhaustion.
Report actual fees, resource use, failed cases and live-versus-local evidence.
The test is not complete after proving, partial submission, or mempool acceptance.
