# Adversarial second pass

Scope: AI-assisted review of one finite unfunded integration. No independent
human cryptographic audit, accepted native ancestry or production qualification.

- **Minting:** complete original u64/conservation constraints remain; exact source
  comparison checks all constraint code after public packing. Differential
  controls and zero/MAX/overflow tests cover both versions. Native payouts and
  exact successor reserve are pinned, with sponsor fees separate from principal.
- **Authorization:** all current owners approve the same actual native effects.
  Wallet checks execute immediately before positive proving. Native code hashes
  the entire reconstructed statement, including actual outpoint/effects context,
  root, expected economic NF, domain, VK, amount and zero inactive fields. Blind
  credentials cannot spend or override owner proofs.
- **Single spend:** the actual Ledger kernel rejects current economic-NF reuse
  atomically. Finite policy initialization excludes its actual prior spent NFs;
  subset scripts remove exited claims. Native replay rejects stale/current
  contexts; the local UTXO model tests both joint/solo conflict orders and repeat
  proposals. This is not accepted-chain DAG/reorg validation.
- **Packing/encoding:** two 128-bit limbs cover all SHA256 bits; no scalar-field
  reduction aliases. All statement bytes remain bound. Validated canonical,
  complete 128-byte proofs and nonidentity points are required. Actual 0.5 proof
  bytes execute under the pinned native 0.6 verifier. Old VK/profile proofs reject.
- **Delivery:** the new verifier must call the original `Operation.check_public`
  before pairing verification, including ciphertext/commitment binding. This was
  added during implementation review. Rehashed altered ciphertext still fails
  genuine proof verification; it cannot inject an unrelated note into Ledger.
- **Original control correction:** an initial local run used raw recipient keys
  as old EXIT destinations. The actual old native parser uses SHA256(0x00 || key).
  The final control proves/reconstructs that exact commitment. The earlier local
  run remains retained; it is not the published matched original-native control.
- **Privacy:** actual wallet history/ciphertexts, eligibility operations and all
  native bytes remain in observations. Unknown metadata refuses. Coordinator
  key/mode are common, all issuance precedes redemption, and private randomizers
  stay out of identified issuance. Explicit origin/randomizer and owner-map
  controls collapse ambiguity. Logical separation is not network anonymity.
- **Dependency loss/recovery:** wallets restore backups and decrypt actual
  accepted-local records. Solo proofs need no issuer or peer. Those same-host
  checks establish no independently replicated proving parameters/history or
  received-native-output spend. Lost experimental parameters can halt proving.
- **Trust/state:** setup is fresh single-party experimental toxic waste, never
  fundable. The native predecessor is supplied at the actual local kernel's root;
  no complete authenticated outer transition installs it on chain. The old native
  parser/permissions do not already accept this semantic change.
- **Costs:** compute/storage/transient mass, synthetic fees, verification floors
  and paid fees stay separate. Useful value counts two payments once; no credit,
  change or withdrawal is extra useful value. Direct verification misses 2%
  even before other costs. The based-app batching alternative has a different
  denominator and no new measured receipt/path here; do not transfer the direct
  floor or a hypothetical batching saving into a general conclusion.

No invariant, consensus source or historical wallet source changed. Current
capacity, full costs, service/network anonymity, received-output spending,
accepted-state anchoring and specialist review remain material limitations.
