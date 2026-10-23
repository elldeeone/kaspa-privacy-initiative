# Private native action prototype

This new, unfunded domain implements the shared Auth528 private action in
[ADR0050](../../docs/adr/0050-proof-private-native-cashout.md) and the
[frozen contract](../../research/next-session/privacy-recovery/PRIVATE-EXIT-CONTRACT.md).
`P=0` transfers private value; `P>0` also pays an owner-selected native P2PK
destination. The terminal `R'=0` case consumes the reserve without appending
commitments. Two authenticated nullifier insertions remain mandatory.

The original policy and funded development instances are unchanged. This is
research code, with no mainnet, accepted-history, privacy-qualification or
security-audit claim.

`kpi-private-exit-native MODE INPUT_JSON OUTPUT_DIRECTORY` constructs ordinary
funding, founding, admission, private and emergency REVEAL transactions.
`*-freeze` constructs and quotes without running a VM. `*-run` additionally
runs official supplied-context Full validation and every input ScriptEngine.
Private vectors contain `auth_hex` (528 bytes), `cipher_hex` (528),
`public_witness_hex` (3344), `proof_hex` (128), and `vk_hex` (328). The selected
public development domain is
`aa39ad5d2da85dfd1695cc74ce3e0f23e713f315d6e5341bccc8a060111354c2`.

The source-generated union is 24,417 bytes. The immutable selected executable
and source/build identities are recorded in
[`native/`](../../research/next-session/privacy-recovery/native/).
No executable, target directory or proving key belongs in this package.

## Ordinary controls

1. `prepare_controls.py --native ELF --prepared MATERIALIZED_DIRECTORY
   --proof-root PUBLIC_PROOFS_DIRECTORY --setup-report NEW_SETUP_REPORT
   --output FRESH_DIRECTORY` verifies the four new genuine proof reports and
   emits positive bases and mutations. Only `private-freeze` and
   `control-normalize-freeze` are called. Preparation does not run a VM.
2. `freeze_controls.py --expected FRESH_DIRECTORY/EXPECTED.json --output FILE
   --review-note NOTE` hashes source, selected executable and actual serialized
   cases for independent review. The coordinator adds `--authorize` after the
   source/fixture release.
3. `run_controls.py --freeze FILE --reviewed-freeze-sha256 SHA
   --expected FRESH_DIRECTORY/EXPECTED.json --output FRESH_RUN_DIRECTORY` runs
   exactly that packet. It retains typed engine/Full outcomes and mismatches.

Controls distinguish rejection before the 14,750,000-unit Groth16 floor from
valid-curve original-proof replays that must reach Groth16 and fail integrity.
The latter mutate destinations, native amounts, outpoints and ciphertext while
preserving preceding public checks. Negative-zero u64 controls document the
native sign-magnitude decoder boundary: the circuit interprets Auth amounts as
unsigned integers. Genuine current-root occupied-nullifier competing spends
belong to the separate lifecycle packet; changing an old witness is not
presented as that experiment.

Fees depend on the emitted body and KIP9 storage context. At rate100, one
two-public-input Groth16 check alone costs at least 14,750,000 sompi. A private
two-recipient transfer plus their two independent private exits has three such
checks: 22,125,000 sompi per recipient before ingress, bytes and storage. That
already exceeds the retained 2% target for a 10-KAS payment.
