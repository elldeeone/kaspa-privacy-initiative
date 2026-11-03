# Offline native private / admission / revealing-exit union

Research-only, public synthetic DO_NOT_FUND. No node, broadcast, wallet, old
proving key or owner workflow. Native upstream is locked to `01b532e8…`.

The actual22,388-byte immutable P2SH policy contains:

- PRIVATE: genuine two-public-input Groth16 verification plus native current
  CM/NF updates, actual outpoint/reserve/fee and immutable successor checks.
- ADMIT: public Note168/CM/cipher binding, current CM append, externally funded
  principal+fee, exact owner change and native verification of both inputs.
- REVEAL: original positioned NF, current membership/nonmembership, CM-bound
  native key with exact ALL, full-note payout+fee, immutable continuation or
  conditional zero-liability terminal consumption.

The approved byte contracts are under
[`research/next-session/private-integration`](../../research/next-session/private-integration/NOTE-STATE-CONTRACT.md),
with the separate [ADMIT contract](../../research/next-session/private-integration/NATIVE-ADMISSION-CONTRACT.md).
The common signature/proof pushes place the redeem script at byte199. State112
is the only mutable policy prefix; the actual VK is in its immutable suffix.

`{private,admit,reveal,founding,funding-prep}-freeze VECTOR.json OUT` constructs,
signs and measures a body **without** running native VM/Full. Matching `-run`
modes additionally run official Full and every actual input engine. Outputs
include exact `transaction.json`, `validation-case.json`, supplied context,
official dimension masses, integer fee quotes100/200/500, raw txid and output
outpoints/SPKs. Founding and funding-prep are ordinary signed P2PK bodies.

`validate-transaction CASE.json OUT` runs the frozen raw native case. The
preparation-only `control-resign-freeze` retains the original supplied entry SPK
while signing a mutated public development control under the requested genuine
sighash; `control-normalize-freeze` recomputes cached txid/storage mass for an
unsigned mutation. These finite tools have no coin selection or persistent keys.

Actual measured controls and the retained3 typed prediction errors are recorded
in [NATIVE-RESULTS-01](../../research/next-session/private-integration/native/NATIVE-RESULTS-01.md).
The complete six-operation primary lifecycle is separate evidence under
[`lifecycle`](../../research/next-session/private-integration/lifecycle/CONTRACT.md).
Supplied history/UTXOs are explicit oracles. Native acceptance and passing tests
do not establish accepted backing, cryptographic correctness, data availability,
financial privacy or production security.

Keep reviewed executables in immutable external copies. The Cargo release path
is mutable and must never be the sole retained identity of an active run. No
build target or development proving key belongs in Git.
