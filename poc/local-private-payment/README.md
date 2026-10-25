# Independent-wallet native KAS payment research

This is the [ADR-0066](../../docs/adr/0066-local-native-kas-payment-prototype.md)
implementation of [RFC-0029](../../docs/rfc/0029-local-native-kas-private-transfer.md).
It uses native **test KAS**, established cryptographic components and a fresh
domain/profile. It is not a mainnet release, cryptographic audit or production
privacy claim. Existing pools and the older frozen study are unchanged.

One wallet creates a recipient note and recoverable change without another live
spending owner. The receiver's exact invoice must be independently authenticated.
Both outputs have private order and encrypted derivation indices. Original-seed
scanning needs public history rather than a roster or saved lookahead. Direct
Exit152 does not require the shared outer prover.

The public ledger still groups one NF with two outputs and reveals fees,
reserve movement, timing and transparent cashouts. Tor with remote DNS, TLS and
isolated sessions avoids direct fallback; it does not establish global traffic
anonymity or erase invoice/counterparty linkage. Local OS-RNG trusted setup and
shared-head contention remain explicit research assumptions.

## Evidence and execution

See the [retained results](../../research/next-session/local-private-payment/RESULTS.md)
for genuine component, GPU and native verification, recovery, negative results
and the current testnet boundary. Passing controls does not prove cryptographic
correctness. Actual confirmed payouts are a separate gate.

- [SPEC.json](SPEC.json): domain, tags, geometry and scope.
- [Bootstrap](bootstrap/README.md): fresh identities, transparent genesis,
  own-only approvals and testnet funding.
- [Chain](chain/README.md): Tor-only official SDK, exact whole-case confirmation
  and once-only submission.
- [Campaign](integration/CAMPAIGN.md): private scheduling, six payments and nine
  independent cold exits under the fixed 21-KAS useful-payment workload.
- [Recovery handoff](../../research/next-session/local-private-payment/recovery-release/COLD-CAMPAIGN-INTERFACE.md):
  authenticated downloaded software, Exit parameters and original-seed recovery.

Private backups, intents, invoices, schedules, logs and ownership maps stay
outside Git. Executables and public proving parameters are separately selected
artifacts. Never reuse a used trial identity or retransmit an uncertain submit.

The old 2% all-in fee target remains failed. Quotes, supplied-context Native Full,
public-node admission and confirmed payouts are separate evidence classes.
