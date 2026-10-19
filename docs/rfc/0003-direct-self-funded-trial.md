# RFC-0003: Direct native-fee trial

Bounded implementation decision: [ADR-0015](../adr/0015-direct-self-funded-tn10-trial.md).

Question: can a user pay privately and independently withdraw native KAS while
paying the miners from the consumed private entitlement, on unmodified TN10?

The fixed state is version1 | commitmentCount1 | nullifierCount1 |
commitments[4*32] | nullifiers[4*32] = 259 bytes. The fixed payload is
`KPIDF01\0`8 | mode1 | nextState259 | ciphertext185 | ciphertext185 = 638 bytes.
Modes 1/2/3 are transfer, continuing exit, terminal exit; exit ciphertexts are zero.

The 431-byte transition preimage is `KPIBND1\0`8 | domain32 | oldState259 |
predecessorTxid32 | predecessorIndexLE64 | reserveInLE64 | reserveOutLE64 |
payoutLE64 | payoutVersionBE16+P2PKscript34 | SHA256(payload)32. Absent payout
fields are zero; absent successor value is zero. Its SHA256 halves are two
canonical little-endian Fr inputs. Both hashes are recomputed inside the circuit.

The native covenant derives all these fields by introspection, enforces the
transaction envelope and output scripts, and preserves its own immutable suffix.
All proof spends have exactly one input, native subnet, version 1, max sequence,
zero gas/locktime, and no covenant-binding metadata. The final exit has no reserve
output. Fees are actual input minus actual outputs, with no external reward output.

Open after this trial: scalable membership/spentness, contention and repricing,
multiple deposits, production setup, long-term data retention, proof latency and
memory, independent cryptographic review, and anonymity under low activity.
Completion of this trial does not resolve those questions or select a production
architecture. Results belong in the experiment README, with evidence boundaries.
