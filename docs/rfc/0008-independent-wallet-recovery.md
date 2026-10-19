# RFC-0008: Stage 1 independent three-wallet recovery

Status: bounded H7 completed, 2026-10-19. [ADR-0020](../adr/0020-independent-wallet-recovery.md).
Offline, full TN10 rehearsal and fresh measured trial passed; all three wallets
exited independently. [Results and remaining limits](../../poc/shared-pool/RECOVERY.md).

## Fixed workload and backups

Fresh 10-tKAS pool (1,000,000,000 sompi). Preserve backups before private sends.
Alice sends 400,000,000 sompi to Bob and 200,000,000 sompi to Carol, retaining
private change after both native fees. Bob and Carol remain offline. Stop the
original Alice prover and all experiment-only state services. Restore Bob,
Carol and Alice separately; each should find one unspent note and create one
full exit. All five created notes must be spent and the reserve fully drained.
This is six transactions: funding, two transfers and three exits.

| Input | Required by | Treatment |
| --- | --- | --- |
| Spending/viewing/native-payout keys | Each wallet | Private backup; never Git or a public service. |
| Initial note opening | Initial depositor | Private backup for recovery before the first transfer. |
| Descriptor hash | Each wallet | Backup's authenticated pool selection; not supplied by an untrusted mirror. |
| Public descriptor, VK and PK | Each wallet | Replicated, hash checked; no address book or secrets. |
| Funding and accepted successor bodies, ciphertexts, input context | Each wallet | Public retained data; authenticate native transitions and chain lineage. |
| Current chain view | Each live wallet | Synced TN10 node; verify accepted bodies and current reserve/payout UTXOs. |
| Software | Each wallet | Pinned source/binary and ordinary native validator, no original coordinator required. |

## Completion and controls

1. One command creates a fresh unfunded identity and its private keys. Seal each
   backup after constructing the funding transaction and before any payment.
   Reject backup,
   descriptor, network/domain, parameter and funding substitution. Cover wrong
   keys, malformed fields and the initial-note boundary.
2. Offline, recover in isolated fresh filesystems with only one backup mounted.
   No original manifest, wallet directories, note exports or prepared exit proofs.
   Check all native transactions and exact SDK round trips. All three native
   payouts must be owned by keys derived from the corresponding backup.
3. Remove the preferred public source; fallback must work. Omitted/reordered or
   corrupted history, stale endpoints, altered ciphertext/proof and a cross-pool
   descriptor must fail or be repaired from authenticated complete data. With
   all history unavailable, fail safely. Replay an already spent claim and
   require native rejection. Do not infer recovery success from safe rejection.
4. Only after offline success: complete a six-transaction TN10 rehearsal, then a
   fresh measured six-transaction trial. All original payment provers stop before
   restored clients start. Each client fetches public updates and submits its own
   payout. The controller may observe results but supplies no spend authorization.
5. Record input/backup schemas, isolation and source failover, original process
   shutdown, parameter loading/proving/scanning/RPC timings, byte counts, fees,
   exact accepted transaction bodies/hashes and all three payout observations.
   Reconcile every sompi and prove no outstanding claims or reserve remain.

At the H6 layout/rate, two transfers and three exits cost 108,565,600 sompi;
ordinary funding is additional and measured from its actual input/change.
This is a planning estimate, not a current fee quote. Rehearsal and trial each
use fresh identities. If a funded attempt fails, retain evidence and recover
outstanding claims through their normal wallet paths before a fresh retry.

## Stop/redesign

Stop the affected experiment for accepted invalid state, incorrect backing,
unauthorized payout, reuse of spent value or private data leaking into public
artifacts. Missing required independent data or inability of any wallet to exit
fails H7 under the declared model. Do not restore access by mounting the original
experiment tree or adding an administrator key. Operational setup errors can be
fixed without weakening checks; resource limits alone must not strand a trial.
Do not call a same-host sandbox result independent-infrastructure recovery.

No cryptographic correctness, network anonymity, indefinite history retention,
general contention fairness or mainnet conclusion follows from this test.
