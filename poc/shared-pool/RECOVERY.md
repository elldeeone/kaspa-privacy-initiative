# Independent recovery of three compact-pool wallets

Status: **bounded Stage 1 passed** — offline recovery, a complete TN10 rehearsal
and a fresh measured trial, 2026-10-19.
Branch: `shared-pool-four-wallet`. [Specification](../../docs/rfc/0008-independent-wallet-recovery.md),
[decision](../../docs/adr/0020-independent-wallet-recovery.md),
[source review](../../research/independent-recovery-source-review-2026-10-19.md).

## Result and decision

All three wallets recovered from pre-payment backups and received their native
payouts after the original Alice prover and public HTTP source stopped. Each
restored client used a separate host, its own backup, an independently retained
public copy and a different RPC node. Each generated its first private exit
proof after restoration. No original wallet directory, receiver list, new-note
export, precomputed exit proof or operator signature was provided.

| Wallet, in exit order | Confirmed payout, tKAS | Parameter load, seconds | Private proof, seconds | Complete recovery, seconds |
| --- | ---: | ---: | ---: | ---: |
| Bob | 3.782704 | 104.666 | 12.196 | 136.012 |
| Carol | 1.782704 | 105.413 | 12.273 | 150.787 |
| Alice | 3.348936 | 104.560 | 12.368 | 150.532 |

These are the fresh measured trial's three observations. Five commitments were
created and spent; no reserve or unpaid claim remained. All six transaction
bodies/full hashes matched the original node's accepted-chain data. Each wallet
also checked its own exact accepted exit through the separate public RPC, and
both nodes confirmed the payouts. Cleanup and rehearsal paid the same amounts.

The recovery host exposed eight logical CPUs on a Ryzen 9 7940HS and roughly
8 GiB RAM, while also running the existing TN10 node. Proving used
`RAYON_NUM_THREADS=4`. Peak prover RSS was 2.74–2.77 GiB, excluding Node/RPC and
the full node. Each restored client read 478,670,543 bytes from its public copy;
478,600,432 bytes were the proving key. These are cold-restoration measurements,
not routine payment latency or general hardware benchmarks.

| Live sequence | Accepted transactions | Total fees, tKAS |
| --- | ---: | ---: |
| Interrupted rehearsal plus ordinary wallet cleanup | 6 | 1.087705 |
| Fresh complete rehearsal | 6 | 1.087705 |
| Fresh measured trial | 6 | 1.110008 |
| Reuse of owned ordinary outputs for funding | 5 | 0.013730 |
| Entire Stage 1 live work | 23 | 3.299148 |

Each pool's two private payments and three exits cost 1.085656 tKAS. Ordinary
funding was additional: 0.002049 tKAS in rehearsal and 0.024352 tKAS in the
measured trial. The latter's small change output increased mining/storage mass
to 24,352; the funding builder charged the measured mass at 100 sompi/mass.
The interrupted prefix is counted once, within its cleanup sequence. Its
unsubmitted proof incurred no native fee. Aggregate accounting reconciles
21.539188 tKAS of initial ordinary inputs to 18.240040 tKAS of remaining ordinary
outputs and 3.299148 tKAS of fees.

**Decision:** retain this recovery path and its explicit backup/public-data
requirements for the compact candidate. Stage 1 is complete for three synthetic
claimants from one initial deposit per pool. This does not close every roadmap
recovery condition or establish useful privacy. Stage 2's chain-only privacy
audit is next; do not expand wallet features merely because recovery passed.

## Failure, controls and evidence

The first funded rehearsal stopped after its two payments: Bob's proof finished,
but synchronous parameter decoding/proving blocked WebSocket processing and the
RPC connection disconnected before submission. The reserve was observed unspent
and no exit submission intent existed. The client now closes RPC during local
proof work, reconnects and checks the current reserve before broadcasting.
Fresh independent wallet runs drained that interrupted pool. A separate full
rehearsal then passed before the measured trial; cleanup was not used to satisfy
the complete-rehearsal gate.

Offline validation covered all three restores, 26 recovery controls, 113
inherited native rejections and independent public-tree/ledger reconstruction.
Controls include wrong backups/keys/parameters, pool/domain substitution,
malformed amounts, missing/reordered/corrupted history, stale or forged heads,
spent claims and unavailable public sources. A valid short archive can extend
from accepted chain data; unavailable required sources cause a safe halt.

Execution code checkpoint: `6fa1ea3`. Every run records exact source and binary
hashes; the final offline gate, cleanup, rehearsal and trial match. The existing
compact circuit, covenant, setup and fee/note floors were unchanged.

- [Measured summary](evidence/2026-10-19-recovery/summary.json),
  [aggregate accounting](evidence/2026-10-19-recovery/aggregate-accounting.json),
  [backup inventory](evidence/2026-10-19-recovery/backup-inventory.json).
- [Final offline gate](evidence/2026-10-19-recovery/offline/offline-result.json),
  [rehearsal](evidence/2026-10-19-recovery/rehearsal/result.json),
  [fresh trial](evidence/2026-10-19-recovery/trial/result.json).
- [Interruption](evidence/2026-10-19-recovery/interrupted-run/summary.json),
  [cleanup](evidence/2026-10-19-recovery/cleanup/result.json),
  [runtime](evidence/2026-10-19-recovery/runtime-environment.json),
  [artifact checks](evidence/2026-10-19-recovery/artifact-verification.json),
  [adversarial second pass](RECOVERY-REVIEW.md).

Exports contain no backup keys/openings or proving key. The descriptor retains
its exact original bytes so its backup pin remains valid. Other sanitized JSON
records retain separate source/export hashes. This evidence deliberately labels
synthetic wallets and is not a chain-observer input or an anonymity measurement.

## Question and fixed workload

Can an offline recipient recover a new private payment and withdraw using its
own pre-payment backup and public data, after the original wallet and data
service stop? All three wallets must exit independently with exact conservation.

Alice funds a fresh 10-tKAS pool, sends 4 tKAS to offline Bob, then 2 tKAS to
offline Carol. Stop Alice's original prover. Restore Bob, Carol and Alice in
separate processes with separate writable filesystems. Each scans ciphertexts,
rebuilds state, creates its first private exit proof and submits its own payout.
The pool has six native transactions and five created/spent commitments.

## What must be backed up

| Input | Private? | Why it is needed |
| --- | --- | --- |
| Three existing 32-byte spending, viewing and native-payout keys | Yes | Discover/decrypt notes, authorize spends and own native payouts. This prototype has no mnemonic derivation. |
| Backup format and SHA256 of the pool descriptor | Keep with keys | Select the intended pool rather than trusting whichever descriptor a server returns. |
| Initial note opening, for Alice | Yes | Recover the original deposit before it is spent; the funding commitment cannot reconstruct its randomness. |
| Descriptor, 328-byte VK, proving parameters and accepted transaction bodies | No | Authenticate funding, reconstruct trees and witnesses, scan ciphertexts and prove. Keep independent copies. |
| Retained chain view and current UTXOs | No | Establish current accepted state; replaying valid files alone cannot establish freshness. |

Backups are sealed before either private payment. Bob and Carol's backups
contain no incoming note opening, membership path, proof or future transaction
list. The public descriptor contains no original receiver/address book.

The initial-note control distinguishes a real limitation: Alice's keys alone
find zero notes at the funding-only state; adding her initial opening finds one.
It is not necessary to supply newly received plaintext notes to recipients.

## Isolation and public data

Offline clients have no network and cannot mount the original experiment tree.
Live clients run on a separate host, in a fresh filesystem/PID namespace, as the
unprivileged SSH user with no effective capabilities. The host uses privileged
mount setup because it disallows ordinary user namespaces. This is process and
file isolation, not a claim of separate human ownership or hostile-host security.

The original public HTTP source is first checked reachable, then stopped.
Each wallet records that source failing and uses an independently retained
static public copy. The copy contains the descriptor, VK, PK and the first three
transactions. The restored client obtains later exits from a separate public
TN10 RPC, following reserve outpoints without a supplied list of future IDs.
Both nodes must agree on the exact final accepted transaction bodies and hashes.
The remote host and copies remain controlled by the experimenter; independence
here means recovery without the original services or private wallet directory.

Archive-byte metrics count files read/copied by a restored client. They exclude
RPC wire traffic and transport overhead. Proof timing excludes cold parameter
loading; total wallet time includes both and public discovery/confirmation.

## Reproduction

This run reused the pinned compact setup from H6. The 478,600,432-byte proving
key was independently copied to the recovery host before shutdown. It is public
in the cryptographic sense (not secret), but no permanent public hosting is
provided by this experiment. It is omitted from Git. To reproduce a fresh
experiment, generate a new setup with `kpi-compact setup /private/params`; to
reproduce these exact instances, retain the files matching the descriptor pins.
Never copy a private trial root into Git.
The existing compact binary implements the unchanged circuit/covenant; build the
additional `kpi-recovery` binary from this branch. Set `KPI_BINARY` to the compact
binary, not the earlier `kpi-shared-pool` executable. Both binaries must be in the
same directory unless `KPI_RECOVERY_BINARY` is set.

```sh
cargo +1.95.0 build --release --locked --manifest-path poc/shared-pool/Cargo.toml --bin kpi-compact --bin kpi-recovery
export KPI_BINARY=/absolute/path/to/kpi-compact
node poc/shared-pool/recovery-trial.mjs new /private/params /private/recovery-tests
node poc/shared-pool/recovery-trial.mjs offline /private/params /private/recovery-tests
```

For live recovery, copy the pinned binaries, Node, SDK and the six recovery
runtime modules onto the separate host. `recovery-remote.mjs` declares the
current trial-path convention. Set `KPI_RECOVERY_HOST`, `KPI_RECOVERY_REMOTE`,
`KPI_RECOVERY_RPC` and the original host's reachable `KPI_ARCHIVE_HOST` as needed.
The original funding address must have an ordinary testnet UTXO above the fresh
pool amount plus its funding fee. The wallet clients require no fee sponsor.

```sh
node poc/shared-pool/recovery-live.mjs rehearsal /private/params /private/live /private/offline-result-root
node poc/shared-pool/recovery-live.mjs trial /private/params /private/live /private/offline-result-root /private/rehearsal-root
python3 poc/shared-pool/export-recovery.py trial /private/trial-root poc/shared-pool/evidence/EXPERIMENT/trial
python3 poc/shared-pool/check-recovery-evidence.py poc/shared-pool/evidence/EXPERIMENT/trial
```

Live execution checks matching source/binary hashes against the completed
offline gate. A fresh measured trial requires a complete funded rehearsal.
Never rerun a used identity's broadcaster. Preserve an interrupted trial and
recover outstanding claims using ordinary wallet exits before starting fresh.

For the tested interruption before any exit, `restore-offline PRIOR BASE`
repeats all three recoveries against a saved synthetic fixture. The live
`cleanup PARAMS BASE OFFLINE_ROOT INTERRUPTED_ROOT` mode creates a fresh recovery
identity for an existing pool and requires the original pre-exit reserve to
remain unspent. It does not rebroadcast earlier transactions and does not count
as a successful full rehearsal. More general interruptions need a separately
reviewed recovery path; do not force this bounded helper past its checks.

The evidence checker needs no private backups. It verifies export hashes, public
tree/lineage reconstruction and the complete integer ledger. With `KPI_BINARY`
set, it also revalidates all six native transactions. It does not independently
establish current chain acceptance or ownership of secret payout keys.

## Limits

Correct synchronized nodes, retained public history, available proving software
and the existing single-party setup remain assumptions. No new consensus rule,
privacy token, privileged signer or reserve withdrawal path is introduced.
This does not test arbitrary pruning, reorg rollback, fee repricing, prolonged
contention or unattended backup operations. Separate RPC/network privacy and
chain-only inference remain open. Synthetic payouts do not measure real-world
anonymity, and passing rejection controls is not a cryptographic audit.
