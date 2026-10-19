# Independent recovery of three compact-pool wallets

Status: offline passed; first funded rehearsal interrupted before an exit
broadcast. Transport fix and ordinary cleanup in progress, 2026-10-19.
Branch: `shared-pool-four-wallet`. [Specification](../../docs/rfc/0008-independent-wallet-recovery.md),
[decision](../../docs/adr/0020-independent-wallet-recovery.md),
[source review](../../research/independent-recovery-source-review-2026-10-19.md).

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
