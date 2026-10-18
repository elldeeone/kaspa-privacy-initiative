# Offline recovery programme: R08–R16

**All requested offline controls have run successfully.** The suite has 80
passing tests: the earlier 66 plus 14 new tests across R08–R16. A separate
three-user rehearsal also completes through synthetic payment and final restore.

This is the offline continuation authorized by the owner, under
[ADR-0014](../../docs/adr/0014-offline-recovery-failure-programme.md). There is no
R00 requirement; the owner clarified the requested range as R08–R16. The full
[recovery acceptance requirements](../../docs/shielded-recovery-test-design.md)
remain separate. In particular, R13's real-proof ordered-execution gate and R16's
independent confirmed-native-payout gate are **not passed**. Every case in the
machine-readable report keeps its full proof/native gate false.

## Run the programme

With the existing [dependencies](RECOVERY.md#run-it) already installed, from the
repository root:

```bash
PYTHONPATH=.local/shielded-design/python PYTHONDONTWRITEBYTECODE=1 \
  python3 poc/shielded-design/recovery_programme.py .local/recovery-programme-NEW
```

Use a new output directory. The command fetches/installs nothing, runs the full
suite, then creates a separate offline shutdown rehearsal. Inspect `report.json`
for counts, per-case scope, source hashes and aggregate synthetic results.
Private test logs, backups, stores, network traces and wallet reports stay under
`private/`. Output directories are 0700 and JSON files 0600. Do not publish that
directory wholesale; only the reviewed report and declared public artifacts
belong in repository evidence.

The [retained report](evidence/offline-programme.json) hashes the exact public
terminal [history](evidence/offline-programme-records.json) and
[checkpoint](evidence/offline-programme-checkpoint.json). Earlier recovery,
transition and payout artifacts remain historical and unchanged. Current source
hashes belong to this programme report, not those earlier runs.

## What each case now demonstrates

| Case | Executed offline result | Still unproved |
| --- | --- | --- |
| R08 | Remove an orphan payout and restore its unpaid claim; replace a deeper history, removing orphan notes, nullifiers, fees and claims. Reject an incorrect common prefix or missing genesis history without changing the current session. | Authentic native fork choice, payout UTXO lineage and real-chain reorg handling. |
| R09 | Actual SIGKILL at four publication boundaries yields the old or new complete generation. Two writer processes yield one success and one stale-revision rejection. Corrupt private scan state and malformed revisions fail. Unknown submissions remain pending until the exact payment appears in the supplied trusted history. | Filesystem/hardware power failure, cross-host writers, real network submission and finality. |
| R10 | An unavailable or incomplete original copy is replaced by a complete archive matching the retained checkpoint. No matching copy returns incomplete data. | Independent long-term retention, actual node pruning and service availability. |
| R11 | Incoming-only backup discovers accepted notes, including spent history, while explicitly declining spendability; spending restore rejects it. Wrong keys/address authorization fail. Missing prover material reports unavailable; substituted bytes fail identity checking. | Production viewing/spending roles and qualification of an actual prover artifact. |
| R12 | Missing external permission rent rejects an exit without consuming funds. Replacement funding lets the exact authorized exit proceed; destination diversion fails. | Native transaction fees, changing fee demand, sponsor-free real settlement/payout and funding linkage. |
| R13 | Ordered valid / invalid / unknown-root / valid model operations continue correctly across restart. A valid ideal predicate under an unaccepted root still fails current-state application. | Real ZK proof classification and forced outcomes bound to the accepted native interval. |
| R14 | Secret canaries are absent from tested CLI/public output. The Python network audit observes no attempts in the tested flows, and an intentional socket control is blocked. | Zero knowledge, anonymity, all diagnostic paths, OS isolation and native/child-code network activity. |
| R15 | Foreign network/pool/lane/genesis, unsupported statement/backup versions and unrecognized migration/verifier fields fail. Existing v1–v3 wire logs remain readable. | Legacy consensus availability, authorized migration and a production verifier upgrade policy. |
| R16 | Producer process exits; its declared path is unavailable. Three fresh user processes each get one backup; a public-only process pays exact claims; three fresh user restorers verify zero outstanding liabilities. | Independent machines/operators, real private proofs, accepted settlement and confirmed native payouts. |

The 14 tests are 2 for R08, 4 for R09, 1 for R10, 2 for R11 and 1 each for
R12–R16. Tests of existing model behavior were added at the existing interfaces;
new rollback, persistence, view and process interfaces were exercised failing
before their implementations. No timeout is treated as rejection evidence.

## Interfaces and assumptions

`RecoverySession.reorganize` validates a replacement full history/checkpoint and
the exact common prefix before swapping the reconstructed session. It never
chooses a blockchain fork itself. Both model horizons remain trusted inputs.
History replay removes all orphan-dependent state together; there is no inverse
transaction guessed from a partial snapshot. A backup expecting orphan receipts
can explicitly return `incomplete_wallet_data`; key-only discovery on the new
complete history is tested separately. No automatic receipt-inventory rewrite
silently discards a user's expected payment.

`RecoveryStore` publishes one protected envelope containing the public export,
derived wallet reports, revision and optional payment intent of unknown outcome.
An exclusive POSIX file lock and revision check guard writers. A synced temporary
file is atomically renamed, then the directory is synced. Load replays the export
and recomputes private reports. Unpublished temporary files from killed writers
are ignored, not treated as committed recovery state. The store never sends a
transaction; its unknown-intent action says to inspect history and not resubmit.
Absence of a payment, including after a fork, preserves that marker. A matching
accepted model effect clears it. Local disk/checkpoint integrity is trusted;
the format is not an authenticated journal against a malicious local host.

`load_retained_archive` tries complete local copies against the caller's retained
checkpoint. It neither trusts a copy's own manifest nor substitutes a checkpoint
from the replacement. `require_prover_artifact` checks availability and SHA-256
identity only; matching bytes do not establish correctness or compatibility.

`make_view_backup` emits `kpi-model-view-backup/v1`, containing incoming secret,
owner/incoming public identities, the existing signed model receive address,
descriptor binding and expected receipts. It omits the spending seed. The view
object shares the strict authenticated receiver checks but has no spend, sign or
nullifier method. Its private result is `view_only_spentness_unknown`, with
`can_spend: false`; historical received amounts are not spendable balances. Its
u64 aggregate range may safely halt on very large cumulative histories. Spending
backups and model key derivation are unchanged. Backups remain unencrypted and
strictly synthetic, not tools for real wallet secrets.

`recovery_shutdown.py` exposes `exit-user`, `pay-all` and `audit-user`. Exit/audit
accept exactly one backup; payment accepts none. The standalone rehearsal uses
one producer plus seven fresh stage processes under the network audit. Each
user funds its own additional model permission rent. This reuses the current
ideal oracle; it does not replace it with real cryptography or enforce isolation
between same-host processes.

## Rehearsal accounting

| Synthetic terminal ledger | Sompi |
| --- | ---: |
| Paid user principal | 1,999,999,000 |
| Paid authorized application fee | 1,000 |
| Remaining principal reserve | 0 |
| Outstanding principal liabilities | 0 |
| Separately returned permission rent | 200,000,000 |

These match the independently worked three-user fixture. No actual miner fee,
native transaction, network query, GPU computation or real ZK proof is required
by this programme. The 1,000-sompi fee is the existing model application fee.

## Adversarial second pass

- **Inflation/double spend:** preserve current nullifiers and paid identities;
  only an explicitly supplied replacement trusted history can remove an orphan
  effect. A malicious or stale checkpoint remains outside this model's defense.
- **Reserve release:** exact unpaid claims constrain synthetic payments. No
  withdrawal key, operator-signature bypass or native release condition is added.
- **Crash consistency:** publication switches a whole generation, and stale
  writers fail. Real killed-process and concurrent-writer results do not qualify
  hardware power loss or cross-filesystem durability.
- **Privacy:** private reports and store envelopes include sensitive derived
  notes. Canary absence and Python socket auditing are bounded observations,
  not proof of anonymity, zero knowledge or an OS sandbox.
- **Dependency loss:** unavailable history/prover material remains incomplete or
  unavailable. It never becomes zero funds, proof invalidity or payout success.
- **Version/fork trust:** wire versions do not create new spend domains. No
  migration path is enabled, and no local checksum establishes chain freshness.

The offline programme is complete within these bounds. The next research work
is the remaining real-proof, accepted-state, native terminal-output and
independent recovery requirements, not declaring the full 16-case gate passed.
