# Financial run a86414d1 operational abort

Run ID:
`a86414d108d6886768f367a3384fd24de49d4fde7475d8469d92adee29c0e6ab`

Status: **consumed, incomplete, never reuse or qualify**.

## Public progress retained

All three parties completed stock proving-key point admission, R1CS row
admission, interparty TLS/MAC/protocol setup, full-trace preflight, and durable
lock. The last typed public stage for all three was
`owner-listeners-ready` at approximately 21:50:23 UTC.

No public `RESULT` or `FAILED` record exists. No completion, financial proof,
privacy, R0/native execution, settlement, or lifecycle claim is permitted.
Private/raw party diagnostics were not read or hashed during this diagnosis.

## Verified cause

The user and kernel journals record a global OOM event at 21:50:26 UTC:

- the kernel killed Codex PID 3478357 in
  `forge-codex-maintenance.service` with about 2.05 GB anonymous RSS;
- the three `mpc-financial` workers were each near 0.95-1.0 GB RSS at that
  instant;
- the `kpi-financial-a864...scope` ended two seconds later after 1h07m30s,
  reporting a 6.7 GB memory peak; and
- the proof cgroup's earlier OOM counters remained zero because the global OOM
  victim was Codex outside that scope.

The run used a client-owned user scope and `bwrap --die-with-parent`. Killing
the Codex/controller process therefore tore down the proof tree. This was not
a typed protocol/proof failure and cannot be retried under the same identity.

## Correction before any retry

- Do not retry yet. `FINANCIAL_CONTROLLER` execution is hard-disabled because
  caller-authored controller/owner hashes and a same-UID registry cannot
  establish fresh independent admission. Only the non-authorizing durability
  probe may execute.
- Before enabling a fresh run, add independently admitted controller and owner
  issuance receipts plus a consumed/abort registry that the child UID cannot
  modify. Follow `DURABLE-FINANCIAL-SERVICE.md`; never use a launcher-owned
  scope.
- Finish/stop heavyweight builds and extra agents before launch; require the
  17 GiB headroom/non-overlap guard.
- Use fresh owner inputs, trial/run/attempt/cohort/TLS identities and roots.
- Build a fresh selected controller because Source05 hard-pins consumed owner
  paths and cannot honestly provide the successor-head Round 2.
- The launcher directly denies this run ID, the Source05 hash, and every path
  under the consumed owner root. An append-only record and tombstones preserve
  the known abort against ordinary selection re-forging or mutable-log
  rollback. They are not claimed to resist their same-UID/storage owner.
- Preserve this negative result unchanged.

