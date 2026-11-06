# Retained attempts

The first host preflight (`6743983b-75ab-4736-a5c2-526065761328`) stopped before
any settlement: rebuilding the executable while its parent was running made a
later self-spawn use a deleted executable path. No receipt, native acceptance,
privacy result or chain action is claimed. Its private runtime and log remain.

Fix: copy the exact executable into each attempt's immutable monitor directory
before starting any wallet/prover child. Never rebuild that running copy.

The completed experiment will identify its frozen source snapshot separately.

The second preflight (`21949623-ea56-4c54-8a59-b74dd1d3b94b`) was deliberately
stopped before settlement after observing about 65 seconds per cold wallet
request: the one-shot harness reloaded/checked the entire public proving key
for every operation. No crypto check was relaxed. Persistent per-wallet actors
now check/load their public parameters once, reuse them in that process, and
restart from their own backups before payout-spend controls. This keeps cold
loading visible without imposing it on every ordinary wallet operation.

Complete host preflight `57e8bc37-dae2-4631-ac3e-68e7e16d16a8` passed both
drainage paths; it created no outer receipts/native acceptance. The six added
guard controls were separately checked against its actual public group input.

The frozen genuine campaign `3e5c9883-0ab1-41ae-b083-36c41db73459` completed
eleven proving executions and both Full-validated histories. Its source freeze
precedes the source checkpoint `0f2735c4`; exact producing source hashes match.
Post-execution analysis/export helpers are separate from that producing epoch.

Supplement `a4c97494-4197-4894-92f4-b6ff3098cff6` completed owned-worker
cancellation and a fresh fully reverified replacement. Its own source freeze
includes the runner/checker and the unchanged original program/host identities.
The public package retains both epochs and the original obsolete receipt.
