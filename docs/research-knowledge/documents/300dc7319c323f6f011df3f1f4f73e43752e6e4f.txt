# Durable local financial service

Status: **durability probe complete; real financial execution hard-disabled**.

`durable_financial_service.py` prevents a Codex terminal, SSH connection, or
launcher process from owning the lifetime of a multi-hour financial run. It
dispatches a one-shot private selection to the lingering user systemd manager
as a service. The service, not the calling terminal, owns the controller.

This is only a liveness boundary. Its public records never qualify a proof,
privacy, R0/native execution, settlement, or funding.

`FINANCIAL_CONTROLLER` currently fails closed before resource admission, state
creation, registry mutation, or process execution. A mode-`0400` selection is
still authored by the caller: matching hashes do not prove that its controller
or owner inputs were freshly and independently issued. A launched same-UID
child could also rewrite a mode-`0600` user-owned registry. Therefore this
service may execute only `DURABILITY_PROBE` selections until the independent
admission requirements below exist.

The retained `run_financial.py` also refuses every direct execution profile
immediately after argument parsing, before resolving paths, creating output, or
dispatching a process. It is build/control source only; it is not an alternate
way around this service gate.

## Why a service, not a scope

The failed runner used `systemd-run --user --scope`. The outer controller and
its `bwrap --die-with-parent` children remained coupled to the Codex process
tree. A global OOM kill of Codex therefore removed the controller and every
proof child despite zero OOM events in the proof's own cgroup.

The replacement uses a user **service** with:

- user-manager linger required;
- `OOMScoreAdjust=-250`;
- no outer memory, CPU, or runtime limit;
- `KillMode=control-group` and `RemainAfterExit=yes`;
- private child stdout/stderr that the supervisor never reads; and
- public REQUEST, DISPATCHED, STARTED, HEARTBEAT, and TERMINAL records.

The selected financial controller may create its own inner resource scope. A
future Source05-style selection must use a deliberately non-binding inner
memory ceiling (at least 64 GiB on this host) and at most the selected 12-core
quota. The durable outer service adds no timeout or memory kill boundary.

## Pre-launch headroom and non-overlap

A production selection is refused before creating its state root unless:

- `MemAvailable` is at least 17 GiB;
- user-manager linger is enabled; and
- no `mpc-financial`, registered build, C++ compiler, Rust build, or slow
  privacy-launch process is active.

This check runs once before launch. Falling memory later is reported through
host telemetry but never aborts an otherwise valid run. Human/agent scheduling
must still keep heavyweight agents and builds stopped until proving finishes.

## One-shot identity registry

Before a permitted probe creates its state root, the launcher takes an
exclusive lock and atomically claims domain-separated tombstones for the
selection, run, trial, attempt, cohort, owner root, and three owner identities.
It then appends a hash-chained consumed record and matching anchor. Registry
files and directories have fixed device/inode, owner, type, and mode checks.
A partial write or a journal/anchor rollback fails closed; tombstones prevent
ordinary reuse after both mutable logs are truncated. Private identity values,
owner paths, commands, and bodies are never copied to public receipts.

The production registry is preseeded with the a864 abort. The launcher also
directly rejects that run ID, the retained Source05 source hash, and every
owner path below the consumed `20261028-05/owners` tree (including mixed-root
selections).

This registry is not yet an authorization boundary. It is owned by the same
Unix UID as a possible child, so that UID or a storage operator can delete or
rewrite both logs and tombstones. The unconditional financial-controller block
is the safety control for this unresolved boundary.

## Exact gate required before a fresh financial launch

There is intentionally no working financial launch command now: invoking
`--launch` with `kind=FINANCIAL_CONTROLLER` returns 78. Do not bypass that
refusal. Before removing it:

1. Create a genuinely fresh owner-input/trial identity. Do not reuse an
   aborted run, owner inputs, trial, attempt, cohort, TLS roster, or output
   root.
2. Build and independently admit the exact controller artifact. The retained
   Source05 controller is
   not reusable because it hard-pins the already consumed `20261028-05` owner
   paths and fixed genesis head.
3. Produce independent owner-issuance receipts binding the fresh trial,
   attempt, cohort, all three owner-input identities, and the admitted
   controller. The launcher must verify those receipts without exposing or
   hashing private owner bodies.
4. Move the consumed/abort registry behind an authority that the selected
   controller and its UID cannot modify, truncate, replace, or delete. Retain
   atomic one-shot reservation before state creation.
5. Add controls proving omitted, reused, rolled-back, copied-stale, and
   re-forged selections cannot execute. Review the source change that removes
   the unconditional block.
6. Only then write a canonical mode-`0400` private
   `kpb-durable-financial-service-selection/v1` containing:
   - fresh 64-hex run ID and matching
     `kpi-durable-financial-<run>.service` unit;
   - exact program/argv plus hashes and sizes for the interpreter/controller
     artifact closure;
   - three public stage paths and exact RESULT/FAILED marker paths for that
     run;
   - `minimum_mem_available_bytes >= 17 GiB`;
   - outer argv with the run ID exactly once, no `--inside-scope`, at least
     `--memory-gib 64`, at most `--cpu-cores 12`, and three fresh owner paths;
   - the exact fixed resource policy; and
   - every authority Boolean false.
7. Run exactly:

   ```text
   python3 poc/local-private-payment/mpc-prover/financial/durable_financial_service.py \
     --launch --selection /absolute/private/SELECTION.json
   ```

   The command returns after systemd accepts the service. It is safe for that
   terminal to disappear.
8. Observe only the public state root and the unit:

   ```text
   systemctl --user show kpi-durable-financial-<run>.service
   ```

   `HEARTBEAT.json` reports the public phase. `TERMINAL.json` reports the child
   exit and marker presence without reading private logs. Neither is proof
   authority; the normal public qualifier must still verify the fresh run.
9. Retain the unit and state until evidence review. Only then explicitly stop
   and reset the unit. Never reset/reuse the run identity.

## Controls

Ten controls use real transient user services only for tiny synthetic children.
They cover service survival after launcher exit, success/nonzero terminal
capture, no public command/path/identity export, unlimited outer resources,
reduced OOM score, headroom/non-overlap refusal, consumed-identity re-forging,
journal rollback against tombstones, exact and mixed-path a864 owner reuse,
and unconditional self-authored financial-controller refusal. Synthetic probe
results use a distinct non-authorizing outcome and are never financial
evidence.

