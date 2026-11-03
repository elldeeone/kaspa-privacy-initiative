# Future monitor correction — not used in either GPU experiment

The historical actor runner remains byte-identical. Its topology guard saw an
already authenticated worker during exit: the same PID/start tick had
no exe symlink and an empty cmdline while NVML still reported memory. The
historical sample did not record process state; these observations are
consistent with exit. Actual Z state is observed only in the new regression. The
old Path.resolve(strict=False) converted that missing symlink into a literal
/proc/PID/exe string, so the guard falsely classified a new live executable.

`pid_lifecycle.py` replaces that decision with a reusable runner seam:

1. Read PID/start/state consistently; missing exe/cmdline remain unavailable.
2. Register exact primary/secondary PID/start identities only after the caller
   verifies cgroup, qualified executable and the actual fixed worker config.
3. Pass every raw NVML row to `evaluate_gpu_topology`. A registered identity in
   Z/X is an exited/stale sample. Keep its reported memory in the sum; never
   replace it with zero. It does not trigger the unexpected-live-worker stop.
4. Reused PIDs, live foreign executables, RPC parent GPU use and a third GPU
   process still stop. Unregistered or unavailable identities make resource
   evidence incomplete. An old PID number alone never establishes ownership.

The topology evaluator is the concrete runner revision seam; it has no GPU,
proof or systemd execution entry point. Future wrappers must call it in place
of the old exe/cmdline-only guard and preserve all raw classifications. They
must also make final stop idempotent: even if an earlier stop unloaded the
unit, always audit every observed PID/start identity and GPU/cgroup cleanup
in a finally block. An absent unit is not proof that its processes disappeared.

Regression command (Python standard library only):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_pid_lifecycle
```

Run from this directory. The test creates a real waiting child, authenticates
its live identity, exits it without reaping, confirms actual Linux Z state,
missing exe and empty cmdline, and tests the production evaluator. It then
reaps the child. Separate cases retain live foreign/reused/unregistered/parent
and extra-worker rejection or incomplete evidence. No GPU proof was rerun.
