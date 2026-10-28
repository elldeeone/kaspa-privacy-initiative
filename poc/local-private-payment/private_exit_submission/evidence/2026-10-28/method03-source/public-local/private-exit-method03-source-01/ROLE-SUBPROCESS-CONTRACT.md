# Finite METHOD03 role subprocess metadata — source only

No new Original, note, proof, private capture, pipeline, network or broadcaster
is authorized by these files. The passed e2e4/7d65/88cb/0582 sources and prior
evidence remain unchanged. Root must freeze the complete new method, source,
clock procedure and persistent budget before any actual vector execution.

`install(role, emit_metadata)` replaces `subprocess.Popen` inside one NEW
selected actual-role wrapper with a subclass of the original class. It calls
the original constructor/methods with the same arguments and values. It does
not inspect environment contents, stdin/stdout/stderr data, config files,
credentials, request/frame/candidate bytes or `communicate(input)`/returned
buffers. Constructor, wait, communicate and poll exceptions propagate normally.

The returned handle's `stop_tor()` is limited to service/client0. It requests
termination through the original methods of that actor's tracked known Tor
children. The unchanged0582 role still polls, waits and emits its actual first
exit observation. A NEW wrapper may read exact STOP+EOF on its existing Tor
stdin and call this method; it must not terminate bwrap before those lifecycle
records can drain. No stream/config buffer is inspected. Unknown/refused child
coverage remains the outer driver's explicit INCOMPLETE cleanup responsibility.

Only exact current argument grammars are metadata-admitted: owner slots0..5
use `/runtime/prover` with no arguments; transport slots0..5 use the exact88cb
curl33-argument request; service/client0 use the exact0582 Tor invocation.
Unknown/buffer/secret-bearing argument or option shapes execute unchanged but
emit a fixed metadata refusal with no rejected value. A refusal is missing/
unmodeled evidence, never permission to claim complete primary coverage.

All public process records have schema
`kpb-method03-role-subprocess-event/v1` and common fields:

```
schema,kind,actor_role,clock_role,subprocess_index,
actual_local_pid,actual_local_ppid,pid_namespace:{link,inode},operation
```

`subprocess_index` is a local numeric Popen-call counter, not a request, response,
packet, digest or content ID. `actual_local_pid` comes from the original Popen
result; `actual_local_ppid` is the calling actor's `os.getpid`, not its PPID.
`pid_namespace` is read in that actor; current and child namespaces must agree
for admitted records, so the child's PID is interpreted in that namespace.
Missing/changed namespace evidence produces an explicit refusal. Host PID and
FD/argv/mount/order joins remain duties of the selected outer launcher.

Launch kind `role-subprocess-launch` adds exactly:

```
pre_Popen_monotonic_ns,post_Popen_monotonic_ns,argv,pass_fds,
stdio:{stdin,stdout,stderr},close_fds,env_mode
```

Each stdio value is `{kind:INHERITED|PIPE|STDOUT|DEVNULL}` or `{kind:FD,fd:int}`.
The environment mode is only `explicit`/`inherited`; contents are never read.
Exit kind `role-subprocess-exit` adds exactly
`observed_wait_monotonic_ns,returncode,observation`, where observation identifies
the first recorded original wait/communicate/poll that observed an exit.
The exit is emitted once, and nonzero codes remain visible. For a unique curl
whose actual fixed202 status is later observed, this real wait observation can
give a stronger causal upper bound. Returncode0 alone never proves HTTP202.

Refusal kind `role-subprocess-refusal` adds exactly
`pre_Popen_monotonic_ns,post_Popen_monotonic_ns,reason`. PID/namespace may be
null only when unavailable; no missing fact is invented. If a selected emitter
fails, the helper attempts a fixed refusal on the same public channel: owner
stderr2, other selected role stdout1. A closed channel remains missing required
evidence; the helper never diverts data into owner frame stdout1. The public
`emitter_failures` count is a diagnostic, not a qualification flag.

`clock_snapshot(actual_role)` delegates unchanged2086 for core roles and adds
only actual service/client0 procfs capture under the same exact clock schema.
It never obtains a proxy clock and relabels it. The same raw current/child
namespace/offset caveats apply. Actual role wrappers capture before intake.

`read_role_event(stream,reader_id='controller/'+role,role=role)` admits only the
strict clock, existing fixed status, process metadata and existing0582 Tor
progress/hostname/exit union. Its observation envelope remains
`kpb-method03-status-observation/v1`. Monotonic/realtime/boottime are the first
three calls after readline, before parsing or queueing. Queue consumers retain
these values and append their own later consumption time separately. Owner
input must be stderr2; transport/receiver/service/client input is the selected
public metadata stream. Never connect this reader to owner frame stdout1.

Coverage is Python app/Popen boundaries and declared passFD/stdio options.
It is not every transient internal C descriptor, syscall, circuit or global-
host observation. Full global-host coverage remains UNQUALIFIED. The pure
fake-Popen controls execute no Tor, curl, prover, private role or network and
must never be relabelled actual METHOD03 capture.
