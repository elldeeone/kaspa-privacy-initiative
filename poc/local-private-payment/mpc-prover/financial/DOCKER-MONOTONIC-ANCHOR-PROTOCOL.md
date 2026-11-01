# Docker monotonic-anchor line protocol

Status: bounded local Testnet research only. `CONFIGURED=0`; launch false.
The rootful Docker operator can replace or roll back the volume and remains an
explicit trust boundary.

The supervisor connects to the `AF_UNIX` socket with its expected host UID and
a 32-byte capability that is never mounted or passed to party processes. The
service checks `SO_PEERCRED` and the SHA-256 of the capability before parsing an
operation. Before sending that capability, the supervisor checks the socket is
an owner-65532, single-link `0660` socket and verifies peer UID 65532 with
`SO_PEERCRED`; the service-owned socket directory is `0750`, not group-writable.
Every request and response is one ASCII line, has single-space token
separators and is bounded to 16 KiB.

The service admits at most eight connection workers. A connection that does
not finish its one request frame within 30 seconds is refused without touching
anchor state; excess connections are closed before parsing. These are generous
local framing limits, not trial/proof timeouts.

The real-container control holds all eight workers on partial frames through
that deadline, confirms an excess connection is refused, then confirms status
recovers with the sequence and checkpoint unchanged.

Requests:

```text
KPBANCHOR1 STATUS <capability-hex32>
KPBANCHOR1 ADVANCE <capability-hex32> <authority-hex32> <configuration-hex32> <instance-hex32> <expected-sequence-u64> <expected-checkpoint-hex32> <next-sequence-u64> <next-checkpoint-hex32> <transition-hex32>
KPBANCHOR1 SHUTDOWN <capability-hex32> <instance-hex32>
```

An advance succeeds only when authority, configuration, instance, expected
sequence and expected checkpoint exactly match durable state; next sequence is
exactly current plus one; and the transition identity has never appeared.

Success:

```text
KPBANCHOR1 OK <READY|SHUTTING_DOWN> <authority-hex32> <configuration-hex32> <instance-hex32> <sequence-u64> <checkpoint-hex32> <record-sha256> <runtime-uid> NONE 0 0 1
```

The final tokens mean: network namespace `NONE`, configured false, launch false,
Docker-operator rollback possible. Every malformed, unauthenticated, stale,
replayed or disagreeing request returns exactly:

```text
KPBANCHOR1 REFUSED
```

No response contains the supervisor capability, registry paths, owner bodies,
MPC material, proofs or settlement data.
