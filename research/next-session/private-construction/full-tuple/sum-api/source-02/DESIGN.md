# ADR0062 exact existing-engine API experiment

Public synthetic scalars only. No downloaded executable or compiler has run
at source-freeze time. The complete source and selected distribution member
closure are externally pinned by SOURCE.json and DISTRIBUTION-MEMBERS.json.
Root reviews them before compiler, MASCOT or curve-consumer execution.

`harness.py stage` authenticates the fixed official archive and finite source
list, excluding all declared original backup inodes/directories by metadata
before public reads. It selects only the existing Linux-adx MASCOT binary,
the stock Python Compiler tree/compile.py, and this separate experiment's
source. Selected code is staged read-only outside any Git checkout.

`calibrate` uses installed Python/OpenSSL/bwrap/ip only. It gives each of
three child filesystem/pid namespaces one own input file and TLS private key,
all public certificates, no host home, no global /out or other owner roots.
All children share a newly isolated loopback namespace, already configured
by bubblewrap. Actual TCP request/reply checks require no added capability
or interface modification. No host network, financial parameter,
wallet, credential/config directory or KAS interface is mounted.

The four normal fixtures are exactly ADR0062. Each run has fresh identity,
TLS and process roots. `-I` reads each process's own mounted input via its
own stdin and enables prints at all players. No common plaintext input or
private-key directory is mounted in any party. The fixture controller knows
these deliberately public inputs; this is not a deployment secrecy claim.

## Exact scheduling APIs and observed-stage limits

At selected MP-SPDZ113c4e47, Compiler/library.py `print_ln_to` lines190–212
explicitly requires interactive `-I` or `-OF .` for nonzero-party printing.
`break_point` lines2000–2008 starts a new basic block and specifies following
code executes after preceding code. `public_input` lines258–262 emits the
stock pubinput instruction for `Programs/Public-Input/<program>`. The actual
selected source files are in the compiler inventory, not substituted mocks.

The program first executes all three existing secret-input calls, then a
basic-block break, per-party `KPX6_INPUTS_COMPLETE` markers, another break,
and a public FIFO input fixed to1. The gate participates as `delta+gate-1`
before `reveal(check=True)`, so it cannot be dead-code eliminated. A
controller-held O_RDWR FIFO descriptor prevents a read-open at initialization
from blocking startup; no gate byte is delivered until all three markers.
The predeclared gate is scheduling instrumentation, not a protocol change.
Actual compiler bytecode/schedule hashes and exact q are retained and joined
before engine execution; definite runtime marker observation remains needed.

One fresh negative loses an isolated party wrapper before engine entry; it
does not claim that a peer completed a connection or accepted an input. A
second waits for every actual input marker, kills/reaps party2 and never
releases that party's gate; only the surviving gates receive1. Its result is
INCOMPLETE, never an accepted two-member sum. Process death does not exercise
arbitrary malicious wire shares or prove privacy. Operational timeout only
produces an incomplete retained attempt; no check is weakened.

The wrong-prime case really invokes stock engines with q+2 against a schedule
compiled for q. It must retain each engine's actual mismatch error. That is
separate from the Python canonical decoder's rejection of encoded q, q+1 or
wrong length, and separate from source inspection. No individual numeric
value's literal absence in logs is treated as a confidentiality test.

## Actual aggregate to existing curve verifier

The bridge reads the first completed engine result's parsed actual output,
not a fixture literal, canonicalizes it to32LE and passes it to the separate
Rust consumer. That consumer derives a verification key from three input
commitments CV(100;-1), CV(100;-2), CV(100;6), three outputs CV(99;0) and
fee3. Their difference is3*R. It signs with the received scalar using the
existing RedJubjub Binding API and checks correct verification plus changed
Delta/digest/fee rejection. There is no Groth16 proof or valid Sapling/KAS
transaction in this consumer; no new generator/signature is invented.

The Cargo manifest and complete86-package lock reuse ADR0061's exact versions
and Git commit, changing only the root package name. The old public dependency
cache is used offline; it contains no Cargo config/credential files. Cargo's
operational cache locks may change, while the old published source/evidence
packets stay untouched. The installed Rust toolchain and public cached source
bytes remain trusted premises. No network or resolver/source-build fallback
is permitted during compilation.

Root schedules every execution under at most4 CPU cores/4GiB and no GPU,
after financial heavy jobs. Each phase keeps failures, actual output hashes,
return codes and owned cgroup counters. No full protocol suite or C++ build
is selected. No result establishes strong privacy, adaptive corruption,
fair output delivery, abort unlinkability, a safe final-authorization/retry
state machine or native financial composition. Original priors and failed
qualification thresholds remain unchanged.
