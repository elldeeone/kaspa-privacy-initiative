# Exact-field sum: smallest existing-distribution recipe

**Proposed, not executed.** 2026-10-24 UTC. Root must record the later ADR and
review the exact launcher/program before execution. Only official public
artifact acquisition, archive inspection, source hashing and ELF metadata
inspection happened in this research pass. No downloaded executable ran.

## Selected distribution and source join

The official GitHub `v0.4.4` tag resolves exactly to
`113c4e47dd94bca9ecab029d2f0abe649bea5c52`, the source commit investigated in
[INDEPENDENT-SOURCES.md](INDEPENDENT-SOURCES.md).
[Official tag reference](https://api.github.com/repos/data61/MP-SPDZ/git/ref/tags/v0.4.4).

The [official release artifact](https://github.com/data61/MP-SPDZ/releases/download/v0.4.4/mp-spdz-0.4.4.tar.xz)
is 78,428,724 bytes, SHA256
`73d6473526101b4433999fc4f7521fdfdc53ddf018e5f64480518d6293f62760`.
That whole-byte identity was independently calculated after download; it
matches GitHub's release-asset digest. The source-only acquisition took
7.171 seconds. The archive has 1,206 members and 409,427,853 regular-file
bytes. These are measured archive facts, not compilation/runtime estimates.

The selected `bin/Linux-adx/mascot-party.x` is 10,621,536 bytes, SHA256
`47d9ae6f52003825946a4abb6cf9dc62f62a4e2fc2c19a5e3ee6f59a6889b07e`.
`readelf` reports only glibc-related dynamic dependencies (`libdl`, `libm`,
`libpthread`, `libc`, ELF loader), and version requirements through
GLIBC_2.28. Host metadata shows x86_64 ADX support and glibc 2.43. This
supports trying the official binary without installing GMP/libsodium headers;
it is not an execution compatibility result or a reproducible-build proof.

The archive's exact `Compiler/types.py`, `Compiler/program.py` and
`Compiler/compilerLib.py` SHA256s match the files fetched from the selected
official commit. Their hashes are in the independent memo. The distribution
itself pins the rest of the Python compiler and native binary bytes; a later
launcher must inventory every selected archive member and hash its own
staging. Do not select executable or verifier code from a result file.

The official [quick-start script](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Scripts/tldr.sh)
copies **all** platform binaries to the working directory. Skip that action;
select just the MASCOT binary. Avoid `make setup`, full-suite tests and
`compile-run.py` auto-build behavior. Use the pinned Python compiler directly.
No system package installation, Docker image or new toolchain is needed for
the candidate binary route. The upstream release binary remains a trust
assumption; no independent security review of it was performed.

## Proposed public program and exact commands

This is the complete intended arithmetic program, shown for source review;
no `.mpc` program was created in this research pass:

```python
from Compiler.types import sint
from Compiler.library import print_ln
delta = sint.get_input_from(0) + sint.get_input_from(1) + sint.get_input_from(2)
print_ln('KPX6_SUM %s', delta.reveal(check=True))
```

Set `q` to the exact decimal Jubjub scalar modulus in [DECISION.md](DECISION.md).
Inside the later fresh, pinned distribution namespace, with the frozen
program at `Programs/Source/kpi_delta.mpc`, the compiler command is:

```sh
/usr/bin/python3 -B ./compile.py -F 252 -P 6554484396890773809930967563523245729705921265872317281365359162392183254199 kpi_delta
```

Run these three processes concurrently, each in its own filesystem namespace
with only its own `Player-Data/Input-P<i>-0` and its own TLS private key. They
must share a **new isolated loopback network namespace**, with no host network,
home, credentials, wallet backups or financial parameters:

```sh
./mascot-party.x -N 3 -p 0 -h 127.0.0.1 -pn 17349 --prime 6554484396890773809930967563523245729705921265872317281365359162392183254199 kpi_delta
./mascot-party.x -N 3 -p 1 -h 127.0.0.1 -pn 17349 --prime 6554484396890773809930967563523245729705921265872317281365359162392183254199 kpi_delta
./mascot-party.x -N 3 -p 2 -h 127.0.0.1 -pn 17349 --prime 6554484396890773809930967563523245729705921265872317281365359162392183254199 kpi_delta
```

These are the actual upstream documented runtime/API flags, not commands
executed in this pass. Fixed-port use is confined to the new isolated network.
The launcher must create independent public trial TLS keys and the required
certificate hash links with existing OpenSSL, retaining no wallet credentials.
Only public certificates go to all parties. Do not mount a common input/key
directory into all three processes or rely on the stock all-parties launcher
for process privacy. A common trusted host remains a synthetic experiment.

Use the stock live MASCOT mode. Do not pass `-F` to the **runtime** (that
selects file-based preprocessing), `-DINSECURE`, unchecked `.reveal(False)`,
fake preprocessing, reused preprocessing/TLS session material, or a
semi-honest replacement. `-F 252` above is the separate **compiler** field
bit-length option; the exact arithmetic prime is selected by `-P`.

The compiler outputs program bytecode/schedules. Their actual hashes and
runtime prime identity must be joined before accepting results. Reject a
deliberately different runtime prime. Validate each fixed local scalar's
canonical 32-byte encoding independently; the general field input API is not
a canonical wire decoder.

## Fixed outcomes and operational budget

Run the four fixed vectors from DECISION.md in fresh isolated identities.
The primary vector `(q-1,q-2,6)` has expected result `3`. Do not print the
input vector or any intermediate secret. A known public input can equal the
result; searching for a numeric value in logs is not a confidentiality test.
For the positive real-curve consumer, form an explicit public synthetic
commitment relation whose difference is `3*R`; correct Delta must verify in
the already exercised Binding API, changed Delta/digest/fee must fail.
Groth16/native proof validity remains outside this gate.

Two declared additional identities stop a party before input and after input
but before completion. The retained outcome is INCOMPLETE/abort; never accept
a surviving two-party sum or issue financial authorization. Timing alone
does not prove private-state preservation. An arbitrary malicious wire-share
injection is **not** tested by merely killing a process; record it as
unverified unless a separate reviewed fault seam is actually executed.

Root's scheduling budget is at most four CPU cores and four GiB memory,
with the genuine financial rehearsal taking priority. This is a scheduling
allocation, not a measured requirement. No execution time or peak RAM is
known. The prebuilt route avoids C++ compilation and OT dependency builds.
Allow generous operational time; a slow run/cap hit is retained operational
evidence and cannot weaken arithmetic/MAC checks or become a privacy result.
Record owned-cgroup CPU/RAM/swap, child exit status and cleanup, not whole-host
usage. No GPU is needed for scalar addition.

If binary compatibility fails, retain the error before considering source
build. The narrow source target is `make -j2 mascot-party.x`, not `make` or
`make mascot`. The selected source pins `deps/libOTe2` at
`fe6b2ff82a976a5332b3a2efe325831588b1324a` and other submodules in its tree;
its Makefile may fetch recursive dependencies. Host GMP/libsodium development
headers are absent. A source-build fallback therefore needs a new complete
task-local dependency freeze; the one make command is not permission to
fetch moving branches or install globally. No fallback build is authorized
by this note.
