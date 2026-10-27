# Command repair 02: explicit existing system linker

Status: SOURCE ONLY; fresh build02/run02 commands await Root review and release.
The first build01 failure is retained. Neither runtime identity has executed.

## First observed result

At 2026-10-27 02:00:02 UTC the exact COMMANDS-01 build ran once in a user scope,
nice10, affinity CPUs0/1, CPUQuota200%, MemoryMax4294967296B. It exited101 after
0.700 seconds. Cargo reached proc-macro2 v1.0.107 and failed its build-script link:
`linker cc not found`. No probe binary, native constraint run or control exists.
This is a build-namespace failure, not a failed matrix-semantic control.

Metadata confirms the host chain /usr/bin/cc -> /etc/alternatives/cc ->
/usr/bin/gcc -> gcc-15 -> x86_64-linux-gnu-gcc-15. COMMANDS-01 mounts /usr but
excludes /etc, leaving that default cc symlink unresolved inside the namespace.
The existing real compiler /usr/bin/x86_64-linux-gnu-gcc-15 is an executable
ordinary file, 1305304B, mode0755, already within the read-only /usr mount.
No compiler binary body was read or copied.

## Exact proposed command delta

COMMANDS-02 uses new build-02/run-02 paths and adds only this build environment:

    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/x86_64-linux-gnu-gcc-15

Cargo documents this target-linker setting as the linker passed to rustc:
[official Cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html#targettriplelinker).
The installed Rust toolchain remains1.97.1. The repair is not yet an execution
qualification of this Cargo/toolchain/GCC combination; any next failure stops.

No mounts are added. Runtime command/environment are unchanged except fresh
identity paths. No all-/etc mount, host home, credentials, network, private
state, PK, native code change, dependency change, compiler flags weakening,
fixture retuning or predicate change is introduced. Native Rust70e448 and
lockfab4acf remain selected exactly; SOURCE-FREEZE-01 and all15 expected control
results remain historical/frozen, not rewritten to claim this successor ran.

The existing parent /dev/shm/kpi-native-output-matrix-gate-01 must remain owned
mode0700. Its USED-IDENTITIES-01.json records build01/run01 as nonreusable.
Only build02, build02/cargo and run02 are proposed fresh0700 directories.

## Retention and resources

Raw first-attempt stdout/stderr, full selected argv, start/end status and GNU
time output are retained under /var/tmp/kpi-native-output-matrix-gate-execution-01.
RESULT-01.json: 39471B, SHA0128d878a93a5c4e91a72bfa5343c34b319c697a2aa407976c7ca349c1c2cc14.
Its build stderr:195B, SHAb5f3bc7472f027d0ebce19c378ae9e12d8f16ea4dcb8dd01bf71f8a5a515e1f5.

All13 ordinary partial-build outputs were read through unchanged helper09 and
retained in PARTIAL-BUILD-01.tar.gz (44901B,
SHA6be37d268b26be2113b48740fa79ed04358ee03129ede4e77700e9b57f184c49).
RETENTION-01.json indexes individual sizes/hashes. The 245169B of partial files,
empty runtime and owned build scratch were reclaimed; no running job remains.

The resource record has actual outer elapsed0.700s, GNU-time wall0.68s,
maximumRSS2332KiB and user/system0.00s. These are launcher observations;
full Cargo process-tree/cgroup peak was not captured. No runtime resource claim
is made. Before any successor run requalify the frozen >=8GiB host headroom and
fresh paths; use the same <=2CPU/4GiB/nice10 bounded scope. Final DATA/readback
work retains priority. Stop first unexpected result and retain it; never reuse
build01 or change source/fixtures to force a pass.
