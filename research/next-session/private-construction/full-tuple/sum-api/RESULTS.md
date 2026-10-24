# Existing private field-sum API: actual component gate passes

2026-10-24 UTC. **The stock three-party MASCOT API computes the exact Jubjub
field sum, and its actual first output verifies with the existing
commitment-derived RedJubjub Binding API.** This retires the executable
exact-field API uncertainty. It is no full owner-private construction,
financial proof, valid Sapling/KAS transaction or privacy qualification.

Final source09 is `00da83a1286abc45408172caab846a48f273c1bafd272efc57419e5dd1742ae9`.
The authenticated65-member installation is
`5d0def4ae617f6365fccb5f243922088faaf7a6148aa0938c3a3f9520c4ff594`.
The [machine-readable summary](RESULTS-09.json) joins actual engine and
curve-consumer receipts. Root and independent reviews preceded execution;
the separate independent review directories retain their own authority.

## Actual outcomes

| Frozen case | Actual outcome |
| --- | --- |
| q-1, q-2, 6 | All three engines opened3 and exited0 |
| 0, 0, 0 | All three engines opened0 and exited0 |
| q-1, 1, 0 | All three engines opened0 and exited0 |
| 5, 11, 17 | All three engines opened33 and exited0 |
| Wrong runtime prime q+2 | All three stock engines emitted their actual compilation/computation prime mismatch error and exited1; no sum |
| Party2 absent before engine/input entry | Both surviving engines naturally exited1 after their connection timeout, before controller cleanup; no sum |
| Party2 killed after all three input-complete markers | Both surviving engines naturally exited1, before controller cleanup; no sum |
| First actual aggregate into standard Binding verifier | Correct received Delta3 verifies; changed Delta, digest and fee each reject |

The four normal cases took1.32–1.42seconds each including fresh container/TLS
orchestration and cleanup. The first stock engine reported approximately
0.082seconds including preprocessing and0.100MB aggregate protocol traffic.
The before-input loss took61.16seconds overall; the after-input loss took
1.48seconds. These are measured component trials. Process death and a
connection timeout are not malicious-wire, adaptive-corruption, fairness or
confidentiality tests. No surviving-subset retry was accepted.

The compiler retained the exact252-bit q in a261-byte schedule and produced
1872-byte bytecode. Source `-F250` describes the usable integer workspace;
`-Pq` and all canonical field inputs stayed unchanged. The actual q-1 cases
confirm full-field input behavior. Each opening used `reveal(check=True)`;
the stock engine reported its default statistical security parameter40. No
INSECURE diagnostic, fake preprocessing or semi-honest substitution occurred.

The curve bridge consumes the parsed first actual result from
[engine-09/RESULTS.json](engine-09/RESULTS.json), not an expected fixture literal.
The existing library derives the verification key from public synthetic value
commitments whose difference after fee3 is3*R. The
[consumer receipt](consumer-09/RESULTS.json) binds that received scalar to the
actual positive and negative verification calls. No note/range/Groth16 proof
is generated or validated, and no spend or native reserve is authorized.

## Isolation, resources and cleanup

The two installed-tool calibrations that failed are retained. Redundant
interface administration was removed after ordinary bubblewrap loopback TCP
worked; this host then refused nested user namespaces. The selected normal
Docker fallback uses the exact already-local image, a `network=none` anchor
and three distinct read-only party filesystems. No pull, global install,
privileged flag, added capability, published port or host network was used.
Each party saw its own input/TLS private key plus public software and
certificates. No engine saw another party's directory or the daemon socket.
The trusted controller remains a trusted same-host test component.

Allocations total at most3.8CPU/3616MiB, including the controller and anchor.
The27 retained owned-container counter snapshots show an observed maximum
container memory peak of32,407,552bytes. These are actual observations, not
complete lifetime CPU totals. Compiler09 used0.289CPU-seconds with54.5MB
owned-cgroup peak and zero swap. The independent curve build used43.406CPU-
seconds,594.6MB peak and zero swap. No GPU was needed.

Every case retained identity-checked cleanup receipts. All28 owned engine
phase containers were independently queried after completion and verified
absent. The calibrations' owned containers were also removed. No unrelated
container, image, service or source packet was changed. Publication selects
only finite source and public output receipts; no TLS key, private MASCOT
state, input directory, financial backup, PK or source argv is included.

## Retained failures and bounded consequence

Compiler06 actually failed because missing optional gmpy2 exposed the stock
warning handler's unassigned `bad_prime`. The official pinned task-local wheel
was added for the compiler only. Source review separately predicted the
`-F252` workspace error; no source07 compiler run occurred. Correcting the
caller workspace to250 preserved q, fixtures, checked opening and the stock
engine. Failure preimages and source01–09 snapshots remain additive.

The original closed ADR0061 experiment, full-tuple design/review, amount
prior, singleton ancestry failure and qualification thresholds are unchanged.
No new masking, curve, signature, KAS relation or privileged exit was invented.

What remains is the full construction: anonymous complete output tuples,
binding the sum to exact common financial effects and correct note witnesses,
safe authorization/disclosure/retry ordering, and a reviewed native relation
with measured proof/fee cost. Static protocol guarantees do not become an
adaptive-corruption or full privacy claim from public synthetic inputs.
Long-term independent recovery storage and real testnet payouts remain
separate lifecycle requirements.
