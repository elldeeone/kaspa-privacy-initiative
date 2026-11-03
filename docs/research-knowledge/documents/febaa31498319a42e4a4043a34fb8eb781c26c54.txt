# Matched compact and wide proof results

Fresh compact2 and wide32 relations now have actual matched Groth16 parameters
and three genuine independently loaded positive canary proofs. A fourth valid
private proof deliberately binds a wrong successor CM root for the native-guard
boundary control. Their role-specific keys
were generated from the exact measured finalized matrices, not adapted from old
keys. These are public synthetic DO_NOT_FUND controls; main native financial and
recovery results are separate lifecycle evidence.

| Role | Constraints | Private variables | Public variables including one | FFT domain | Public PK bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| compact2 |3,284,767|3,248,304|3|4,194,304|1,307,894,256|
| wide32 |7,448,842|7,361,092|3|8,388,608|2,892,421,872|

Compact continuing and terminal modes have the identical finalized matrix hash
`98c92c77b48028768456068b950ea65c019bf72931cab1b6174b9545fad6514a`.
Wide has `be86280d0ad0ede51e9fea23b3962765543e4a30c85d8e6a1d63b877d6aee9be`.
The standard generator's retained actual finalized CS reproduced both hashes
and official query dimensions. Every setup was fresh OsRng, serialized/fsynced,
stream-hashed and independently read back through its same new descriptor.
Both setup workers quit before owner operations; no resident operator is needed.

The exact canonical manifests are
[compact2](parameters-compact2-01/public-parameters.json), SHA `f27a806928b5c2409d4e4c5428a75deabef6ecf9601b60889667e90363f26043`,
and [wide32](parameters-wide32-01/public-parameters.json), SHA
`b1f0e93bf153c423c669524318efe276917a902d4e9e6b250fba564face94149`.
Selected owner build05 is an ordinary0500 ELF, SHA
`1662fcd9a5b90b8658e07aed2250a4c9c11d2390e80d7addae717090d63fb94d`.
Its compiled source/build identity remains
`8c6a5ab16aab7212cccaf6125f39363d94c854b824bd89ff1eb633f0bad7590a`:
only the separately authenticated compiled parameter pins changed after setup.

## Relation and parameter controls

Twenty-eight host/parser/SHA/HMAC/tiny-parameter controls passed. Fourteen
negative assignments failed actual finalized constraints: all-slot output/list
binding, duplicate/order changes, excessive and deliberately wrapping sums,
terminal rho/cipher sentinels, reserved bytes, alignment/role, wrong membership
root/NF, inflation and reserve overcommit. Parser rejection never counts as
UNSAT. One separately declared next-CM-root alteration remained SAT as expected:
native public state/tree checks, not private conservation alone, must reject it.

Both complete real PKs passed owned-byte length/SHA, exhaustive decode and
extracted VK/query/source/role checks before an empty inherited witness pipe
was released. Seven real-file early errors (missing/cross-role/corrupt/short/
trailing) retained all offered public control bytes and produced no proof.
Wrong-domain/VK/dimension and trusted trailing-decoder controls used independent
tiny keys; they are not described as real-key experiments. No owner backup or
private witness was read for these tests. The explicit public canary definition
is retained in the control source; its bytes are not secret user material.

The three positive canary proving processes authenticated the appropriate whole
PK and exact READY identity before reading/writing their public request. They
created and independently checked continuing compact, terminal compact and wide
proofs, taking12.117,11.957 and26.995 seconds for complete cold operations.
Wide peaked at a systemd-reported10.5G with swap0 under a20GiB ceiling. The
fourth wrong-successor-root canary also produced a checked valid private proof
in12.169s. Native Full then rejected the complete body with
`SignatureInvalid(VerifyError)` at58,246 units, before the Groth16 charge. The
[source-bound native assertion](../lifecycle/BOUNDARY-ASSERTION-ADDENDUM-01.json)
records this private/native responsibility boundary. Raw
Auth/proof/VK files are eligible only for these explicitly independent public
controls; actual-owner witnesses, hashes, maps and discarded preparations remain
private. Genuine proofs and tests are implementation evidence, not soundness,
accepted-chain backing, privacy, complete fees or production qualification.

## Measured performance correction

The first two uncached compact shape checks completed positively, but a first
wide shape was intentionally stopped for diagnosis; that incomplete attempt is
retained and is not an UNSAT, OOM or proof-latency result. Build02 later completed
all three finalized shapes: compact63.43/68.62s and wide155.51s. Cache true/false
alone had no material benefit in the small fixed public probe, and was not
claimed to fix the bottleneck.

Stage timers located59.36s in compact SAT traversal versus1.78s synthesis,
0.72s finalization and1.40s matrix hashing. The pinned Arkworks predicate path
uses parallel evaluation of tiny polynomial terms for each R1CS row. Calling
that path from an external main thread induced repeated worker handoffs.

The same small public relation, with actual pool counts and the same14-CPU cap,
retained SAT and exact matrices across1/14-worker and inside/outside-pool runs.
The final runtime creates CS objects inside a selected local pool: shape/check
use1 worker, actual setup/proving retain14. Full compact SAT fell to1.995s and
the complete identical-matrix shape check to6.33s. All direct negatives still
ran and rejected without dropping any check. This is a measured development
validation improvement; it is not a p95 or GPU/proving speedup claim.

Cleanup records distinguish explicit systemd inactive/dead/PID0/unloaded from
unavailable direct kernel cgroup observations, which remain null. No PK blob,
compiled ELF, private input or old artifact is committed in this lane.
