# Signature predicate: source freeze before execution

**SOURCE ONLY. Await Root's source review before compilation, owner key
generation/signing, witness generation or checking.** No such phase has run.
This is an unreviewed authorization-predicate prototype, not a Groth16,
native-KAS, privacy, malicious-MPC or complete-payment proof.

Authority is the immutable [plan](../SIGNATURE-AUTHORITY-PROTOTYPE-PLAN-01.md)
`42900a915b5e61078597cef42ad351819605276db20bd4f96e661816af757ac2`
and [Root implementation release](../ROOT-SIGNATURE-PREDICATE-IMPLEMENTATION-01.json)
`8a43a526ce5c1f8907bc13c1435468145a98950a22ba414733ed951d95463691`.
Root prospectively selected 192 MiB tools, 2 GiB scratch, 4 GiB peak RAM and
30 CPU minutes serially, before measurement. Logical fixtures and expected
failures are unchanged. The source manifest pins the exact files for review.

## What is real, and what remains absent

[authority.circom](circuits/authority.circom) contains the actual pinned
Circomlib EdDSA-Poseidon verifier with enabled=1. The same verification key and
independent nullifying key determine the consumed input note; no spending
signing secret is a circuit input. Input membership is a synthetic two-leaf
tree. Integer amounts/fees, NF, exact output CMs, context, anchor, nonce and
signed height interval are constrained.

Every coordinate/CM byte is range checked, all 256 bits are connected to a
strict field representation, and top two bits are zero. Scalar encoding has
zero top three bits and the verifier enforces S<Q. PK/R8 have explicit curve,
nonidentity and constant-Q subgroup checks. The new ladder composes pinned
BabyAdd/BabyDbl with nonzero-denominator inverses and curve checks. A zero
denominator is unsatisfiable, rather than leaving an unconstrained division.
This is a source argument; composition correctness, compilation and valid-key
acceptance remain untested. Retain any valid-key rejection; never search for
different passing owner keys or weaken the check. EscalarMulAny's subgroup
precondition is not used to establish subgroup membership.

The circuit hashes ASCII `KPIAUT01` plus both complete 520-byte tuples with
actual SHA256: 17 compression blocks. All byte bits and both derived LE128
limbs are constrained. [hash-golden.circom](circuits/hash-golden.circom) is the
small companion required by the plan's padding-boundary checks: fixed
55/56/63/64-byte inputs, seven blocks total. It checks bit order against Node
SHA256; the driver also uses the fixed `abc` digest/LE128 golden. No host
complete-ciphertext digest oracle substitutes for the circuit SHA.

Signed ciphertext bytes remain fictional. Encryption, ciphertext-hash
consistency, output proof/receipt validity, current note/profile/KDF
compatibility, actual state/NF-set acceptance, native effects/fees, original-
seed direct exits and data availability are **unimplemented**. A newly signed
arbitrary ciphertext is deliberately accepted as authorization-only evidence.
The plain prover sees owners, NFs, output pairs, values and note/NF material:
**NON-PRIVATE**. Frozen 2% fee and active-retry/output-intersection failures
remain unchanged. No architecture or financial profile is selected.

## Tool closure and static review limits

[package-lock.json](package-lock.json) freezes 96 registry-only packages.
[TOOL-ARCHIVE-CLOSURE-01.json](TOOL-ARCHIVE-CLOSURE-01.json) records independent
helper09/SHA512 checks of every downloaded archive against that lock.
[INCLUDED-CIRCUIT-CLOSURE-01.json](INCLUDED-CIRCUIT-CLOSURE-01.json) pins every
actual included circuit file. Archives bind dependencies; this is not an audit
or an exhaustive byte comparison of the installed tree with archive members.

[TOOL-PREPARATION-01.json](TOOL-PREPARATION-01.json) records the exact compiler,
existing explicit Node and installer identities. Tool preparation used npm
12.0.1 with install scripts/audit/funding disabled and isolated empty config
files. The first setup invocation rejected duplicate `/dev/null` config paths;
two distinct empty files fixed that before installation. No test logic changed.
Tools/cache/compiler occupy 180,811,508 bytes, within 192 MiB. No compiler or
signing import was executed. The selected blake-hash archive contains a pinned
117,680-byte Node addon, tried before its JS fallback; it is not security-
audited, loaded or built here. Root can review this boundary before execution.

The original Snarkjs checker has no serial option at its public interface.
[check-serial.mjs](check-serial.mjs) is a source-derived adapter preserving its
constraint arithmetic/loop, rebasing imports, selecting singleThread for both
curve allocations, enforcing witness dimensions/section length and exact
`witness[0] == 1`, and terminating handles. Installed upstream files are
unchanged. This adapter also needs review; a final rejection is not a proof of
cryptographic soundness, malicious composition or exhaustive test coverage.

## Frozen finite execution and stop rules

[FIXTURE-RECIPE-01.json](FIXTURE-RECIPE-01.json) and [run.mjs](run.mjs) define
the exact finite records, cases and expectations. Owner children retain fresh
signing keys, produce only an allowlisted public handoff, and exit before the
plain prover checks witnesses. Fixture construction may overlap idle owner
processes while forming the common synthetic root; this is not asynchronous
wallet/service liveness qualification. The key-generation recipe and all
nonsecret bytes are fixed before owner execution. Pin its public HANDOFF
before checking; no key is published as a reproducibility seed.
There are 49 rows: 46 owner-input cases, two stale-limb mutations and one
checked relation with four SHA padding vectors. Five accept and 44 reject.
Forty rows require actual R1CS checking; only nine degenerate point/zero-
signature controls permit explicitly labelled generation-only rejection.

Compilation and checking are serial and use the explicit reviewed Node and
Circom paths below. Create only the dedicated scratch root/run identity.
Do not reuse an existing run directory. Compiler/generator errors, unexpected
acceptance, failed positive/differential, incomplete mandatory R1CS controls
or resource overrun are retained failures, with no automatic retuning/rerun.
Generation-only rejection is separately labelled and cannot satisfy a control
whose purpose requires actual R1CS rejection. Keep small public results and
positive witnesses and any unexpected-case witness/input; expected rejection
witnesses may be deleted. No failure witness is discarded before stopping.

Prospective commands after Root's release, from this directory:

```sh
mkdir -p /dev/shm/kpi-signature-predicate-scratch-01
/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node run.mjs prepare /dev/shm/kpi-signature-predicate-scratch-01/run-01
mkdir /dev/shm/kpi-signature-predicate-scratch-01/run-01/build
/var/tmp/kpi-signature-predicate-tools-20261026-01/circom circuits/authority.circom -l /var/tmp/kpi-signature-predicate-tools-20261026-01/node_modules --r1cs --wasm --O1 -o /dev/shm/kpi-signature-predicate-scratch-01/run-01/build
/var/tmp/kpi-signature-predicate-tools-20261026-01/circom circuits/hash-golden.circom -l /var/tmp/kpi-signature-predicate-tools-20261026-01/node_modules --r1cs --wasm --O1 -o /dev/shm/kpi-signature-predicate-scratch-01/run-01/build
/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node run.mjs check /dev/shm/kpi-signature-predicate-scratch-01/run-01 HANDOFF_SHA256_PRINTED_BY_PREPARE
```

Before running, helper09-verify this source/tool closure and recheck shared
disk/RAM. Prefer the dedicated tmpfs; never crowd out financial work. Capture
compiler CPU/RSS separately and report aggregate preparation/compile/check
costs; per-process Node metrics are not total concurrent RSS or a hard sandbox.
No setup, ceremony, proving key, Groth16 proof, GPU, network submission, wallet,
funding, service change or blocked native-exit benchmark is part of these
commands. Any future PK remains a separate review/audit matter; the existing
three exemptions from the nine-Original audit remain unchanged.
