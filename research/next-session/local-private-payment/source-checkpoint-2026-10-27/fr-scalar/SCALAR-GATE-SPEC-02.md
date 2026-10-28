# Exact BN254-Fr stock-MASCOT scalar component

Status: SOURCE PROPOSAL02 / UNCOMPILED / UNEXECUTED. Requires independent source
review and a separate Root resource/runtime release. No current audit job is
changed or interrupted. All inputs are deliberately public synthetic numbers.

## Question and scope

Can the already selected stock MASCOT installation compile a new exact-Fr
program, accept fresh Fr runtime state, and produce identical fully checked
arithmetic results at three parties? This tests component compatibility only.
It supplies no Groth16 proof, matrix interoperability, private-note secrecy,
ownership anonymity, malicious-prover composition or fee qualification.

The gate uses `sint.get_input_from(0|1|2)`, including multiplication of a prior
secret multiplication result. It does not substitute clear compiler constants
for inputs. Seven fixed public vectors yield 28 zero residuals per party.
Only residuals are opened in one `reveal(check=True)` before tagged output.

## Exact existing public origin

Public software root:
`/var/tmp/kpi-sender-private-lifecycle-01/assets/shared-mpc-software-01/software`.
`COMMON.json` and `INSTALLATION.json` are in its parent directory,
`/var/tmp/kpi-sender-private-lifecycle-01/assets/shared-mpc-software-01`.

- `COMMON.json`: 8,968 B,
  `7aa260678e118f15d23c707feb906a9ed75695fd36af06cb1ba5b72bfc6a237e`.
- `INSTALLATION.json`: 10,766 B,
  `5d0def4ae617f6365fccb5f243922088faaf7a6148aa0938c3a3f9520c4ff594`.
- Stock `mascot-party.x`: 10,621,536 B,
  `47d9ae6f52003825946a4abb6cf9dc62f62a4e2fc2c19a5e3ee6f59a6889b07e`.
- `Compiler/program.py`: 74,171 B,
  `1b112e8d96f088017daf23d4f2e253dbc25e1a7fbf24faca348b2655e0551251`.
- Existing runtime image:
  `sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea`.

COMMON selects 59 files totaling 17,556,841 B, including old admission wrappers.
Reuse its authenticated vendor origin, compiler/dependency files and stock
engine read-only. Do not execute/relabel the old codec, party wrapper, program
or prepared-v1/v2 session as an Fr profile. COMMON itself still declares Q;
this proposal is a separate profile and does not rewrite that declaration.
Runtime qualification must authenticate the exact selected closure before use.

Source support, not a binary execution result: MP-SPDZ v0.4.4 resolves to
`113c4e47dd94bca9ecab029d2f0abe649bea5c52`. Its explicit-prime setup accepts
the supplied modulus; four-limb field storage covers 193–256-bit primes.
The old 251-bit Q and new 254-bit Fr occupy that same range. Whether this exact
stock binary accepts the new profile remains UNRUN; retain any failure without
switching modulus, disabling checks or rebuilding a replacement invisibly.

## Field, fixture and byte boundary

Fr is exactly
`21888242871839275222246405745257275088548364400416034343698204186575808495617`.
It is distinct from the old admission Q and from the BN254 curve base field.

`PUBLIC-FIXTURE-01.json` contains ordered triples for zero, one, p-1, wrapping
addition, wrapping multiplication, small mixed values and large canonical
values. Party i receives the i-th value of each triple: seven fields each.
Use the buffer-only `fixture_preflight.validate_fixture` after unchanged
helper09 admission. It requires exact schema, modulus, vector order and values;
each value must be canonical unsigned ASCII decimal in [0,p), up to 77 digits.
No signs, leading zeros, booleans, duplicate keys, aliases or implicit reduction
are accepted. The returned three streams are public fixture bytes only.

Retained planned parser negatives, all UNRUN: missing/extra vector; reordered
vector; unknown field; duplicate JSON key; wrong modulus Q; `p`, `p+1`, `-1`,
`+1`, `01`, non-ASCII digits, boolean and a changed in-range fixture value.
These are pure input-validation cases, never a live participant attack.

## Exact prospective commands and state

Fresh run ID is 32 lowercase hexadecimal characters. Bind one new program,
fixture/preflight source hashes, Fr and run ID in a new manifest. Every retry
gets another ID, fresh compile output and fresh per-party state. Do not mount
old Player-Data, preprocessing, MAC files, schedules or bytecode.

Compiler argv inside the existing bounded runtime:

```text
/usr/bin/python3 -B /software/compile.py -F 252 -P 21888242871839275222246405745257275088548364400416034343698204186575808495617 kpi_fr_scalar_gate RUN_ID
```

Read-only `/software` is the selected stock software. Place the new `.mpc` in
fresh `/work/Programs/Source`; bind fresh Programs output there. Set
`PYTHONPATH=/software/compiler-dependency`, `PATH=/usr/bin:/bin`,
`LANG=C.UTF-8`, `TZ=UTC`, and chdir `/work`, following the existing compiler
boundary. No package installation/vendor rebuild. Python bytecode writes stay
disabled. `-F` means usable integer bits: the inspected compiler rejects a
value above `prime.bit_length()-2`. Hence **252**, not 254. The program checks
both `program.options.prime` and `program.bit_length`.

Require fresh schedule `kpi_fr_scalar_gate-RUN_ID.sch` with an exact
`p:21888242871839275222246405745257275088548364400416034343698204186575808495617`
field-header line. Authenticate all generated program files before runtime.

For each literal PARTY in 0, 1, 2, the prospective engine argv is:

```text
/engine -N 3 -I -p PARTY -h 127.0.0.1 -pn 17349 --prime 21888242871839275222246405745257275088548364400416034343698204186575808495617 kpi_fr_scalar_gate-RUN_ID
```

Here `/engine` is the selected stock binary; runtime `-I` is the existing
party wrapper's interactive-input option. Do not pass compiler `--insecure`
or disable MAC/correlation checks. Each worker gets only its public fixture
stream on stdin, the authenticated new Programs tree read-only, and a fresh
owned work directory. Reuse the existing isolated three-party runtime/network
boundary rather than opening a host/world RPC port. No Original, owner input,
wallet root, PK, key or financial controller is mounted. The exact launcher,
network identity/credentials, closure and output paths still need implementation
and Root selection; these argv are a proposal, not an executable release.

## Acceptance and honest failures

All three engines must exit successfully. Each must emit one exact run header
and all indices 0..27 exactly once as `KPI_FR_RESIDUAL INDEX 0`; tagged output
must agree byte-for-byte across parties. Reject missing/extra/duplicate tagged
records, a nonzero residual, wrong run ID, incomplete engine or insecure-mode
warning. Retain complete raw compiler diagnostics locally. Raw engine stdout/stderr,
MAC/preprocessing state and TLS keys remain under a fresh private transport
root; only the selected one-party worker reads its own engine logs. The public
result is a closed typed projection of run ID, exact argv, field, exit and 28
zero residuals. The controller never reads/hashes/logs TLS key bodies or raw
engine logs. Record field header, actual argv, code/input/output identities and
observed timings; distinguish configured limits from measured peaks. No timeout alone accepts or aborts a trial.

This gate has no BN254 G1/G2 wrapper. A later source-reviewed gate may adapt
MP-SPDZ's existing authenticated EC-share/opening pattern with established
BN254 arithmetic and strict group codecs. Do not export raw shares into current
co-snarks half-share APIs or call scalar success a Groth16/privacy pass.

## Resources and release conditions

New source/fixture/metadata stay small; existing 17.56 MB software is mounted,
not copied. Generated bytecode and MASCOT preprocessing sizes and Fr RSS have
not been measured, so no invented peak or completion estimate is given.
Earlier public admission calibration `RUNTIME-02.json` records 17.216 s and
3.855 s compiles, and 86.728 s and 16.214 s engine phases under three workers
with two CPU/four GiB budgets each. Those are different programs over Q and
are reference measurements only.

Reserve up to the existing three times four GiB worker budget plus compiler/
controller headroom; availability must be checked when Root releases a job.
Use a fresh small explicit preprocessing batch if the selected stock profile
supports it, while retaining full checks; do not assume a batch size or disk
bound without inspecting its exact option and measuring generated data. No
heavy compile/preprocessing begins while the final audit/readback needs the
remaining root/tmpfs space. Resource scheduling is separate from arithmetic
acceptance. This source proposal authorizes no runtime job.


## Concrete one-command source proposal02

`run_fr_scalar_gate.py` now implements the described compile and three-party
run path. After Root independently selects freeze02 and the launcher digest,
the one prospective command is:

```text
python3 -B /var/tmp/kpi-active-mpc-source-gap-ag94i2r1/run_fr_scalar_gate.py --freeze /var/tmp/kpi-active-mpc-source-gap-ag94i2r1/SOURCE-PROPOSAL-FREEZE-02.json --freeze-sha256 SELECTED_FREEZE_SHA --source-sha256 SELECTED_LAUNCHER_SHA --output /var/tmp/kpi-active-mpc-source-gap-ag94i2r1/run-01 --execute
```

No command has been executed. The launcher authenticates its own/source/fixture
selection and the immutable vendor closure through unchanged helper09 first.
It reuses only `Docker` and `bubble()` from the exact source-pinned existing
admission backend (5b82fceca4b382b58e41a0499518736d2597587aecb4dfe5a15444991ef3f451).
Its `codec.py` dependency is loaded as public definitions only, using pin
6b6ef7f294e333f458cffc4c2d5ad18fc59ab084c04b948deecbf2abcac35fa3.
No old admission preparation, session validation, phase runner or party worker
is called. The selected fixed stock image is never pulled or modified.

Fresh Programs, compiler work and seven-number public input streams live in the
fresh output. The run ID is created automatically. A new three-party Docker
loopback anchor uses network:none; each worker joins only that anchor's network
namespace. `fr_scalar_party.py` invokes the stock engine with exact Fr,
--batch-size1024 and all normal authentication/correlation checks. This is a
preprocessing batch choice, not a total RAM/disk bound or acceptance shortcut.

Fresh TLS and per-party Player-Data live under
`/var/tmp/kpi-owner-private-lifecycle-01/private/fr-scalar-transport-RUN_ID`,
which the unchanged host guard already covers. Only each worker's fresh leaf
is mounted, never the private parent, a wallet directory, an Original, another
party's key or old preprocessing. TLS keys are created directly by OpenSSL;
the controller uses metadata only and never opens/hashes/copies their bodies.
Public peer certificates are copied through helper09. Raw engine diagnostics
and newly generated MAC/preprocessing state are retained privately; public
worker stderr is a fixed unsuccessful status only. The whole host/Docker
administrator remains trusted, as in the existing same-host calibration.

Public aggregate PASS requires all three complete typed party results, all
engine and wrapper exits0, exact field/argv/run joins, 28 zero residuals each,
no insecure warning and successful identity-checked cleanup of every container
owned by this run. Failed runs retain source, bytecode and diagnostics. There
is no timer acceptance condition, fallback field, disabled check or reused
trial identity. Compiling/running this source is still pending Root review and
a separate resource release.
