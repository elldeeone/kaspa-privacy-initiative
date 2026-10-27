# Synthetic two-owner aggregate

**Source implementation only; no circuit compilation, build, witness generation
or R1CS check has run.** This is plain-prover, public-fixture correspondence
testing. It does not hide a coordinator's map or change native payments.

The frozen [plan](../TWO-OWNER-AGGREGATE-EXPERIMENT-PLAN-01.md) is
`458451f62e00bade1a7207b312ded0081ae05ac526c9c46318d54f6c5ddb2bc1`.
[Recipe](FIXTURE-RECIPE-01.json) fixes 29 rows: seven accepts and 22 rejects,
all requiring actual R1CS evidence. The original public handoff/signatures are
reused without keys or owner processes. [Accepted offline decision](ADR-OFFLINE-AGGREGATE-01.md)
selects only this research implementation; execution needs Root's source freeze.

`circuits/authority-template.circom` is the byte-exact existing authority source
prefix with its `main` removed. `circuits/aggregate.circom` composes it twice.
Public input names are exactly eight context fields, NF[2], tuple[4][520] and
feeTotal: 2,091 fields; there are no outer outputs. Per-owner digest/message
outputs stay internal. Boolean bijections preserve complete 520-byte tuples.
CM distinctness is within this batch; no historical uniqueness rule is added.

`audit_sources.py` and its mutation controls inspect the chosen public source
interface, exact template extraction and recipe. They are pure Python text/
integer checks, not circuit compilation, witness verification or privacy tests.
The wrapper's separate pure selector control enumerates 16 possible Boolean U
and 65,536 possible Boolean V matrices, finding 2 and 24 bijections. These
controls do not substitute for the selected compiler and full R1CS checks.

The later selected pipeline must pin ordinary and assertion-disabled-C++
aggregate R1CS files and establish full byte identity before any witness check.
Only the ordinary R1CS is the acceptance authority, using the unchanged pinned
serial checker. Missing witnesses, generator/parser failures and checker errors
are failures for all 29 rows. Preserve the first unexpected input/witness and
stop; never retune, rekey or automatically rerun.

All eventual logs/builds/witnesses belong in a new owned 0700 tmpfs run. Root's
prospective envelope is 8 GiB RAM, 3 GiB scratch and 30 CPU minutes, one serial
job, coordinated with live confirmation work and checked against fresh resource
headroom. Per-process Node metrics alone are not complete child-process
accounting. No new dependencies, compiler source build, setup, PK, proof, MPC,
GPU, network submission, native-profile migration or Original operation belongs
to this experiment.

The synthetic relation has no CVin/CV balance/Delta, output encryption/proof
validity, accepted-state or native-effect binding, replay database or recovery
implementation. Same-state replay accepts. Public owner-coded tuples and the
plain constructor expose the map even when its correspondence uses private
wires. Current native 1NF→2CM grouping, active-retry and 2% fee failures remain.
