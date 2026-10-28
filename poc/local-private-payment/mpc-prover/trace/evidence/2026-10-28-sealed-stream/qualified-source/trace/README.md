# Authenticated witness recipes

`trace_witness.hpp/.cpp` executes the public recipes emitted by
`private-batch-relation/src/trace.rs` on the existing authenticated MASCOT field
context. It never reconstructs or opens a wire. Owner-local auxiliaries enter
through the masked owner-input boundary; joint recipes extend those shares.

The exact token header is:

```text
KPB_TRACE_V1
FIELD <BN254-Fr modulus>
SOURCE_SHA256 <digest>
MODEL_SHA256 <digest>
LAYOUT_SHA256 <digest>
MODEL_VARIABLES <proof assignment prefix length>
VARIABLES <prefix plus scratch wire count>
INSTANCES <proof instance count, including ONE>
INPUTS <count> <strictly increasing nonzero global wire IDs>
OPS <count>
...operations...
END
```

A linear combination is a term count followed by nonzero canonical Fr-decimal
coefficient / wire-ID pairs in strictly increasing wire-ID order. Empty means
zero; wire zero is the fixed ONE. Supported operations are `LINEAR target LC`,
`MULADD target LC LC LC`, `ADD_BITS width outputs[width] words LCs[words*width]`
and `ASSERT_ZERO LC`. Unknown operations, undefined reads, duplicate targets,
bad coefficients, missing assignment columns and trailing data refuse.

`RANDOM_BIT target` writes only a fresh scratch wire using the stock active
MP-SPDZ preprocessing `get_bit()` in the same MAC context. Output sort/shuffle
selectors must be derived from such hidden entropy, not supplied as clear
coordinator inputs. This operation neither samples a public bit nor reduces
a field value into an asserted bit. Random-key collisions and all subsequent
selector constraints remain obligations of the selected permutation program.

The separate, hash-verified layout is `KPB_TRACE_LAYOUT_V1 MODEL_VARIABLES m
INSTANCES k OWNERS n`, then `OWNER ownerN count columns...` for each strictly
ordered authenticated owner role, followed by `END`. Each owner's columns are
strictly ordered and disjoint. They must be in the model's private range;
derived public digest and scratch columns cannot be owner inputs. The trace's
`INPUTS` must equal this exact union. The backend passes each DDNNT result as
an ordered `OwnerTraceInput` vector with its authenticated role, and the
interpreter scatters values using only the pinned layout. It accepts no caller
column remapping. The DDNNT contract must bind the corresponding role/count and
layout identity before intake.
`ownerN` must equal the canonical label of authenticated integer client role N;
it is not a caller-selected alias.

`ADD_BITS` consumes little-endian bit expressions, not packed secret field
values. Shorter operands must be explicitly zero-extended, including all carry
bits allocated by the actual Ark gadget. A public, value-independent sum bound
must fit the width. Authenticated parallel-prefix carry logic computes the
bits without opening them or asking a clear host to decompose a secret. Bitness
still requires the complete actual constraint-system check; the recipe alone
does not make an input bit valid.

The program is fully inspected and hash-bound before private intake. Parties
agree its source/model/layout/trace identities and operational batching. During
execution a bounded window follows the public dependency graph and batches
independent multiplication layers. Window size and the schedule depend only on
the selected recipes, never on wire values. Every multiplication uses the same
stock checked MASCOT context. Inspection records each scratch wire's last use;
execution releases scratch after the window containing that use. Only the model
prefix is retained and passed to proving; scratch stays private. No scratch
value is opened during release.

Assertions produce private residuals. `trace_private_checks_hold` computes an
authenticated full-field validity bit without opening it. Integration must
combine that bit with validity of every actual R1CS row on the same complete
assignment before releasing one aggregate verdict or any proof-related opening.
It must also use the selected derived-public-prefix policy and durable release
barrier. This module does not replace those obligations, the native public R0
wrapper, private state construction or the scoped observer experiment.

Inspection also records the exact assertion count. Execution retains their
original trace order, even when dependency scheduling completes a later
assertion first. The validator binds that count and ordered residual sequence.

`public_controls.cpp` instantiates the same executor over public Fr fixtures
only when compiled with `KPI_TRACE_PUBLIC_CONTROLS`. The authenticated runtime
does not contain this evaluator. Public controls compare every actual Ark SHA
assignment column and ordered synthetic residuals across several window sizes;
public reference evaluation refuses `RANDOM_BIT`.

`trace_gate_main.cpp` and `run_trace.py` select the unfunded public `abc` SHA
fixture with two owner roles. Both digest limbs are derived as authenticated
values, then compared to independently known public fixture constants by
ADR-0076 validation. The one-use validation capability owns the same complete
assignment used for proving. Its typed public receipt exposes only public
bindings, residual counts and the public field coin. A released result requires
all three complete proof encodings to agree and independent Ark verification;
a changed public digest must reject. Failure controls require the exact typed
phase and validation state on all three parties, with no candidate proof.

The gate requires V2 owner contracts that bind the exact trace and owner layout
alongside model/source/keys/cohort/role/count before masks. Retained V1 toy
contracts keep their original encoding and are refused by this trace gate.
This public-prefix gate supplies no financial derived-prefix or durable-history
factory and carries no payment or privacy qualification.
