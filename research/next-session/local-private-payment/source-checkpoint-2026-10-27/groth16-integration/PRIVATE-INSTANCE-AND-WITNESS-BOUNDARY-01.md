# Public-instance timing and shared witness construction

Source boundary only. No implementation, input ingestion, proof or privacy
experiment is supplied by this note.

The inspected co-snarks interface has a clear `SharedWitness.public_inputs`
vector and a separately shared private suffix. The ordinary prover therefore
knows the public prefix before proving. If a future private-payment batch puts
raw stable NFs or an owner-labelled NF order in that clear prefix or its
preparation messages, a colluding prover learns them before finalization even
when the coordinator's result JSON is narrow. A private suffix alone does not
remove that disclosure. The selected full-proof toy deliberately uses clear
`[ONE,t=128]` and cannot qualify private-instance timing.

This is a conditional integration question, not an assertion about the current
NativeAuth component's raw public variables. Its inspected public signature/
spend boundary uses the two128-bit limbs of SHA256(statement200); the sole NF
also appears in the complete external4077-byte packet that the owner currently
reconstructs. Do not confuse an opaque digest with a raw NF. The eventual batch
must specify which exact values, commitments and packet fields each owner,
prover and coordinator sees at each step. If final public values must remain
hidden until batch readiness, their authenticated computation and delayed
declassification need an explicit qualified contract; it is not provided by
the existing clear-prefix API. No full-effects binding may be weakened to
obtain that property.

The backend also does not automatically construct a shared extended witness.
The public Ark exporter supplies matrices, variable layout and public parameters,
not a clear owner witness. Owners may compute their own local component
auxiliaries and deliver them through the strict masked external-client path,
but a global assembler must preserve every variable/constant and handle all
cross-owner derived wires inside qualified MPC. Concatenating component WTNS
files or using the existing clear `split-witness` dealer is not that assembler.
An input client's public block offset or proof-file slot may reveal the owner
mapping even when its values are secret. Preserve the selected private
permutation/assignment through the whole protocol rather than publishing it in
an adapter receipt.

The full-proof gate exercises one concrete cross-client auxiliary `z=x*y` and
all proving stages. It does not provide a generic malicious-secure Circom VM,
private SHA/HMAC/EdDSA witness generation, a complete NativeAuthSpend witness,
multi-owner consent or a private2-input/4-output financial batch. Those remain
separate required implementation/qualification work. All existing integer,
range, complete-effects, state, authorization, replay and independent-exit
invariants continue to apply.
