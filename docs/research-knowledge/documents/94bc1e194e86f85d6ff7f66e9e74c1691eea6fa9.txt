# Exact-SHA check scope

The frozen build's 10 passing tests include the original eight cheap
serialization/hash/domain checks and these two new tests:

1. All 64 combinations of three Boolean input values and constant/witness
   allocation modes. Both formulas equal the original; candidate constraint
   count never increases. For three variable bits, combined cost falls from
   eight constraints to three.
2. Variable-message SHA-256 against `sha2 = 0.10.9` at lengths
   `0, 3, 55, 56, 63, 64, 72, 73, 76, 96, 104, 137, 140, 208, 484` bytes.
   These cover padding boundaries and every SHA message size in this circuit.
   Actual constrained output bytes are equated to the host expected bytes.

The copied compression body was independently compared to the pinned original.
Its only round-body changes are the Ch/Maj calls. That structural comparison,
Boolean identities and output checks support this narrow implementation change;
they are not a cryptographic audit or proof of the surrounding transfer system.

Primary source links verified on 2026-10-23 UTC:

- [Pinned Arkworks SHA-256 gadget](https://github.com/arkworks-rs/crypto-primitives/blob/ba00127bf673d93d73a3e8bf969cb9eeced20d12/crypto-primitives/src/crh/sha256/constraints.rs)
- [Pinned Boolean selection](https://github.com/arkworks-rs/r1cs-std/blob/70a8298c82ef22b6ab81ee3a6cbf5138a3691aeb/src/boolean/select.rs)

The packaged `r1cs-std` VCS metadata records a dirty flag. Exact inspected file
hashes in the static review identify the actual registry source; the commit
link is supporting provenance, not a claim of byte equality to every repository
file.
