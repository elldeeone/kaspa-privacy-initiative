# Fresh initial-pair proof profile

This isolated profile reuses the reviewed two-v6 binding and S7 state algorithms
with a fresh public test-only setup, domain, pool ID and guest image. It is an
offline initial-pair composition experiment. The owner CLI, ledger replay and
owner withdrawal-proof workflow are parked and are not implemented here.

The guest checks two genuine inner proofs and the complete declared state update,
then commits the existing 336-byte state journal. Native verification must bind
that journal to the actual predecessor UTXO and reserve. Guest execution alone
does not authenticate a UTXO or establish reserve backing, exits or privacy.

`evidence/selected-profile.json` records the independently selected fresh
parameters and guest image. The immutable stage00 build manifest records source,
lock, tool, raw ELF and wrapped-program identities. Before the guest build, the
host fully checked the exact 328-byte VK, including canonical encoding, subgroup,
nonidentity and input arity. Only the private immutable guest-key constructor
skips repeated subgroup validation; submitted proofs retain all checks.

Qualification so far:

- Fourteen binding/static-key regression groups and one fresh state-range group
  pass. The old state suite is retained under `state/reference` and was not rerun
  as a fresh-instance qualification.
- The fresh genuine pair passes the fully checked and compiled-key host gates
  with identical independently expected P1088. A genuine changed authorization,
  malformed proof and identity proof reject at their expected layers.
- Stage00 source and executable were archived before publication pins change.
  Its unselected publication pins blocked execution and proving at that stage.

The actual native predecessor context and independent input/J were selected before
Stage01 host rebuilding. Eighteen guest cases passed. One genuine Succinct
receipt was produced, independently verified on CPU, and compressed to the same
Groth16 claim without guest replay. The compressed receipt also passed independent
CPU verification with fourteen negative controls. See `RESULTS.md` and the immutable evidence
records for identities, measurements and remaining native-composition scope.
