# Public settlement proof experiment

This is the unfunded ADR59 experiment. It verifies two scheduled compact private-action proofs, every public NF/CM transition and the exact final native financial body, then commits a 424-byte journal. It accepts no owner witness or proving key. Public fixtures are deliberately unsafe and must never be funded.

The compiled child profile uses the capacity-exit domain/key and the original note/nullifier namespace. The wrapper domain separates only the outer policy/journal. Existing funded pool programs have no migration or aggregate branch. The actual W program verifies a genuine RISC Zero compressed receipt; the separately named hash oracle is diagnostic only.

The selected guest image and program are in `outer-selection.json`. Host-only receipt conversion does not change the guest. Build the new host offline with its lockfile; `build_guest.py` records the original guest build. `run_outer.py` operates only on the selected public two-payment fixture outside Git:

1. `execute`: check the host predicate and the guest's exact journal.
2. `prove`, then `verify`: genuine Succinct receipt and independent CPU verification.
3. `compress`, then `verify-compressed`: same-claim Groth16 receipt and CPU verification.

The original launcher's `native-proof` stage deliberately remains tied to its original frozen host. That attempt rejected legitimate SDK coordinates because its extra roundtrip compared Ark affine sign flags with raw field coordinates. The checked fix, boundary controls, separately selected rebuilt host and exact successful conversion command are retained in [NATIVE-CONVERTER-SELECTION-02.json](../../research/next-session/independent-payments/fees/NATIVE-CONVERTER-SELECTION-02.json). Its host command is `native-proof RECEIPT EXPECTED_J NEWOUT`; it verifies the genuine selected-image receipt before producing the canonical 128-byte native proof. The original receipt and guest were unchanged.

The launcher authenticates the exact runtime and official compression assets, isolates external networking, measures CPU/cgroup/GPU use, and stops its own unit. The read-only filesystem remains reachable; this is not a claim that source or backups are absent. Operational resource failures are retained failures, not cryptographic invalidity results.

Native Full validation, independently recoverable private cashouts, accepted-chain/current-head evidence, recovery availability, linkage measurements and full-lifecycle fee targets require their own evidence. Passing this public predicate alone establishes none of those claims. At two payments, verifier amortization alone already exceeds the 2% payment-plus-independent-private-exit target before overhead.
