# Public Groth16 adapter review

Source reviewed: `poc/shared-settlement-verifier/public_g16.py`, SHA256
`f559a4eade76cceac366edf8b0df6928a95bf34e870dd1d9c5d3e1740aad6816`;
controls SHA256
`63f04501ac1843c4cde12d0dfa4b7b48c2b399a54aa29e5f573eee356730b40b`.

ACK for its bounded predicate API. It authenticates the complete selected
`1662fcd9...` executable before executing a sealed owned copy, passes only sealed
public Auth528/proof128 bytes, chooses a strict trusted role, and compares the
actual subprocess result with the exact expected role/VK/authorization/proof
identity. Checker identity/protocol failures remain unavailable infrastructure,
not a false proof predicate. No PK, backup, witness, signer or network API is
present in this adapter. Host/toolchain/runtime authority remains a premise.

Retained `fees/g16-controls-01/RESULTS.json` records eleven expected cases with
eight actual old Rust checks. Four positive checks include a private-valid but
native-NF-invalid current-state proof. Coherent fee/reserve alteration preserves
public reserve arithmetic but invalidates its original proof. Proof mutation,
role transplant, wrong trusted role, trailing widths and wrong executable are
separately classified. The reviewer inspected source and retained results; this
review did not rerun cryptography or open owner material.

This predicate does not authenticate native NF absence, CM updates, exact body
effects, current chain authority, combined settlement or a fee reduction. The
new public transcript checker must independently enforce those relevant public
obligations and preserve the distinction between cryptographic validity and
settlement validity. Two individually valid same-head alternatives cannot be
made sequential by a wrapper or manifest.
