# H11 source and method refresh

This supports the [frozen study](../poc/shared-pool/PRIVACY-STUDY-SPEC.md), not a
new protocol subsystem. Dates in experiment reports use Australia/Sydney;
source queries occurred on 2026-10-19 UTC.

- Rusty Kaspa head: [`24854ef83998a6da29f4012fb6d2a8e225685702`](https://github.com/kaspanet/rusty-kaspa/commit/24854ef83998a6da29f4012fb6d2a8e225685702).
  The diff from H10's `91888a4` changes `Cargo.toml` packaging to include assembly
  files, not covenant/signature semantics. Native validation remains pinned to
  `01b532e8b553523216471682649693af92f0fd16`; no dependency upgrade is inferred.
- [KIP 17](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0017.md)
  remains Active. It supplies public transaction introspection, not privacy
  against observers reading amounts, payloads, scripts and ancestry.
- Initiative head [`05ea24a`](https://github.com/olafweller/kaspa-privacy-initiative/commit/05ea24a5cdb89ba5dd2cfec1041b1e69fa8de68d)
  adds local user-held recovery/terminal-exit work through PR 55. It is a
  different pipeline. [P13](https://github.com/olafweller/kaspa-privacy-initiative/issues/13)
  remained open with zero comments. Neither determines our policy decision.
- vProgs `f9b84a8`, Kaspa research `c923fac`, Orchard `616a669`, and RAILGUN
  `36bcf5e` were unchanged at refresh. Existing Aztec, Monero and MWEB comparisons
  remain in the [prior source review](compact-privacy-source-review-2026-10-19.md).
  We reuse the distinction between historical membership and current spentness;
  no sequencer/runtime, ring signature, aggregation or token is imported.
- [Orchard's commitment tree](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/commitment-tree.md)
  motivates treating an anchor as an eligibility boundary. The source is not
  evidence that a large candidate set gives uniform anonymity.
- [Kappos et al.](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-kappos.pdf)
  motivate entry/exit amount and timing attacks;
  [Moser et al.](https://petsymposium.org/popets/2018/popets-2018-0025.php)
  motivate joint elimination and age baselines. Their historical success rates
  are not transferred to this implementation or present-day privacy systems.
- [CP-SAT's documented integer/status semantics](https://developers.google.com/optimization/cp/cp_solver)
  support an exact integer feasibility implementation. Unknown and invalid
  results are errors, not extra anonymity. Explicit one-to-one matching speeds
  the same relation tested by the original Z3 formulation. Independent tiny
  enumeration and one complete four-wallet Z3 comparison check the resulting
  candidates. Solver agreement is not a cryptographic proof or audit.

The population projection omits cryptographic byte-level attacks and assumes
confidential commitments/proofs/encryption, private unused fallbacks and unique
payout addresses. Genuine native calibration checks the relation and decoding.
None of this measures RPC queries, IP linkage, mined timing, users or adversaries
in the wild. A logical source reconstruction using fewer fields can reject a
policy; a favorable model result cannot establish real-world privacy.
