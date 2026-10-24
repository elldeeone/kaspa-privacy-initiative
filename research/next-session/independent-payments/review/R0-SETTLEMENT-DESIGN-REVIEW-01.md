# R0 settlement design review

Design ACK for a separate unfunded ADR59 prototype, not a cryptographic/native
implementation ACK. Reviewed virtual contract
`ef3eebd883f90be77ad1664848c12906d09530effc9b5eefde41f12567e2afb0`
and current concrete plan
`762066d94b2e4a67cff6460b691a8dc3dfd549a9b21d8a57b7c2f569eb41013d`.

The candidate explicitly changes native authority: actual wrapper W authorizes
two strictly compact/P0 virtual child transitions under an installed child
template C. First child starts at actual Q0; second starts at the canonical
previous virtual body ID. Fresh financial profile/domain/keys/statements and
explicit client consent are mandatory. Old proofs calibrate code only; no old
instance, virtual context or fee can silently inherit this authority.

The declared424-byte journal and8108-byte two-record payload totals check.
The critical acyclic boundary is explicit: payload contains only child records,
not journal/hash/current ID/outer proof. Journal is reconstructed. Outer proof
is in excluded signatureScript; actual final ID includes genuine inner proofs
in payload. Guest is compiled before W and does not embed W containing its own
image. W SPKs are public guest inputs and independently checked by native.

Actual native W must reconstruct Q0/S0/R0, exact child payload, exact sole W
continuation/state/reserve and financial-body projection, then derive the same
journal. It must never accept a caller-supplied body hash or image selection as
authority. Guest must verify genuine child proofs and all public NF/CM/body
semantics, exact ordering and cross-child uniqueness. Hashing a list of proofs
alone cannot replace these checks.

For each child, private inputs equal outputs plus Fi. The actual body must
enforce `F=sum(Fi)=R0-R2` with exactly one input/continuation and no hidden payout,
sponsor or surplus. Provisional fixed-width-slot quote is only preparation;
normalize/reconcile the complete genuine inner payload before guest execution
and recheck the final outer body. A changed quote requires fresh owner proofs.
Native fixed header/context/frame requirements and budget/storage pricing need
explicit differential controls; a normalizer or cached ID is not settlement.

Direct private fallback must use the same original real NF namespace and current
roots as aggregation and REVEAL, from one original backup/public data, without
outer compression assets or another owner's witness. It must survive full CM
capacity via the separately reviewed no-append relation. Pending virtual
outputs are not confirmed claims. Complete delivery/update records must remain
recoverable after coordinator loss; commitments alone do not supply availability.

Host/oracle and actual native body checks precede outer proving. Then require
actual assumption-free Succinct receipt, independently verified same-claim
compression, pinned VK/image/journal and genuine Full native outcomes with
coherent mutations. Setup/host trust, stale/reorg reconciliation and independent
retention remain explicit. A successful wrapper cannot erase its public child
output cohorts or make scheduled requests asynchronous.

The plan correctly retains the economic failure: ideal verifier-only complete
payment cost is1.475%+1.55%/N at10KAS/reference100, hence2.25% forN2 before
overhead. P0 aggregation alone does not qualify full-lifecycle or N1 fees; actual
cooperative and unilateral bodies must both be priced. No privacy,2% fee,
cryptographic soundness or accepted-chain qualification is granted here.
