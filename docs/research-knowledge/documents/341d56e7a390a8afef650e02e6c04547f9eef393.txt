# One-invoice preparation source review

Source ACK for the bounded pure preparation/public export seam, anchored by
`privacy-wallet/SOURCE-FREEZE-01.json`
`e4abc86d6e1fcc0ad21408ff22a87cec787a63a0605d5bcc5c18989c30983bf9`
and eight public development controls. Reviewed actual payment/reuse/prepare
code and controls; no proof, PK, native lifecycle or hidden owner material was
needed by the reviewer.

Request parsing is exact, duplicate-safe and integer-only. Preparation binds
requested net/exit credit and positive fee, rejects self/own-history/spent claims,
requires positive bounded change, derives a fresh seed-recoverable change index
and reuses selected existing assembly. Original positioned/dummy NFs, shuffled
CM/CF pair ordering and exact conservation remain with the old relation. Quote
and accepted snapshot authority belong to the installed caller, not this helper.

The export copies only selected public fields and checks exact candidate
Auth/payload/proof frame/point/state/reserve/fee. It deliberately accepts an
explicitly fake program/proof fixture while labeling output UNVERIFIED; it is
not a proof/native verifier or reusable signed intent. Genuine Groth16,
canonical v1 ID, selected immutable child tail, native NF/CM semantics, actual
currentness and new virtual authority must be enforced externally before trust
or financial publication. A Candidate/PreparedPayment must never be serialized.

Reentrant tests recover actual encrypted sender change from the original seed
and account for two invoices/three cashouts at the receipt/state level. Fake
outpoints/program/proofs remain fake: no full lifecycle, economic target or
privacy qualification follows. Later integrated use must preserve whole-key
READY before backup, actual quote binding, one owner backup per namespace and
the observed invoice/change/timing disclosure boundaries.
