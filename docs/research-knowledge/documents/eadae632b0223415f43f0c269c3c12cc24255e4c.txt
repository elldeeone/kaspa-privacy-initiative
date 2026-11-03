# Sticky-control review addendum

The independent [static review](../../../review/STICKY-OWNER-BASKET-MODEL-STATIC-REVIEW-01.md),
SHA256 `5a82d855c1e25b40a4b6e6006e86db7c84bf74f4fa7377b70657fbe594e3ac28`,
found no blocker within the stipulated ideal finite control. Review was
text-only, without importing or running either model, and manually reproduced
24 views / 21,277 assignments. Root accepted the bounded findings.

The service-local liveness restriction is stronger than overlap detection:
`open_other_session` refuses **any new basket** while an original intent remains
eligible, even when the proposed basket uses wholly disjoint NFs. It is not a
demonstration of concurrent private-payment service or general cross-session
privacy. No variant was added to relax that restriction or manufacture a pass.

Global history, its durability through crash/reorg, log-before-publication
ordering, private accepted-NF pruning and enforcement across every service or
prover remain ideal assumptions. Their concrete protocol/source has **not been
selected or implemented**. A centralized Python object provides no evidence
that a server can enforce those properties maliciously or atomically.

The positive statement concerns remaining honest A/B after C leaves. Pruning
reveals the departed intent's NF/output pair, and honest B leaving while
colluder C stays exposes A. Forgotten/bypassed history restores the baseline
failure. The independent Exit route remains an ideal accounting/authority
control; this work supplies no actual recovery or privacy qualification.

Actual asynchronous payment batching, the new intent/proof statements and
profile/setup, private prover composition, durable threshold service, native
acceptance, real original-seed recovery and measured fee behavior remain
**unbuilt or untested by these models**. The frozen 21-KAS 2% all-in fee FAIL
remains unchanged. No cryptographic, native, network or production pass follows.

This is a separate later note. All frozen source, input, expectation, report,
review and execution-output paths/pins remain unchanged. No model was rerun.
