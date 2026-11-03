# Privacy candidate boundary review

Reviewed the new source comparison and one-invoice wallet design59f6945c before
implementation. ACK for wallet compatibility/recovery work, **not a privacy
qualification or a new cryptographic design**.

The useful concrete change is a wallet request for exactly one recipient
invoice plus positive seed-recoverable sender change, using the existing compact
relation. It reduces the number of unrelated recipients in one disclosed payer
output cohort. It is structurally the existing serial study arm; packaging it
does not resolve that arm's incomplete solver results or create new evidence of
anonymity. A known invoice participant can infer its positive sibling is payer
change under this declared policy and may propagate later forced change spends.

The design correctly preserves all public partitions, NFs, amounts/fees/native
outputs, positions, ordering and legitimate participant information. Known-seed
integration material must never become blinded truth. Its requested original-
backup recoveries and three cold owner-local proofs are engineering gates,
not a new privacy score. Complete actual fees, useful principal and payer refund
must remain separate; this small-payment canary is not expected to meet2%.

The primary-source comparison correctly distinguishes Orchard generic shuffle
and transaction binding from restricted pairing, PCZT's private prover inputs,
and RAILGUN public grouped calldata. A public permutation/outer proof cannot
erase already-public per-action labels. Separate spends/outputs with global
balance is an established design family to study; multiparty coverage, binding,
owner-secret isolation and coordinator transcript leakage remain unresolved for
this implementation. No new primitive is selected by the analogy.

The singleton source limitation persists even with two-real-input/partial
payments: before another independent source exists, conserved value ancestry
cannot acquire a different source merely through encryption. Keep timely
unilateral exit and explicitly report that privacy limit. Forced waiting,
working balances, invented users and hiding known wallet policy do not qualify
as fixes.

Before any future heldout: select a realizable candidate; freeze the full
observer including invoice-to-change propagation, truth/secret boundaries,
workload and original thresholds/stop rules; validate public controls and query
coverage. Preserve all prior failures and UNKNOWNs. No new heldout privacy
generation has been reviewed or authorized by this memo.
