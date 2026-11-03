# Read-only independent capacity recount

The separate fee/source reviewer reported a successful bounded standard-library
recount of the frozen capacity artifacts. The reviewer performed no native
execution, build or artifact edit; this note records that advisory, rather than
claiming another native run or a separately retained verification program.

The reported rederivation covered all43,691 CMs,43,690 real NFs,21,845 dummy NFs,
65,536 physical records/successors and43,690 private-split/leaf-reveal value
equations. Current CM/NF roots matched; the sole unspent position43,689 holds60M.
Both incremental append and a complete131,072-leaf NF-tree rebuild matched
the append65,536 successor:

`483133f0727fed34890a85ade25709343c7215b0a895036e7535f266f75aa86f`.

Independent terminal dimensions matched the actual official native report:
estimated24,816 bytes, compute45,176, transient99,264, storage11,756 and complete
mining49,632. Fee24,816,000 at500 leaves payout35,184,000. The control changes
only top-sibling payload byte1,885, its correctly re-signed signature and cached
ID; amount/context/budget200 are identical. Its recomputed append root fails,
matching the retained Full `SignatureInvalid(VerifyError)`.

The reviewer reported10.44s for this bounded read-only work. The missing exact
intermediate helper5fd9 remains a preparation-source provenance limitation.
Synthetic/algebraic history, one-sompi historical fees, historical placeholder
ciphertexts, descriptor reuse and lack of historical proofs/chain acceptance
remain explicit. This recount does not remove any of those qualifications.
