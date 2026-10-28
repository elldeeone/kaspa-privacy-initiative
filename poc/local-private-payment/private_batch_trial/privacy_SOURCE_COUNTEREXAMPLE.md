# Prospective source counterexample: known recipient knowledge

Recorded before executing private payment preparation. This is a public source
model, not an observation of private wallets, a backend transcript or a native
financial result. The frozen method and workload remain unchanged.

Owner1 is the colluder. The fixed schedule sends owner0's round-one payment to
owner1, then owner2's round-two payment to owner1. Trusted confidential invoice
routing identifies those counterparties to their recipient. Owner1's Original
can decrypt its incoming Output CF and recognize the corresponding public tuple.
The existing owner-private scorer already uses this legitimate invoice-issuance
and selected-worker knowledge; it is not cryptographic sender authentication.

Consequently, exchanging every honest creator0/2 label contradicts one known
incoming creator fact in each round. The method's strict global creator-swap H1
is expected to fail under that full declared view. Do not remove the incoming
receipt, hide the route, change the colluder, or weaken H1 after observation.

That creator fact alone need not reveal its linked change tuple or input NF.
In the exact direct-fact model, after fixing the colluder's one input and two
created tuples, a known honest payment tuple has three possible change partners.
There are two honest input-owner permutations, three output-creator partitions,
and six joint candidates per batch. A pair-tag control fixes the partner and
reduces the output partition count to one; a full constructor map fixes both
inputs and creators. These counts precede truth and make no posterior claim.

Actual scalar/group transcripts, ciphertext behavior, metadata, all terminal
outputs and economic/chronological constraints may reduce those sets further.
They must be measured or marked unqualified. Input ownership, output-creator
ambiguity, created-pair ambiguity and the input-to-authorized-pair relationship
must be reported separately. A strict H1 failure does not establish that every
one of those relationships was uniquely recovered.

Reuse anchors: `poc/owner-private-payments/wallet/score_worker.py` and
`SCORING-API.md` explicitly join decrypted incoming receipts with the colluder's
own private invoice issuance; `score_codec.py` enumerates exact two-per-creator
partitions before truth. The new source adapts those finite constraints and the
existing salted observer-capsule/count-only isolated scoring boundaries.
