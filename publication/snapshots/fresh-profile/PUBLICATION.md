# Fresh-profile public research checkpoint — 22 October 2026

This branch contains a **partial offline native-KAS composition experiment**.
Four fresh genuine inner proofs, an initial native prefix and a genuine paired
state receipt passed their recorded software/native checks. The public replay,
owner CLI and DRAIN workflow remain blocked/unimplemented. This is not a
complete private payment system. DO_NOT_FUND.

| Evidence | What actually ran | Entry point |
| --- | --- | --- |
| Initial four proofs and prefix | Fresh untrusted single-party setup; bootstrap, ADMIT, two SPEND proofs; supplied-context official Full prefix through n5/m2/R1.66B | [Initial proof/prefix report](research/intensive-2026-10-22/INITIAL-FOUR-AND-NATIVE-PREFIX.md) |
| Pair receipt | Eighteen guest cases, one Succinct proof, same-claim Groth16 compression and independent CPU checks | [Proof results](poc/s7-owner-lifecycle/proof/RESULTS.md), [closed manifest](poc/s7-owner-lifecycle/proof/evidence/final-packet.json) |
| Native pair | Official isolation→Full, reserve metering, 12 typed script controls and 3 host controls; actual selected predecessor | [Native report](research/intensive-2026-10-22/s7-native-policy/pair-native-01/execution/results/report.json), [manifest](research/intensive-2026-10-22/s7-native-policy/pair-native-01/MANIFEST.json) |
| Ordinary SPEND | Two alternative forks of the same pre-pair context; corrected repeat preserves the first mount limitation | [Native policy scope](research/intensive-2026-10-22/s7-native-policy/README.md), [corrected observation](research/intensive-2026-10-22/s7-native-policy/ordinary-spend-native-02/MANIFEST.json) |
| Independent public math | Exact public bundle/tree/P/J reconstruction | [Oracle scope and reports](research/intensive-2026-10-22/lifecycle-oracle/README.md) |

The [earlier integration snapshot](https://github.com/elldeeone/kaspa-privacy-initiative/blob/work/intensive-research-20261022/PUBLICATION.md)
has different development parameters and older J42/one-shot J336 statements.
Its [ADR0037](https://github.com/elldeeone/kaspa-privacy-initiative/blob/work/intensive-research-20261022/docs/adr/0037-offline-continuing-s7-owner-lifecycle.md)
records the planned scope; planned owner exits did not run. Use this branch's
[reproduction guide](REPRODUCE.md) for its exact selected fresh profile.

## Limits that remain

All native UTXO/DAA context was supplied offline. Official Full validation does
not establish that this UTXO exists in an accepted chain, remains unspent, or is
backed by accepted genesis/deposits. No funding, broadcast, testnet payout or
mainnet operation occurred. The two ordinary SPEND observations are alternatives
and cannot be combined into a ledger. The paired proofs use count 5; count 7 in
the oracle denotes a derived commitment-prefix membership check, not a genuine
owner/historical-anchor proof.

Fixed 40M ordinary fees pass 100 but fail 200 and 500 sompi per mass. Fixed 80M
paired fees pass 100/200 but fail 500: the measured mass 196,484 requires 98,242,000
sompi. The 1700 budget and authorized fees were retained. No target retuning,
privacy improvement, security, exit readiness or fundable architecture is
claimed. Existing privacy requirements and the frozen failed privacy study
remain unchanged in the earlier snapshot.

## Git is a filtered source/public-data view

The full local packet is larger than this publication. Generated host/guest
software binaries, caches, producer-only plans, test-wallet files and the public
962,197,520-byte proving key are omitted. The public key's recorded SHA256 is
`9a10b69c6354d72ed39b2f4f65375701dda52508eeb21bafcbc3b1f9ae032102`;
stream identity and its VK prefix were checked, but restoring that key and
proving with it were not qualified.

The [omission inventory](publication/OMITTED-ARTIFACTS.json) records exact omitted
paths, sizes, hashes, local-retention status and rebuild references. Public VK,
bundles, receipts, P/J/native-body data, reports, source and locks remain in the
publication where listed. Closed manifests and historical logs are unchanged:
their absolute/sibling paths describe original runs, and their full file lists
cannot all be rehashed from Git alone. Use the two publication pages for
portable navigation. Rebuilding software and generating a fresh randomized
setup are separate operations; neither silently replaces missing old artifacts.
