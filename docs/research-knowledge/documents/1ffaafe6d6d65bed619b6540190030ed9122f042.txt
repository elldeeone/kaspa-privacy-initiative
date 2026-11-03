# Sources for independently scheduled common payouts

Read before H18 implementation, 2026-10-20 UTC. This changes a wallet-policy
experiment and its observer, not cryptographic or native transaction rules.

The [H17 review](common-payout-sources-2026-10-20.md) remains applicable.
Rechecked public repository heads: KIPs `e4ae2332117b5cb68bd6188e065ef885b6d17939`,
Rusty Kaspa `4edcbbccb449f84832afb1ca157904b35f37d006`,
vProgs `f9b84a863a7c7c20586a9cf947550475e894f72e`, research
`c923faca11a49148fa7d912d27ce00197a5c5a4a`.
The actual native dependency remains
`01b532e8b553523216471682649693af92f0fd16`; no latest-SDK qualification is implied.

Initiative head advanced to `52bb2b4e7a1e0a8f98aecb58d33933f0b03d9e33`.
[PR56](https://github.com/olafweller/kaspa-privacy-initiative/pull/56)
adds an integrated partial/full-exit guest; later work packages its proving
lifecycle. [PR59](https://github.com/olafweller/kaspa-privacy-initiative/pull/59),
head `585558091cc7d326e28d10f9c04e709952c85cf5`, prepares offline wallet
onboarding and explicitly leaves actual-chain integration pending. These are
different feasibility/recovery tasks. Do not describe current upstream as
still limited to PR55's host-only full-exit fixture.

[P13](https://github.com/olafweller/kaspa-privacy-initiative/issues/13) continues
to separate confidentiality from amount, timing, wallet and network inference.
[KIP-17](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0017.md)
and the pinned v6 source supply the existing transaction/covenant boundary.
Neither makes a wallet's timing policy private.

Re-read the pinned vProgs covenant/research design and RAILGUN, Monero and MWEB
files linked in H17, plus
[Orchard actions](https://zcash.github.io/orchard/design/actions.html) and
[Aztec state](https://docs.aztec.network/developers/docs/foundational-topics/state_management).
Retain encrypted owner-held notes, nullifiers, padded operations, private
change and explicit native boundary amounts as the relevant established
components. Do not import runtime/operator machinery, ring decoys, EVM asset
handling or MWEB consensus extensions for a client scheduling question.

[Kappos et al.](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-kappos.pdf)
motivate testing observed wallet behavior and timing alongside amount
constraints. H18 adapts that attack perspective, not their empirical Zcash
results. The triangular bounded delay is an experimental scheduling choice;
there is no claim that this distribution is an established anonymity defense.

Local source check: H17 stores `minute` but its inference only checks
chronological order; elapsed time enters its cost scorer. H18 must add actual
timing compatibility to inference, retain the untimed ablation and evaluate
best guesses instead of treating all feasible sources as equally likely.
