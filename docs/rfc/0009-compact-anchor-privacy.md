# RFC-0009: Can fresh authorization improve compact exit privacy?

Status: bounded offline mechanism supported; population policy remains open,
2026-10-19.
[Decision](../adr/0021-separate-exit-fallback-and-privacy-policy.md),
[audit and evidence](../../poc/shared-pool/PRIVACY.md).

The old count-three authorization identifies one source transaction despite
100 later payments. A small abstract control admits three sources with a
newer anchor. The [H9 matched comparison](../../poc/shared-pool/FRESH-PROOF.md)
now generates genuine replacements: the target has 3/5 possible sources after
two/four intervening payments, including full drain; singleton remains one.
The old fallback independently rebuilds without a prover, and both winner orders
reject the second spend. Added native fee is zero; warm target proving takes
about 9.5 seconds. A normal-user privacy policy remains unmeasured. H7's newly
proved exits supply a different-ledger control, not a matched comparison.

The bounded question was whether a genuinely fresh authorization, generated
locally at withdrawal time, removes deterministic source identification for
the same claim while preserving a privately held old proof as an independent
exit fallback. H9 supports this mechanism for its frozen fixtures. It does not
select the common anchor, acceptable waiting or population threat model. No
consensus change, new token or trusted relayer is proposed.

Before a follow-on evaluation, freeze matched ledgers, target withdrawals,
recent-anchor choices and observation horizons. Cover singleton activity and
two explicit low-activity schedules; do not invent independent deposits that
this variant cannot accept. If the intended question needs those deposits,
design that missing capability explicitly before using it in a workload.

Compare old and fresh authorizations offline under the actual native validator.
Apply public anchor, timing/order, integer value/floor and joint-history attacks,
including eventual payouts. Keep truth available only to a separate scorer.
Record source/note candidates, full-coverage inference success, abstentions,
native mass/fees, proof startup/warm work and delay. A larger candidate set alone
does not meet the branch plan's privacy screening threshold. Preserve those
thresholds or revise them explicitly before evaluation, never afterward.

An old/fresh pair spends the same economic note and has the same nullifier.
Both can independently authorize an exit before either is spent; both must not
pay out. Test both winner orders in separate offline states and reject the
second spend after the first. Bind both to the intended payout, domain and exact
fee, and never publish both pending authorizations as a privacy measure. The
fallback's secrecy is separate from the availability of public accepted history.

Stop if public amounts/topology still force the source, gains require artificial
background users, independent exit fallback breaks, or local proof work misses
the stated use case. Any partial-change/aggregation relation is a subsequent
architecture decision with fresh RFC/ADR and security tests. A funded privacy
trial needs a decision that offline evidence cannot answer; it is not required
to reproduce this source-link counterexample.
