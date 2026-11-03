# RFC-0009: Can fresh authorization improve compact exit privacy?

Status: H11 bounded policy screening passed; funding-origin privacy remains
open, 2026-10-20 (Australia/Sydney).
[Decision](../adr/0021-separate-exit-fallback-and-privacy-policy.md),
[audit and evidence](../../poc/shared-pool/PRIVACY.md).

[H11](../../poc/shared-pool/PRIVACY-STUDY.md) now tests 32 ledgers in each of two
explicit regimes, plus controls, and calibrates two against genuine native
proofs. Full-drain source guessing falls from 100% to 64.4% / 38.5%, passing the
unchanged screening targets. Saved fallbacks still settle without a prover;
refreshing adds no native fee. The study is complete within that scope, not a
real-world anonymity result. Funding origins remain uniquely reconstructable
for 94.4% / 88.5% of withdrawals. Retain the mechanism and investigate equal net
credits next; equal gross amounts leave the bootstrap/admission fee difference.
This next hypothesis is not implemented or claimed solved by H11.

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

[RFC-0010](0010-compact-independent-deposits.md) now scopes that prerequisite in
a new immutable compact version: independently funded two-note admissions and
four wallets exiting with proofs saved before later deposits. H10 passed
offline and on TN10; see [the report](../../poc/shared-pool/DEPOSITS.md). Preserve this RFC's population thresholds and observer
boundaries; successful admission/exit mechanics alone cannot complete its study.

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

H11 used the frozen [independent-deposit policy study](../../poc/shared-pool/PRIVACY-STUDY-SPEC.md)
before generation or scoring. It separates an integer-model population screen
from two genuine native-proof calibrations, retains the original thresholds,
and tests complete drainage as the primary observation horizon.
