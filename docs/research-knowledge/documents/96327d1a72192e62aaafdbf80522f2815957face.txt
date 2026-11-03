# Prospective public source-policy linkage prediction

Frozen at **2026-10-26 04:32:10 UTC**, before final payouts were available. This
separate [prediction](SOURCE-POLICY-PREDICTION-01.json) changes neither frozen
economic observer. It uses selected public generator/wallet rules, not a
generated private PLAN/state, original, owner log, hidden truth or actual payout.
The [source-limit record](PUBLIC-GENERATOR-OBSERVER-LIMITS-01.md) explains the
stronger observer omitted by the earlier two arms.

The prediction is conditional on execution of these selected source policies:
three actors initially own20KAS each; first-round outgoing amounts are5KAS,
second-round amounts2KAS; actor1 chooses `change` in round two while actors0/2
choose `received-preferred`; every actor receives one note per round through the
same private cycle; positive payment fees are at most50,000,000sompi; and every
actor exits its three remaining notes, largest first. Actor order is privately
shuffled in each payment round; direction is privately chosen; the nine exit
requests are shuffled together. No particular realized order is assumed.
The public source phase order is required: payment event indices0–5 precede
exit indices6–14. An interleaved financial ledger is outside this generator
assumption and cannot receive a supported ownership prediction from this arm.

`payment.prepare` selects only notes worth at least payment+fee+60,000,000sompi.
Thus a received5-KAS note cannot fund a5-KAS payment; all first-round spends use
the original20-KAS note. A received2-KAS note cannot fund2KAS plus positive fee
and change. A received5-KAS note always can fund2KAS under the50m fee cap.
`received-preferred` filters for eligibility before falling back to change, so
that fallback does not occur for actors0/2 in round two. Actor1 deliberately
uses its original-note change and leaves its received5-KAS claim untouched.

Write f_i and g_i for actor i's exact public first/second payment fees. The final
gross note values are:

| Source actor | Final gross claims, sompi |
| --- | --- |
|1|1,300,000,000−f_1−g_1;500,000,000;200,000,000|
|0 or2|1,500,000,000−f_i;300,000,000−g_i;200,000,000|

With1≤fee≤50m, their value bands are disjoint. The prospective public gross
multiset is three200m; two in[250m,300m); one500m; one in[1200m,1300m); and two
in[1450m,1500m). Predict that the unique gross500m exit and the unique gross in
[1200m,1300m) are both actor1-owned claims. **Gross means native payout plus its
own exact exit fee**, not a500m native output. The received500m claim originated
from another actor's asset root; common ownership does not mean common ancestry.

The selected source-order bridge ties actor i to party-i, GEN3 funding input i
and initial CM slot i. `activate.py` preserves TRIAL owner order for ordinary
sources and records; `sign_worker.py` signs the matching row/input index with
that party's funding key. Both initial and cached launchers pass backups in
party0/1/2 order. This is a conditional selected-source/input-provenance
assumption, not a generic protocol rule or a private-content proof. The actual
public GEN3 result binds the trial UUID and source closure; no separate
contemporaneous activation argv receipt was found. Do not describe reconstructed
argv as a frozen receipt or independent attestation. Actor1 therefore denotes a
public funding-input/CM index under this bridge, not an independently verified
human identity.

The public simulator enumerates all36 pairs of payment actor permutations; the
two cycle directions give72 source schedules but do not affect actor value
queues. It deduplicates equal value profiles and matches the nine observed gross
exits against three descending actor queues. It retains a set of possible actor1
exit-position masks, rather than weighting duplicate directions/schedules as
extra evidence. The nine-request global shuffle permits1,680 actor interleavings.
Empty support means inconsistent source assumptions/model/input, never a vacuous
must-link or privacy pass. Conditions, bands and rules are not tuned afterward.

Source-only evidence includes:

- `wallet/payment.py:77–80` eligibility; `recovery/history.py:159–173`
  eligible-received preference, change fallback and largest-note selection.
- `wallet/worker.py:186–191` exact fee cap check before payment preparation;
  `integration/launch_cached_campaign.py:166` sets50m.
- `integration/campaign_cached.py:62–109` round amounts, randomized actor/cycle
  order, asymmetric selection and global exit shuffle.
- `bootstrap/activate.py:84–110`, `new_trial.py:71–78`,
  `gn3_entry.py:33–67`, and `sign_worker.py:55–86` establish the order bridge.
- The public initial caller preimage32c8f9888f6b8025cc259e981b18d28c2226c4a5e1bce9116f999d0f627c358f
  and launcher preimage20399a06eebb18e7721a547e66cbf6475c3439a0599a27b215acafd394c2503b
  preserve those preparation rules; the cached resume does not recreate a plan.

Only final externally selected public data will test these predictions. No
private truth is used to claim accuracy. This is a source-policy ownership
side-channel in a selected research workload, not a generic cryptographic or
NF-preimage break. General protocol privacy and the earlier arms' model-relative
root-label symmetries must remain separately scoped.
