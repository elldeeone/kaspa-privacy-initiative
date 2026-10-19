# ADR-0021: Separate exit fallback from the privacy policy

Research decision, 2026-10-19. Stage 2's initial audit reached its documented
redesign gate. No circuit, covenant, setup, native transaction or invariant is
changed by this ADR. No mainnet or upstream adoption decision.

## Evidence and decision

The [public-only compact audit](../../poc/shared-pool/PRIVACY.md) uniquely links
the first H6 exit to its note-creating transaction in both the two-payment and
100-payment traces. The old count-three anchor admits only the first transfer's
two outputs after the initial note is spent. This identifies a source transaction,
not which output, private key or person. Additional payments and delay cannot
enlarge the proof's historical membership universe.

Retain reusable authorization/current-settlement separation for independent
exits. Reject frozen authorization plus waiting as the normal privacy remedy
for this case. Do not advance wallet expansion on the claim that unrelated
payments have increased that old proof's anonymity set.

Investigate fresh private authorization against a recent common anchor before
porting partial withdrawals. In the small abstract H6 comparison, replacing
count three with count seven leaves three source transactions instead of one
under joint amount/history constraints after drain. This justifies a paired
offline experiment, not selection of a validated privacy policy. The existing
relation already permits choosing the newer accepted root; changing the bound
authorization requires a new proof. See [RFC-0009](../rfc/0009-compact-anchor-privacy.md).

The old authorization can remain a private, independently usable fallback.
Publishing both old and fresh authorizations reveals the same nullifier and
lets an observer recover the old restriction. Store an unused fallback privately;
publicly mirror accepted history and parameters, not pending authorizations.
This is a proposed wallet policy. H6's experimental `public/bob.bundle.json`
and labeled evidence are deliberately outside the chain-only observer input.
No retrospective privacy claim is made for those published experiments.

## Alternatives and consequences

Bounded withdrawal delay can affect timing among compatible sources, but cannot
remove this deterministic certificate. Equal payouts with private change may
improve amount ambiguity; compact state does not implement it and it cannot
alone enlarge a frozen historical anchor. Do not change the private relation or
pay for more chain activity before testing the cheaper anchor-policy choice.

A fresh proof adds local proving/history work, not inherently another native
transaction or an L1 change. Cold startup remains costly. Value/topology
constraints and insufficient independent activity may still force one source.
One initial deposit is not a shared pool of independently funded participants;
later deposits require separate application work. Source candidate counts are
not users, probability estimates or real-world anonymity.

Keep the Stage 2 privacy gate unresolved/redesign, with Stage 3–4 expansion
deferred. The traffic-policy screening thresholds were not exercised; a bounded
negative audit is complete without pretending the candidate passed them.
Current spentness, exact fee/payout binding, reserve conservation, recovery,
single-party setup and data-availability assumptions remain unchanged.

## Follow-on evidence and retained decision

[H9](../../poc/shared-pool/FRESH-PROOF.md) now supports the proposed mechanism in
three predeclared offline fixtures. Genuine fresh proofs change the target's
source candidates from 1 to 3/5 after two/four payments through full drainage;
the no-activity control stays at one. Native fee/mass is unchanged. Warm target
proof work is about 9.5 seconds, with a 100.414-second cold parameter load.
Both winner orders reject the other proof; both alternatives rebuild independently
with only public state and the selected private bundle. No new relation or setup.

Retain fresh authorization as the candidate normal path when useful later
activity exists, preserving the old authorization privately for exit. This is
a supported mechanism choice, not an optimal anchor policy or privacy claim.
The unused old proof and distinct authorization never enter the fresh observer
or exported history; an actually used fallback necessarily exposes its anchor.
All claims drain, so neither proof can spend its note afterward.

Keep Stage 2's population gate open. Three deliberately chosen small ledgers do
not meet its statistical criteria or establish independent-user privacy. No
automatic TN10 run, protocol expansion or change to the existing stop conditions.

Sources and rejected/adapted analogues:
[primary-source review](../../research/compact-privacy-source-review-2026-10-19.md).

## H11 policy decision — 2026-10-20 (Australia/Sydney)

The [frozen independent-deposit comparison](../../poc/shared-pool/PRIVACY-STUDY.md)
passes its original screen in both regimes: 35.6% / 61.5% relative reduction in
full-drain source guesses, zero additional native fee and bounded measured proof
components below the delay budget. Keep fresh authorization as the normal
candidate path and old authorizations privately for exit. Waiting 20 minutes
without additional activity added no benefit in this workload.

The bounded study is complete. It does not establish strong privacy: 94.4% /
88.5% of funding deposits remain uniquely inferable after drain. Equal gross
contribution controls do better but retain a bootstrap/admission net-value
difference of 112,000 sompi. The next smallest hypothesis is equal net credited
deposits under the existing relation, measured against those controls through
complete drain. No denomination policy, partial-exit relation, setup change or
consensus change is implemented or accepted by this decision.
