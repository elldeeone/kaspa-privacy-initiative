# Prospective finite public controls

**Proposed before implementation/execution.** These controls falsify limited
claims or check an attacker rule. They are not a random privacy population,
new holdout, proof/native acceptance result or a replay of the old 96 views.
Root/adversary review must fix the source and fixtures first.

## Exact first experiment

Use fresh, explicitly public DO_NOT_FUND symbolic fixtures, with integers in
sompi. Keep public observer facts separate from a verifier's labeled fixture;
run the observer without any truth/owner-purpose map. Public fixture labels are
available to reviewers, so no empirical anonymity claim is possible.

The independent certificate checks every prefix liability, positive input,
chronology, selected-input uniqueness, at-most-once spend, output sum, native
payout and fee. Candidate input sets contain one or two distinct earlier
positive notes. Known participant original-NF occurrences constrain only that
participant's own note. All CM positions/gaps and public partitions remain.

Predeclare these eight control groups:

1. **Visible partition wrapper.** Put two independently authorized public
   action records into one envelope and publicly permute the combined output
   list, retaining actual component arrays/ranges/digests. Recover the same
   labeled CM sets. Expected result: the claimed partition-hiding fix is FALSE.
   A hidden-assignment wrapper without this data is not declared impossible;
   it instead needs a new coverage relation and is outside this control.
2. **Direct cohort breadth.** One issuer has 32 genuine due invoices for the
   wide control. The corresponding compact realization delivers those same
   invoices one per action with change/dummy. One legitimate payee record
   labels other economic outputs in the wide partition, but none in its own
   compact partition. Emit guesses for all public positions, including change;
   report the economic subset only in the later verifier. This is a direct
   disclosure-scope result, not an anonymity improvement.
3. **Sparse change-chain propagation.** One boot note funds a genuine invoice
   plus positive sender change, then a second genuine invoice. The first payee
   knows its own CM, value, original NF and payer role. Its NF is absent from
   the next action; the bootstrap was spent. Excluding zero/future/spent notes
   leaves the sibling as the unique possible input even with two input slots.
   Under the explicit sender-change wallet policy, infer the later payer role.
   Expected result: serial baseline still fails the role-privacy claim.
4. **Singleton ancestry.** Deposit, private payments/change and a withdrawal
   precede any second actual source. Check the nonnegative conservation/causal
   induction. Repeat with one/two inputs, partial/full native payouts and an
   eventual second funding after the target. Expected result: single-source
   ancestor remains forced; the future source never becomes eligible early.
5. **Counterparty is not funding origin.** A legitimate private payment gives
   an actor value from another funder; that actor subsequently pays an invoice.
   Its counterparty label does not equal the bootstrap origin. An observer that
   adds that equality must fail true-history compatibility.
6. **Change knowledge is conditional.** Repeat the sibling control with zero
   remainder, with an additional eligible independent positive claim, and with
   generic protocol two-payment outputs instead of the selected one-invoice
   policy. Do not infer positive change or sender ownership from missing facts;
   do not force a later input when another valid history remains.
7. **Mode/currentness/spentness boundaries.** Include partial native cashout
   with positive private change, a full cashout with other reserve remaining,
   physical gaps, replayed selections, a future note, duplicate input and wrong
   public predecessor. If new no-append mode is used, bind its selected source
   and public full/no-change fact; old mode0=R0 is not silently imported.
8. **UNKNOWN and false-certificate guards.** An unsolved query is incomplete.
   A certificate for global SAT must also satisfy the requested query. A wrong
   known-NF association, invented owner/lineage equality, altered fee or missing
   prefix cannot pass as ambiguity/privacy.

## Outputs and pass/fail semantics

The report separates CONTROL_CHECK_PASS from PRIVACY_TARGET_FAIL. An expected
leak correctly detected is not a privacy pass. Each forced result identifies
which public facts and protocol/wallet assumptions entail it; unsupported
human identity remains NOT_MODELLED.

Exhaustive queries use the unsimplified global relation and independent integer
certificates. A candidate/history missed by an incomplete constructive search
falls back to the exact solver or UNKNOWN, never UNSAT. Complete candidate
coverage is required before any forcedness field is emitted.

No whole-claim alternative NF-pair family from a real/private claim is published.
No actual backup, financial witness, old private alternative or its fingerprint
is an input. Source and known public controls are distinct from any future
heldout corpus. If actual wallet canary records are used, they are fresh public
unfunded development material and are labeled separately from native acceptance.

Default envelope: at most two CPU cores /6GiB total /zero swap, one solver
thread. Exact generous operational limits and source hashes are fixed after
public fixtures/code review and before execution. Solver/resource cancellation
is explicit incompleteness. No new cryptographic primitive, setup, funding or
RPC is part of these controls.
