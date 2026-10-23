# Self-funded native exit feasibility checkpoint

**Status:** native and model experiments complete and independently reviewed.
**Date:** 2026-10-23 Australia/Sydney. Baseline `8d7d719`.
DO_NOT_FUND. This is a separately versioned public prototype with synthetic
supplied state and UTXOs. Existing private notes are unchanged.

## Concrete result

The new candidate C reveal policy accepts an owner-signed, **self-funded**
whole-note exit without a fresh SNARK or external fee input. The native branch
checks the CM-bound native key, note opening, standard HMAC nullifier, current
CM membership, current indexed-NF insertion, exact fee/payout and immutable
successor. It reveals the note-local NF credential, not private spending
authority. The private s+k ownership guard is only a reference predicate;
**no genuine private-proof branch is implemented**.

Official native isolation, Full and ScriptEngine accept all 60 frozen signed
positive bodies and reject all 39 negative controls at their exact predeclared
causes. The 99 bodies match their pre-execution identities. Fee affordability
is a separate result: 36 of 45 prospective fee profiles pass their economic
screen, and 9 fail. Consensus validity does not imply affordable relay/inclusion.
[Closed native report](future-exit/REPORT.md), [independent gates](INDEPENDENT-GATES.md),
[independent economic recount](future-exit/FUTURE-COST-REVIEW.md).

For a 60M-sompi claim at the 500-sompi/mass research scenario:

| Exact supplied context | Owner-authorized fee | Native payout | Economic screen |
| --- | ---: | ---: | --- |
| Terminal singleton, minimal5,979B redeem | 14,318,500 | 45,681,500 | Pass |
| Continuing reserve,60M remainder, minimal redeem | 15,369,000 | 44,631,000 | Pass |
| Terminal singleton,32,768B NOP envelope | 35,066,000 | 24,934,000 | Pass, conditional size allowance |
| Continuing reserve,60M remainder,32,768B envelope | 35,119,000 | 24,881,000 | Pass, conditional size allowance |
|49,152B envelope | Required mass exceeds100,000 | Cannot retain10M within50M fee cap | Fail |
|20M or10M reserve remainder | Fee/storage fixed point exceeds the cap | No qualifying payout | Fail |

Each profile starts from the same 60M principal and retains the unchanged 10M
payout floor and 50M fee cap. Owner signatures reprice actual full bodies using
a prospectively frozen integer fee/storage fixed-point calculation. Fees are
not copied from a different payout layout. Original fixed50M-fee bodies and
their failures remain separate. All 15 agility layouts pass at 100 and 200;
only 6 pass at 500. The scenarios are research assumptions, not market fee quotes.

NOP padding counts complete redeem bytes and native resource/mass cost; it is
not an implemented private branch. A future union script is covered only if it
fits that envelope with the same fast-branch behavior. Prior validity, complete
backing and authentic current data are supplied assumptions, not proved chain
lineage. The [terminal accounting argument](TERMINAL-ACCOUNTING.md) explains
why R=V is conditionally sound. The [backing/tail review](BACKING-AND-TAILS.md)
explains the stronger exact-backing plus 60M-note-floor condition that could
exclude small continuing tails in a future note-only protocol; it does not
erase any frozen failure or establish that the prototype enforces the future
private relation.

The declared budget200 is also source-qualified for this fast branch: a
conservative independent bound is `U <= 326066 + 6L`, at most620,978 units
for the49,152B envelope, below its2,009,999-unit allowance. This does not qualify
future private code. [Source-bound review](future-exit/FUTURE-SOURCE-BOUND.md).

## Other completed blocker work

- The unchanged upstream permission/delegate route passes 22 exact native
  outcomes, including three externally funded fee-rate positives. Full mass is
  4,987 and its 500-rate fee is 2,493,500 sompi. Its payout constraints reject
  claim-funded fees: this route does not solve an unaccepted private note's
  self-funded exit. Remaining-entitlement continuation is not qualified.
  [Native claim report](native-claim/RESULTS.md).
- The bounded liability model exhausts 128 base configurations over 9,397,840
  financial states. A **separate conditional ideal-reveal model** exhausts 128
  configurations over 13,051,392 states. Neither finds a modeled accounting or
  authority violation; all 11 deliberately broken rule variants yield
  counterexamples. Expected fee exhaustion, unavailable data and service loss
  before accepted withdrawal authorization remain failures. These are ideal
  authority/membership models, not cryptographic/native proofs. A controls-only
  reorg-quote defect is retained and corrected separately; financial graph
  sources were unchanged and not rerun.
  [Closed model report](liability-model/REPORT.md).
- Current source research identifies relevant unmerged claim-builder, exit-feed
  and reorg work, pinned separately from the measured upstream master. Source
  findings do not imply deployment or durable recovery.
  [Primary sources](PRIMARY-SOURCE-OPTIONS.md), [source cost envelope](COST-ENVELOPE.md).

## What still blocks the complete private lifecycle

1. **Private integration:** specify and review the future receive descriptor,
   recipient acceptance and genuine private relation enforcing the same CM/NF,
   two independent secrets and committed native key. Implement and measure the
   actual private/native union, including exact backing, admission, transfers,
   rejection controls and version compatibility. The current real-NF counter
   bound must not be combined silently with old v6's two-NF input-padding
   semantics; capacity and privacy metadata need an explicit joint design.
   Existing notes do not migrate automatically.
2. **Complete fees:** the current actual 40M authorization fees remain unchanged.
   Even their cheaper native quotes plus an unamortized admission miss the
   10-tKAS lifecycle budget. Admission and payment cost allocation still need a
   genuine, correctly priced batched path; a cheap tail exit alone is insufficient.
3. **Independent end to end evidence:** backup predating receipt, durable public
   data, current accepted lineage/backing, service shutdown, contention/reorgs
   and actual confirmed testnet payout are not supplied by these checks.
   The existing price-prior privacy failure and wallet/latency requirements also
   remain unchanged. The previously rejected S7 owner/replay workflow stays parked.

Decisions: [RFC-0019](../../../docs/rfc/0019-fees-and-independent-exit-obligations.md),
[ADR-0039](../../../docs/adr/0039-exit-liability-and-native-claim-experiments.md),
[ADR-0040](../../../docs/adr/0040-public-revealing-exit-feasibility.md).
