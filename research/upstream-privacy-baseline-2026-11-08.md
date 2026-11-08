# Upstream baseline for the current-L1 privacy comparison

Checked 8 November 2026 (Australia/Sydney). This is a read-only source refresh,
not a new privacy result or a decision to send work upstream. `git fetch upstream
main` and `git ls-remote --heads upstream` found the sole upstream head at
`7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`, the same commit retained as the
5 November baseline. GitHub's [pull-request list](https://github.com/olafweller/kaspa-privacy-initiative/pulls)
showed zero open PRs at this check. Historical PR heads are not current branches.

## What the upstream code actually supplies

- The [README at that commit](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/README.md)
  and [RFC-0001](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/docs/rfc/0001-state-architecture.md)
  keep the production architecture open. A single Based App is a provisional
  investigation; a direct covenant is a comparison option. Neither architecture
  has a complete privacy or N-user shutdown qualification.
- The [actual TN10 recovery result](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/recovery-tn10/live-2026-10-20/README.md)
  records a 10-test-KAS deposit, owner-local private credit and payment, Bob's
  4-KAS withdrawal, Alice's final 6-KAS withdrawal, six real outer receipts and
  six accepted native settlements. The original application entry point became
  unavailable, and a separate operator replayed accepted state without its
  cache. The owner-reported local wallet restores are distinguished from those
  independent observations. Both payout outputs were found unspent at readback;
  this is bounded functionality/recovery evidence, not measured anonymity.
- [RFC-0002](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/docs/rfc/0002-shielded-payment.md)
  specifies hidden note ownership/amounts during private payment, while its exit
  intent still includes a public destination and principal. It is proposed, not
  an accepted production protocol. The [recovery implementation package](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/recovery-tn10/README.md)
  explicitly uses Bob then Alice as separate exits, including a full terminal
  drain. A case-insensitive search over `poc/` and `docs/` at this commit found
  no blind-signature, common-set or atomic-bundle withdrawal implementation.
- [P13](https://github.com/olafweller/kaspa-privacy-initiative/issues/13) is
  open and asks for timing, amount, RPC, network, wallet-correlation and
  outsourced-prover leakage; it distinguishes proof confidentiality from
  measured anonymity. The only visible comment at this check is the fork's
  7 November active-service timing finding. It explicitly says it is not an
  upstream bug report. No upstream adoption or privacy agreement follows.

## Fair comparison boundary

Upstream has a **runnable, bounded two-user deposit/payment/sequential-exit
baseline**. It does **not** already have the same three-claim equal-value group
withdrawal, blind reply service, 47-useful-KAS workload or complete observer
transcript as this branch. A direct code-level privacy score of upstream versus
the bundle would confound different workloads, participant counts and exit
relations. Current upstream source supports a **field-level comparison**:
published exit amount/destination versus the fork's whole-set payout mapping,
with identical disclosed owner/fee/contact facts. A future matched implementation
would need an explicitly scoped adapter and a predeclared common workload; do not
label the present traces as a matched trial.

The immediate low-cost falsification should use the fork's already accepted
transcripts, keep all legitimate known-owner and public-amount facts, and score
private *payment* facts after full withdrawal. The result can decide whether an
independent-wallet or larger-cohort run is warranted. It cannot, by itself,
demonstrate that the bundle beats upstream's unimplemented alternative for the
same workload. No consensus change is available or proposed.
