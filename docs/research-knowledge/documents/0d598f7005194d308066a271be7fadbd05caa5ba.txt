# Independent-payment privacy controls

This package checks eight fixed public falsification groups and one separately
frozen outgoing-recipient regression. It does not generate a new holdout,
rescore the old 96 views, create native transactions or establish cryptographic
anonymity.

- `ledger.py`: strict symbolic public data and independent integer certificate
  checking, including one/two real inputs, partial payouts and exact spentness.
- `observer.py`: complete selected/excluded-input queries and limited, explicit
  application-role deductions from legitimate participant facts.
- `partitions.py`: disclosed-component recovery and the restricted direct
  same-partition invoice rule. A display permutation is not hidden assignment.
- `fixtures.py`: reviewable public controls; full owner/purpose maps stay in the
  separate runtime. Symbolic CM/NF/cipher labels are not real cryptographic data.
- `run_controls.py`: eight control groups. Expected leaks are privacy failures,
  even when the control correctly detects them.
- `run_outgoing_addon.py`: unchanged red/green calibration of legitimate outgoing
  recipient ownership, for one/two-input allowances.

[Design and exact interfaces](../../research/next-session/independent-payments/privacy/DESIGN-01.md)
preceded execution. The first source and run are retained; source02 adds the
review-found missing outgoing recipient fact. All global SAT certificates are
checked against original conservation/spentness equations and their requested
query. UNSAT relies on the pinned Z3 model/execution. This is not an exhaustive
owner-world reasoner or a claim that arithmetic alternatives have cryptographic
preimages/equal probabilities.

The known one-invoice positive-change policy is stronger than the generic
compact relation and is explicitly supplied. Bootstrap ownership, all own
notes/NFs and outgoing invoices are included when legitimately known. Current
payer roles never simply become original funding-source labels. A prospective
nonterminal no-append mode is distinctly labelled and is not native acceptance.

No keys, seed material, financial backups or real/private whole-claim NF-pair
alternatives are used. No cryptographic relation, mainnet, fee qualification or
privileged withdrawal is introduced. The original amount-prior and sparse
funding failures remain.
