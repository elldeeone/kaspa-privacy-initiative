# Fresh service-loss recovery: confirmed TN10 payouts

The fresh old-KPX2 trial completed the service-loss path. After private payment
and prover shutdown, two isolated clients each used one seed backup and newly
fetched public data to discover their unspent claim, quote and sign a new
consented revealing exit. Both native test-KAS payouts confirmed.

The successful identity is trial `0c29caac-c339-4474-abd4-28fcbcc92641`, domain
`7b2e385d172c8d1a7b509174ede883faa228d553dec94f1ae6a5560435bde956`.
It is distinct from the abandoned, unfunded `c0d00370…` identity. That first local
run passed its proof and six native checks, then failed SDK bookkeeping because
systemd's PATH omitted Node. Its exact records and the unused first merge remain
retained. The corrected runtime checks Node before reading seeds or starting
setup. [Retained failure](retained-local-failure-01.json),
[unused merge](service-loss-02/ordinary-funding/20261023-ordinary-merge-01/UNUSED-PUBLIC.json).

Seven transaction broadcasts confirmed: the ordinary funding merge, funding
preparation, founding, admission, private payment and the two newly built exits.
The private payment created two 60,000,000-sompi notes. Whole-source accounting is:

| Destination | Sompi |
| --- | ---: |
| Bob payout | 55,026,200 |
| Charlie payout | 55,036,800 |
| Ordinary source change | 24,398,700 |
| All seven transaction fees | 40,413,200 |
| **Original ordinary source** | **174,874,900** |

Fees include the 274,600-sompi ordinary merge and 40,138,600 sompi for the six pool
lifecycle transactions. Each exit exceeded the strict greater-than-20 depth
policy, at observed depths 185 and 188. The subsequent descriptor-only terminal
refetch and local public native replay checked all five pool transactions,
reconstructed CM4/NF5 with zero reserve and no pool head, and found both payouts
unspent. That final check read no seed.
[Fresh terminal closure](../wallet/unspent-terminal-01/RESULTS.json).

The [95-file public packet](service-loss-02/PUBLIC-FILES.json) preserves exact
public bodies, contexts, releases, once-only intents and confirmations. Its
[hash manifest](service-loss-02/SHA256SUMS.json) covers 94 payload files. Seven
bulk observations totaling 462,309,586 bytes remain local; the sanitized packet
is 985,123 bytes. The exporter passed eight public controls and independent
adversarial review. [Exporter controls](EXPORTER-CONTROLS.json),
[matching source and prefix review](readiness-02/index.json).

This closes the tested R1 liveness path under selected validating-node, retained
public-data, authenticated-descriptor, installed-software and development-setup
assumptions. Adapter headers with empty parent objects remain node assertions;
the fresh fetcher's expanded, rehashed headers are separate evidence. These
Auth484 fallback exits disclose note details and native payouts with explicit
consent. The small trial does not qualify fees, financial privacy, independent
consensus, durable data availability or production safety. The Auth528 private
cashout prototype remains a separate unfunded experiment.
