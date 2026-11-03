# Private-action proof results

The new unfunded relation completed 49 frozen full-CS controls: **8 SAT and 41
UNSAT**, with no host/parser rejection counted as UNSAT. It has 3,231,025
constraints, 3,195,131 witness variables and 3 instances including the constant.
[Raw results](RESULTS.json) pin the source, fixtures, reports and session.

One new OsRng setup produced one new VK. These five actual fee-fixed public
synthetic fixtures then each produced a genuine proof with checked verification
under that same resident VK:

| Case | Witness/prove/checked-verify seconds |
| --- | ---: |
| Ordinary P=0 payment | 8.293 |
| Bob payout with private change | 7.989 |
| Bob full owned-note payout while pool continues | 8.200 |
| Charlie terminal payout, no CM append | 8.129 |
| Rebound current Auth after Bob's NF was occupied by REVEAL | 8.090 |

The last proof establishes ownership-relation validity only. Its occupied current
NF must fail native absence validation. Actual native acceptance, both race
orders and body validation are recorded by the separate lifecycle/native lanes.

Setup took 13.316s, or 14.879s including official uncompressed PK serialization.
The new PK is 1,290,878,896 bytes, mode 0600, outside Git; there is no PK/matrix loading
API. The whole session used 444.26 CPU seconds, cgroup peak 5,595,713,536 bytes,
zero swap and app GNUtime maximum RSS 4,148,144 KiB. Its 6:13.20 wall includes
several minutes resident idle awaiting the reviewed actual packet. Phase peaks
are not independent. Cleanup is inactive/dead/PID0 with exit 0. The first sizing
run's outer GNUtime wrapper RSS is explicitly invalid as app RSS; later app
GNUtime runs execute inside the namespace.

Fixed-allocation source review plus five same-VK genuine proofs establishes
compatibility of the tested modes. A complete sparse-matrix digest was not
computed. One proof timing per statement does not qualify p95 performance.

This is not funded, accepted chain backing, privacy qualification, production
security or a cryptographic audit. Payout values, fees and traffic remain public;
terminal drainage and external knowledge can reveal amounts. The 147,500-mass
verifier floor still implies 22,125,000 sompi for one half-amortized payment proof
plus one independent private exit at reference 100, exceeding the 20,000,000
sompi complete-lifecycle target before other costs. The fee failure is retained.
