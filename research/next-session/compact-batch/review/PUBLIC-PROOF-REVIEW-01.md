# Public genuine proof artifact review

**All three public relation canary proof reports and artifacts match the selected
roles and frozen source.** This is an independent public artifact/hash review,
not independent cryptographic verification or native financial acceptance.
Date: 2026-10-23 UTC. No owner backup/witness, PK, setup/proof/native runtime or
network operation was used by this reviewer.

The three records live in `prover/public-canary-proofs-01/`. Each is explicitly
PUBLIC_SYNTHETIC_DO_NOT_FUND with nominal public fixtures disjoint from main
owner Notes/NFs. Their reports retain the B04 build/source identity, exact public
role manifest, PK length/hash, role VK hash, fourteen actual workers and checked
Groth16 verification. Every Auth528, proof128 and VK328 public artifact was
independently read, length-checked and hashed against its report.
The combined `SUMMARY.json` SHA256 is
`fab7a00e41dc554766eeef0f04a8cb43f45e857465aaf2e7eddd89ea4fae505e`.

| Fixture | Mode/start | Reserve before | Fee | Payout | Reserve after | Prove + checked verification | Whole run |
| --- | --- | --- | --- | --- | --- | --- | --- |
| compact continuing | 2 / 2 | 130,001,000 | 1,000 | 0 | 130,000,000 | 8.820s | 12.117s |
| compact terminal | 0 / 0 | 1,000,000,000 | 1,000 | 999,999,000 | 0 | 8.627s | 11.957s |
| wide32 | 32 / 32 | 32,000,001,000 | 1,000 | 0 | 32,000,000,000 | 19.425s | 26.995s |

All values are integer sompi. Fee1000 here is a relation canary value; it is not
an actual native minimum fee or a whole-payment cost measurement. Auth magic,
mode, physical aligned start and public reserve subtraction agree with the
expected canaries. Compact terminal and continuing use the same selected VK;
wide uses the separately selected wide VK. The report's full-PK read/authenticate/
owned-decode phases precede canary use and are recorded separately from proving.

No actual owner cold recovery, economic recipients, native all-engine financial
acceptance, competing-spend/public-transition rejection, chain acceptance or
confirmed payout follows from these artifacts. Full lifecycle fee measurement
must include funding, wide delivery and every independent payout using exact
officially normalized native bodies and actual proof operands. Privacy and
long-term availability remain separate measured questions. Passing these
canaries is evidence for this implementation, not a cryptographic audit.
