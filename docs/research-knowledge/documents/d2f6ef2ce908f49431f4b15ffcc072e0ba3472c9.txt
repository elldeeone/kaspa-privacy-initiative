# Native-KAS research checkpoint

This branch combines two separately published research snapshots. It contains
source and public test data; a complete fundable private payment system has not
been demonstrated. DO_NOT_FUND.

The [latest fee and independent-exit checkpoint](research/next-session/exit-fee/RESULTS.md)
records the new public self-funded native reveal prototype, finite liability
models and upstream permission-claim cost checks. Its current-state/authority
and fee results do not implement the future private-proof branch or complete a
private payment lifecycle. All keys/credentials in these fixtures are deliberately
public test vectors. The [previous cost and correctness checkpoint](research/next-session/RESULTS.md)
retains its separate proof/performance and budget results unchanged.

| Snapshot | Retained result | Evidence |
| --- | --- | --- |
| [85e3939](https://github.com/elldeeone/kaspa-privacy-initiative/commit/85e39398fd97ff0299e07fad8899cd3f4cc454ac) | Development-instance J42 binding and synthetic J336 state proofs, supplied-context native checks, observation and v6 budget1600 | [Checkpoint](research/intensive-2026-10-22/FINAL-CHECKPOINT.md), [results](research/intensive-2026-10-22/RESULTS.md) |
| [68d7b03](https://github.com/elldeeone/kaspa-privacy-initiative/commit/68d7b039f606bd42b39d8d1317c0bfd76c277ae0) | Separate fresh key/domain/image; four inner proofs, initial native prefix, alternative ordinary spends and genuine paired J336/native Full check | [Fresh-prefix result](research/intensive-2026-10-22/INITIAL-FOUR-AND-NATIVE-PREFIX.md), [public oracle](research/intensive-2026-10-22/lifecycle-oracle/PUBLIC-ORACLE-MANIFEST.json) |

The profiles have different keys, domains and images. Do not mix their proofs or
context. Fresh S7 budget1700 is separate from historical v6 budget1600.
The original publication guides are preserved under publication/snapshots.
Their relative links describe their original branch roots; use the commit links
above for those exact views. [REPRODUCE.md](REPRODUCE.md) gives merged-tree checks.

Proof/native checks concern the tested implementation and supplied UTXOs. They do
not establish accepted ancestry, backing, cryptographic correctness, production
safety, permissionless exits or financial privacy. The setups are untrusted
single-party test setups. No mainnet use, real funding or live broadcast is part
of this checkpoint. The previously rejected owner CLI/public replay/DRAIN workflow
remains parked and was not completed by this merge.

Two feasibility limits remain under unchanged [RFC-0012](docs/rfc/0012-useful-privacy-requirements.md):

- The declared price prior alone reaches21.0977%, exceeding the20% absolute
  approximate-amount cap. The completed workload remains unqualified.
- One native Groth16 verification costs at least147,500 mass: at500 sompi/mass,
  its73,750,000-sompi fee exceeds the supported60,000,000-sompi minimum claim,
  before transaction overhead. Aggregation cannot guarantee a lone user's exit.

Git intentionally omits generated software, producer-only test-wallet/plan files
and the962MB public proving key. [The combined omission map](publication/OMITTED-ARTIFACTS.json)
preserves hashes and original local locations. Frozen manifests and branch
inventories remain unchanged; some name omitted files or historical paths.
They cannot all close against this merged public view. Retained receipts, VKs,
proof bundles, native bodies, source and negative results remain available.
[Third-party notices](publication/THIRD-PARTY-NOTICES.txt) and
[build guidance](research/publication-notes/PROOF-BUILD-GUIDANCE.md) accompany them.
