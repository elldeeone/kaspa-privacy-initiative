# Independent public replay results

The generic replay recovered the completed TN10 pool from a public descriptor
and freshly fetched network records. It reconstructed the terminal state without
operator snapshots, owner labels, expected payments, private keys or a proving
key. All five discovered pool bodies also passed the pinned local native
validator, including Full and every input script engine.

This closes public reconstruction of this completed history. A newly recovered
unspent note followed by a fresh confirmed exit remains a separate experiment.

## Actual network history

Input identity:

- Descriptor: [`../fetch/descriptor-v1.json`](../fetch/descriptor-v1.json), canonical
  SHA256 `434cefba486cf7d41afb44c0f538be898f93d4440bf70b1b40cbfaff4cfef1dd`.
- Fresh vector fetch: [`../fetch/vector-refetch-02/network-data/fetch.json`](../fetch/vector-refetch-02/network-data/fetch.json),
  SHA256 `9390feab0166ca7710e4357ef6aa079d5bef10f84e357b4776d72c148ecba9e4`.
- Approved validator ELF SHA256
  `73fb41c66c374da91200f06ae442f5bd8beb3c7954c71fae954b12bec9b1c1cf`.
  Its source/compiler/template provenance is retained in
  [`template-build-01/`](template-build-01/).

The input graph, rather than a hardcoded stage list, selected founding, admission,
private transfer and two reveals. Replay derived four CM/delivery records, five
physical indexed-nullifier records and final reserve zero. Both native payout
outpoints were present in the fetcher's current queries at that observation.
Their values were read from validated reveal outputs; they were not inputs to
recovery.

The local native run checked all five bodies with their actual fetched input
contexts. A sixth validation changed one ciphertext byte and recomputed its
public Auth ciphertext hash while retaining the original curve proof and input
signature script. It reached Groth16 verification and rejected with
`Groth16 verification failed`. This distinguishes a proof/transcript failure
from a framing-only rejection.

[`live-refetch-01/evaluation/RESULT.json`](live-refetch-01/evaluation/RESULT.json)
and its six public case/report pairs retain the result. Public replay plus five
positive native validations took 0.0712 seconds. The complete offline process,
including JSON loading, result writing and the negative control, took 0.13
seconds under GNU time and reached 35,264 KiB maximum RSS. It ran with network
unshared, 2 CPU quota, 6 GiB memory and swap zero. The owned unit exited with no
remaining processes; caps, telemetry and cleanup are retained.

The distinct electron fetch corroborates the same selected bodies, input
contexts, accepting headers and current queries; see the fetch lane's
corroboration artifact. The local native run above used only the vector bundle.
Neither endpoint agreement nor local execution establishes independent
consensus. Local Full validates the supplied input contexts; accepted inclusion,
scan completeness and the latest view retain the selected validating-node
premise. The finite scan/current queries are not an atomic or permanent view,
and durable historical data availability is not established.

## Public replay controls

[`tests-01/RESULT.json`](tests-01/RESULT.json) records 26 passing controls against
retained public records, with no new RPC. These cover missing prefix/middle/tail,
duplicate/competing spends, wrong policy/genesis/input context, corrupted
ciphertext and CM/NF witnesses, false terminal/current queries, stale or removed
frontiers, false depth metadata and integer/extra-field rejection. Incremental
Merkle roots and paths also agree with the existing immutable V2 full tree over
80 seeded append cases. The separate adversarial review found three current-view
and confirmation-binding defects before the frozen run; those fixes and their
negative controls are included in the final source.

The exact source and actual-run artifact closures are retained under
[`../adversarial/`](../adversarial/). Passing these controls is implementation
evidence, not a proof of cryptographic correctness or privacy.

## One unproved 10,000-operation cost run

[`scaling-01/report.json`](scaling-01/report.json) measures the same public state,
witness, policy, value and lineage checks on **unproved synthetic input**. It uses
one founding plus 9,999 private one-real/dummy splits: 10,000 total operations,
19,999 CM records, 19,999 physical NF records and 10,000 positive unspent notes.
Final synthetic backing is 600,000,000,000 sompi. The fixture is explicitly typed
`kpx2-unproved-synthetic/v1`; normal network replay and the wallet reject it.

| Measurement | Observed |
| --- | ---: |
| Fixture generation | 2.186 s |
| Stream JSON encoding and SHA256 | 1.981 s |
| Actual JSON decode after releasing generated objects | 1.124 s |
| Public replay of decoded bundle | 10.702 s |
| Whole process, GNU time | 16.09 s |
| Maximum process RSS | 1,653,796 KiB |
| Maximum observed cgroup memory peak | 2,252,382,208 bytes |
| JSON fixture size | 550,304,208 bytes |
| Ideal transfer arithmetic at 20 Mbit/s | 220.122 s |

The outside-Git fixture has SHA256
`ec1f4f0b9d9242e6f3948bc672f9a0a773c82ffb9c1a1049d536672feb19f4c1`.
Only its complete identity, source, plan, report and resource logs are published.
There was one frozen scaling run, with 2 CPU quota, 6 GiB memory, no swap and no
network, native ELF, seed, PK or prover mounted. Cleanup is empty. The 15-minute
and 4-GiB research scores were not operational abort limits.

Synthetic proofs, signatures, transaction IDs and recipient ciphertexts are not
valid chain material. `complete` remains false; crypto, consensus, native
execution, actual network download and full wallet recovery were not measured.
The 20-Mbit/s figure is byte arithmetic, not a measured throttled transfer or
whole-recovery qualification. One run on this machine is not a reference-device
p95. Public computation was small here; raw accepted-history discovery and
retention remain distinct costs, as the actual fetch evidence shows.

## Trust and remaining work

The receiver must authenticate the descriptor digest and founding outpoint from
wallet setup. Matching domain/code cannot choose between separately funded pool
copies. The installed approved full policy template checks the selected
protocol's semantics; descriptor or RPC input cannot choose executable code.
The development setup VK and selected node remain explicit assumptions.

The replay exposes authenticated deliveries and physical nullifier state to the
separate seed-only wallet. That wallet must establish ownership by decrypting
and validating notes, and distinguish historical receipts from current native
UTXOs. A failed decryption cannot prove that every unknown positive note belongs
to someone else. This work does not recover orphan disclosures or local invoice
issuance state, hide public REVEAL exits, demonstrate permissionless proof
availability, establish durable data availability or qualify a complete private
payment system.
