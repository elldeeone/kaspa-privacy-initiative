# Fresh-owner launcher and context boundary review

**Source ACK for root-released bounded synthetic owner execution, conditional
on the selected cold-loader gate.** This adds launcher review to
`OWNER-RECOVERY-SOURCE-REVIEW-01.md`; it does not claim an actual owner run.
Only public source was read. No backup, witness, PK, model truth, native/proof
runtime or network operation was used by this reviewer. Date: 2026-10-23 UTC.

| File | SHA256 |
| --- | --- |
| `poc/compact-batch-lifecycle/run_owner.py` | `c620788d4f694ea25f4876c49a4f853d39224eef83e91501ad819796c2cc5185` |
| `poc/compact-batch-lifecycle/owner.py` | `8d6a0bfedc9072039ad6a8d126af78ef2222274d8aa14b493c15968c6c2b1a49` |
| `poc/compact-batch-lifecycle/native_runtime.py` | `dac6d42987a9419864c967773677a033c143028053f33f5f6ad506739ef005af` |

Each action constructs a fresh bwrap process with all namespaces unshared,
cleared environment, private proc/tmp, selected read-only software, only its own
original backup, one shared read-only role PK, public selection/descriptor/history
and a fresh output directory. Controller plans, other backups, earlier private
outputs and the repository parent are absent. The payer receives only the public
recipient invoices. The outer entry records actual cgroup limits before entering
the mount namespace; its own directory is not mounted inside. Every action starts
a standalone prover; no resident prover or aggregate owner witness is introduced.

The first pass found that the pre-read inode guard omitted three SDK dependency
files later read during pre-READY history normalization. The implementation now
defines shared `SDK_FILES` for `kaspa.js`, `kaspa_bg.wasm` and `package.json` and
uses that same tuple in both owner/launcher guards and mounts. These metadata
checks precede public copying/hashing/reads. This correction does not alter the
Rust relation, native policy or proving parameters.

The accompanying `public_case` correction validates an exact five-field supplied
context: canonical decimal amount/DAA strings and bounds, canonical hex SPK,
`is_coinbase is False`, `covenant_id is None`, exact input/context count. It then
preserves the validated flags rather than silently projecting arbitrary supplied
flags into false/None. Supplied synthetic contexts remain supplied evidence;
their validation cannot establish actual accepted chain UTXOs or DAA scores.

The launcher source cannot prove that all32 owners were actually isolated or
that original sources/caches disappeared. Retain each actual standalone run's
selected READY/worker result, observed limits, namespace absence controls and
cleanup classification. Missing kernel process observations must remain unknown,
not be relabelled zero. A separate genuine mirror retrieval and cache-loss cold
case is still needed. None of these source properties establishes independent
providers, durable public retention, current chain spentness or funded payouts.

The private-SAT wrong continuing CM-root control still needs native rejection;
the correct private relation intentionally leaves public tree transition checking
to native execution. Cross-role/REVEAL real-NF replay and competing-spend checks,
all32 recipients' own receipt/CM/NF reconstruction and exact whole-lifecycle fees
remain actual execution evidence to obtain. Publishing raw private alternatives,
own backups or owner maps is not permitted by this review.
