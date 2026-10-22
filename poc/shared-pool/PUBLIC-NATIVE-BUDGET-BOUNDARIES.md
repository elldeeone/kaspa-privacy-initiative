# Native budget boundary qualification with genuine public proofs

**Result: all 48 synthetic-context boundary cases pass full native validation
at budgets 3000 and 1600, with identical metered units.** All 48 exact native
bad-anchor controls reject. The highest measured cost is **14,970,859 units**,
leaving **1,039,140 units** below the budget-1600 allowance. This additive
checker did not change the historical v6 budget default of 3000.

The integrated factory subsequently adopted 1600 through a separate
[factory/replay regression](PUBLIC-V6-BUDGET-1600.md) and ADR-0036. The original
frozen source/evidence packet below remains unchanged. This integration copy
of the boundary helper now explicitly constructs its 3000 comparison baseline,
so it does not infer a historical budget from the new factory default.

The existing [13-operation qualification](PUBLIC-NATIVE-BUDGET.md) measures a
fixed genuine rehearsal. This experiment instead supplies deliberately varied,
**synthetic and unfunded prior contexts** to the unchanged native script and
genuine retained proofs. It corroborates the separately reviewed source upper
bound; it does not establish an authenticated prior state, value backing or
chain acceptance for these contexts.

## Frozen experiment

The sole public input is the existing selected rehearsal JSON, SHA256
`7fd8bd70774872a1748fb52d32754556e578f8abf89c76100e28e1fd315b02a1`.
No private key, opening, witness evaluation input, proving key, new setup or
new proof is used. The executable is network-isolated and sees only this input
and its own immutable binary.

The 48 cases use unchanged genuine authorization/proof/ciphertext triples:

| Original zero-based operation | Actual mode | Supplied reserve behavior |
| --- | --- | --- |
| 4 | SPEND, zero payout | Continue |
| 5 | SPEND, nonzero payout | Continue |
| 7 | DRAIN | Continue and terminal |

Each of those four behaviors has twelve cases:

- Predecessor sentinel, tail, and middle insertion.
- One differing comparison limb at a time, for all five unsigned little-endian
  `less256` limbs. Other limbs remain equal.
- All five limbs unequal, with lower limbs opposing the highest limb's result.
- Physical predecessor positions 127/128 and 32,767/32,768.
- Near-capacity commitment/nullifier state.

Every synthetic commitment suffix is deterministic public data. The genuine
commitment prefix and the proof's actual historical anchor remain unchanged.
Every odd commitment-prefix root is recomputed, including the genuine prefix;
no arbitrary root is labeled accepted. The independent nullifier linked-list
construction checks every increasing little-endian edge, physical pointer,
leaf occurrence and terminal sentinel reference before making a witness.

| Near-capacity branch | Prior CM / NF count | Next CM / NF count |
| --- | --- | --- |
| SPEND | 65,533 / 131,064 | 65,535 / 131,066 |
| Continuing or terminal DRAIN | 65,535 / 131,068 | 65,535 / 131,070 |

Both satisfy `nf_count <= 2*cm_count`. The maximum inserted NF index is 131,070,
inside the depth-17 tree. Commitment appends remain below 65,536 leaves.

## Pass conditions

For every case:

1. `PublicState::witness` and `settle` construct the actual state transition and
   native transaction, preserving proof, authorization and ciphertext bytes.
2. Budget 3000 and 1600 both pass the genuine pinned `TxScriptEngine` and full
   native transaction validator, with identical metered units and actual
   integer-sompi fee accounting.
3. Metered units remain at or below the independently derived source ceiling
   15,857,502, below the budget-1600 allowance of 16,009,999. A contradiction is
   a failed experiment; its expected result is not retuned.
4. A canonical transaction with one changed historical-anchor sibling is
   rejected with the exact typed native `VerifyError`, preventing an unrelated
   parser, resource or proof-format failure from satisfying the negative case.
5. The standard-library Python validator independently folds all historical
   anchor, NF predecessor/update/empty-append, CM append and history append
   paths; it recounts comparison vectors, capacity bounds, native outputs,
   accounting and the unchanged genuine proof identities.

The [Rust checker](src/bin/kpi-public-native-budget-boundaries.rs) and
[freeze/verification wrapper](verify_native_budget_boundaries.py) are additive.
The native dependency remains rusty-kaspa
`01b532e8b553523216471682649693af92f0fd16`; the scientific source baseline is
`ec6aa15d586bcc8a90f7232b433fd48d8c73d509`.

## Retained evidence and resource scope

[Attempt 01](evidence/2026-10-22-public-native-budget-boundaries/attempt-01/validation.json)
passed in 5.432 seconds. The complete coordinator-owned unit used 138,407,936
bytes peak RAM and zero swap. The native report preserves all 48 canonical
transactions, prior/next compact states, synthetic UTXO contexts and comparison
vectors. The independent Python checker folded **576 Merkle paths**, observed
five sentinel, seven tail and 84 middle predecessor cases, and checked all
requested limb/index/capacity shapes. These observations overlap at the tail
sentinel where applicable; they describe the 96 individual insertions.

The first resource sampler started after that short job completed. Its
[resource receipt](evidence/2026-10-22-public-native-budget-boundaries/attempt-01/runtime-receipt.json)
therefore retains systemd's invocation ID, main PID, monotonic start/end and
peak counters, while explicitly recording that live `/proc` start ticks were
not sampled.

A second resource-audit run had already been launched when the coordinator
advised that this repetition was unnecessary. It is retained separately as
[attempt 02](evidence/2026-10-22-public-native-budget-boundaries/attempt-02/runtime-receipt.json),
without increasing the scientific case count or claimed coverage. Its native
JSON is byte-identical to attempt 01; four live PID/start identities were
sampled and all matching processes disappeared after completion. Its peak was
138,489,856 bytes with zero swap. Both owned runtime units are stopped, with
empty cgroups. No further repetition was performed.

An initial source-only compile failed because the new checker omitted the
explicit `u16` conversion into native `ComputeBudget`. Correcting that Rust
type conversion produced the executable used by both runs. It changed no
case, expected outcome or protocol check. Both build records remain in the
coordinator's `native-runtime/boundaries-build-01` and `boundaries-build-02`
directories.

## Interpretation limits

Native verification authenticates execution against the **supplied** UTXO
context. These prior UTXOs have synthetic outpoints, NF sets and reserve values;
there are no actual funding transactions. The historical commitment prefix is
genuine, but the synthetic later context is not claimed to arise from a valid
sequence of prior operations. No ledger acceptance, backed pool, economic
default, spendable funds, privacy qualification or cryptographic assurance is
established by this experiment.
