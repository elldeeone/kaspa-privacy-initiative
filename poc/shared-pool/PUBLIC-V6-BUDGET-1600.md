# v6 transaction factory budget 1600

**Result: the v6 transaction factory now selects budget 1600.** All 13 rebuilt
genuine public transactions pass full native validation, and complete
historical3000 and factory1600 replays produce identical public state and
integer accounting. All five negative controls reject at the intended layer.

The integration change sets only the v6 reserve-input factory budget to 1600.
The other protocol versions retain their prior constants. The fee remains
40,000,000 sompi. Historical transactions and evidence are preserved exactly.
The decision is recorded in [ADR-0036](../../docs/adr/0036-v6-native-budget-1600.md).

Three pieces of evidence support the narrower default:

- The fixed-v6 source bound is 15,857,502 script units, below the 16,009,999
  allowance at budget 1600.
- All 13 genuine public rehearsal operations passed full native validation at
  1600 with unchanged proof, authorization, ciphertexts, outputs and signatures.
- All 48 synthetic-context comparison/index/capacity boundary cases passed at
  1600, with real unchanged proofs and explicit unauthenticated-context limits.

Those earlier packets were produced from a factory whose default was 3000.
Their source hashes, manifests and bytes remain historical evidence. The
integrated boundary helper explicitly constructs its 3000 comparison baseline;
it does not infer that baseline from the current factory default.

## Replay compatibility

The replay verifier formerly reconstructed transactions using the current
factory default. Changing that default alone would reject genuine historical
3000-budget transactions at the exact-body comparison.

Replay now preserves only the supplied reserve input's typed version-1
`ComputeBudget` in its reconstructed transaction. It finalizes the transaction,
recomputes contextual storage mass and still requires every other canonical
field to match. Native script metering and full transaction validation remain
mandatory. Explicit compute/storage/transient mass limits of
500,000/500,000/1,000,000 prevent an excessive declared budget from bypassing
transaction capacity. Relay-fee, standardness and sigop policy checks retain
their existing separate locations.

This accepts a native-valid operational budget without making it proof-bound.
At the pinned native source, transaction version-1 IDs and `SIG_HASH_ALL` omit
the compute budget; the full transaction hash includes it. Lower budgets must
still execute the real verifier successfully.

## Final regression requirements

[The new factory checker](src/bin/kpi-v6-budget-adoption-check.rs) uses only the
same allowlisted public rehearsal. It rebuilds all 13 transactions through
`PublicState`, `witness` and `settle`, rather than editing a budget field on an
already-built candidate. It requires:

1. Actual factory selection of 1600; exact unchanged proof/redeem/reserve and
   successor scripts, authorization, ciphertexts, amounts, signatures, outputs,
   contextual storage mass, transaction IDs and native `SIG_HASH_ALL` values.
   Full hashes must change.
2. Full native validation and existing factory policy checks for both versions,
   unchanged actual script units, and matching independent retained hash/meter
   vectors from the earlier budget screen.
3. Successful complete historical3000 and factory1600 replays, with identical
   final public state and integer-sompi accounting.
4. Precise rejections for a genuinely underbudget input, changed fee/output,
   wrong genuine proof and excessive65535 declared budget. The excessive case
   must pass the actual proof predicate and then fail the explicit mass check.

[The Python wrapper](verify_v6_budget_adoption.py) freezes source, lock, public
input and executable before its network-isolated native process. It compares
canonical public bodies, actual parent SPKs and previously retained native
hash/meter vectors independently of the new checker.

[The successful run](evidence/2026-10-22-v6-budget-adoption/attempt-01/validation.json)
completed in 0.393 seconds. The full coordinator-owned unit peaked at
31,367,168 bytes RAM and zero swap under a two-CPU, 2 GiB, ten-minute cap. Four
live PID/start identities were observed; all matching processes disappeared
after completion. All owned build/runtime units are stopped with empty
cgroups. The [manifest](evidence/2026-10-22-v6-budget-adoption/attempt-01/MANIFEST.json)
pins the final source, public input, executable and exact native hash/meter
vectors; the separate runtime receipt records resource identity and cleanup.

## Limits

The change reduces declared compute mass; it does not reduce the actual native
proof-verification work. At the declared 500-sompi/gram stress rate, the maximum
measured necessary fee remains 95,814,000 sompi, above the 60,000,000 minimum
note. Including the 10,000,000 payout floor requires at least 105,814,000 sompi.
The singleton minimum-note problem at that rate remains.

No new cryptographic relation, setup, proof, key, network operation, funded
context, chain-acceptance assertion or privacy qualification is introduced.
