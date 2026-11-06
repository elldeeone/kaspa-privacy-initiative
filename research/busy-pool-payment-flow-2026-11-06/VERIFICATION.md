# Verification receipt

Completed locally on 6 November 2026. These checks do not prove cryptographic
correctness, independent recovery, production safety or accepted chain state.

- New queue release tests: **3 passed**. Retry retains original age/payload;
  payment batches do not pass an older withdrawal; partial acknowledgments,
  duplicate retries and invalid batch bounds refuse.
- Complete host preflight passed both full-drainage routes; six additional guard
  controls passed. This stage alone made no outer receipt/native-acceptance claim.
- The paired experiment completed **11 genuine proving executions**. Both full
  native histories drain principal/liability; eight restored-key output spends
  validate. Queued child-before-parent and double-spend guards refuse. A real
  stale native receipt transplanted into new effects fails Groth16 integrity.
- The supplementary owned-CUDA cancellation and fresh complete proving execution
  passed. A different fresh native proof witness fully replays in the unchanged
  history, preserving IDs, descendants and all payout spends.
- `bash poc/busy-pool-payment-flow/check.sh` passes without wallet backups,
  proving parameters or GPU. It authenticates both executed source epochs,
  verifies SDK receipts/actual native effects/current ancestors, reproduces six
  guard refusals, regenerates observer/measurement outputs, and replays the fresh
  replacement witness. The original stale refusal was observed by the frozen
  producer; it is distinct from the accepted-history public replay.
- `bash scripts/ci_fast.sh`, `python3 scripts/research_knowledge.py check`,
  `python3 scripts/check_rfc0004_accounting.py` and
  `python3 scripts/check_rfc0004_review.py` pass. Historical/static checks retain
  their original scope and do not establish new native/privacy facts.
- The finite **129-file evidence export** passed an exact-material scan against
  all excluded wallet backups and native private keys. Public manifest/source
  hashes pass; raw runtime, keys, proving parameters and compiled host stay local.

The selected group/source UTXOs are synthetic. No RPC/broadcast, funded trial,
provider allocation/invoice, mainnet action or consensus change occurred.
