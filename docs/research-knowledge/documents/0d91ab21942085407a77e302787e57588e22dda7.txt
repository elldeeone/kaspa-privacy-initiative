# Ordinary acquisition commands

Run the same `ordinary_funding.py` command with one operation: `collect`, `quote`, `sign`, `submit`, then `reconcile`. Each controller output must be fresh and outside Git. All commands require the selected software root, externally pinned source freeze, financial profile, externally pinned constructor receipt, selected original LIVE trial directory, and both original trial directory exclusions. Default behavior only stages; actual execution requires `--execute` and the applicable root release.

Common arguments:

```text
--software-root SOFTWARE --source-freeze SOURCE --source-freeze-sha256 SOURCE_SHA
--profile FINANCIAL_PROFILE --identity PUBLIC_CONSTRUCTOR_RECEIPT --identity-sha256 IDENTITY_SHA
--live-trial-directory LIVE_ORIGINAL_TRIAL
--exclude-trial-directory LOCAL_ORIGINAL_TRIAL --exclude-trial-directory LIVE_ORIGINAL_TRIAL
--output FRESH_CONTROLLER
```

1. `collect` additionally takes `--rpc APPROVED_TN10_RPC`. It produces `OBSERVATION.json` containing only mature ordinary A coinbase sources. Wait for adequate maturity and value before quoting; collection reserves no intent.
2. `quote` takes `--observation OBSERVATION --observation-sha256 SHA`. The closed network-off worker produces `client/run/validation-case.json` and `client/run/QUOTE.json`.
3. `sign` additionally takes `--case UNSIGNED_CASE --case-sha256 SHA --quote QUOTE --quote-sha256 SHA`. The closed worker mounts only the selected LIVE original A backup and produces a signed `client/run/validation-case.json`.
4. `submit` uses that signed case, original quote, selected source observation and `--rpc`. It performs a new closed public Full check, fresh source queries and one immutable intent before at most one submission. Its network result is a query-only status.
5. `reconcile` uses the same signed case, quote and observation pins and `--rpc`. It never submits. It produces `NETWORK-RESULTS.json` and, only after exact output observations, `ACQUISITION.json`.

The selected constructor namespace holds `ordinary-funding-intent.json`. If it exists, no new quote, signature or submission is allowed there. Preserve it even when the response is unknown. Continue with `reconcile`; failed trials use a fresh constructor identity and namespace.

After acquisition is observed, GN2 uses exact ordinary outputs 0 and 1, each 2,100,000,000 sompi, as its A and C sources. Output 2, if present, remains A's ordinary refund. Capture a fresh anchor and sources for the GN2 workflow; do not substitute a local rehearsal history or reuse a proof from another trial.
