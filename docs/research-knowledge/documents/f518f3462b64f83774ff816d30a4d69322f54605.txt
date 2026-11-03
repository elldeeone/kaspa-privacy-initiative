# Non-live observed read-retry component

This standalone family adds public failure observations and one classified read retry. It has not run against Tor, the SDK or testnet, and is not a profile or financial readiness claim.

- The facade still uses the production Tor bridge and the same closed five-method read-only IPC. The six network rows include both the original worker and its qualified staged counterpart; confirmation also authenticates its own source row.
- Every worker generation drains stdout/stderr before its failure snapshot. The public event journal retains only closed typed stage/error hints, method/cursor/count metadata, actual exit code/signal and stream closures. Raw diagnostics, arguments, addresses, environment and response bodies are not retained.
- Only a negative IPC reply with a matching current-request SDK_AWAIT/FAIL/DISCONNECTED event permits one retry. The facade closes that generation, opens a fresh Tor stream to the identical peer and sends the same JSON snapshot of the original method/params. Worker IDs restart per generation; public logical calls and journal sequence remain monotonic.
- Unknown EOF, parse/shape/encode failures, other worker phases, timeouts and cleanup failures do not retry. The original and second failures remain separate; cleanup rejection preserves the primary failure.
- The fetch still awaits qualified parallel preparation before connecting. Admission, fixed frontier, stale/reorg fallback, current-view, whole-CASE, payout and financial replay checks are unchanged. The original runtime/cache/admission and all frozen variants/corpora remain intact.

Validation: two Node syntax checks and two guarded Python AST checks passed. Independent bounded controls passed 23 groups with 16 local synthetic children. The first run had a fixture keepalive setup failure; both runs are recorded in the control report. The existing 217-file byte-equivalence benchmark was not repeated.

Adversarial boundary: repeating a closed read cannot submit, mint or withdraw KAS. Reconnection adds no acceptance authority and preserves the existing selected-validating-node trust assumption. Chain/reorg and value checks remain with the unchanged acquisition/replay path. Public cursors and stage timing are observable in the diagnostic journal; this is not privacy or cryptographic proof.

Any raw-response reuse must use separately reviewed siblings; it is absent from this six-row family. Root source review is the next gate before any separately authorized profile or execution.
