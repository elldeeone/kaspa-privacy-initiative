# Recipient experiment versions

The selected prospective integration is [V2](v2/README.md): separate per-invoice
note incoming bytes and a stable delivery public key in Invoice208. Its
[27-check result](../../research/next-session/private-integration/recovery/V2-REPORT.md)
is offline and uses an explicit synthetic accepted-state/archive oracle.

The original files in this directory remain the immutable V1 experiment. Its
[25-check result](../../research/next-session/private-integration/recovery/REPORT.md),
source manifest and observed shared-incoming privacy channel are preserved.
V2 lives in a separate subdirectory and uses the unchanged pinned Rust bridge.

Neither version broadcasts, replays a ledger, authorizes a withdrawal or proves
accepted backing. All development keys are public DO_NOT_FUND test fixtures.
