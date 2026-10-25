# Public terminal verification on a fresh runner

`public_verify.py` places externally selected public bytes and calls the existing
HTTPS transport, strict archive unpacker and frozen `replay_closed.py`. It adds
no financial parser, proving, signing, wallet recovery or chain RPC interface.

The workflow is restricted to pushes on `research/shielded-kas-feasibility` that
change its source, workflow or configuration. The committed configuration starts
with `enabled: false`; there are no guessed future object hashes. Enable it only
after the actual terminal objects pass publication checks, exist at their public
URLs and pass the local HTTPS verification.

An enabled `kpx8-public-verification-config/v1` contains exactly:

| Field | Meaning |
| --- | --- |
| `schema`, `enabled` | Exact schema above and boolean `true` |
| `transport_selection.url` | Actual selection URL under the selected research release |
| `transport_selection.bytes`, `sha256` | Whole selection identity selected outside the download |
| `terminal_index.bytes`, `sha256` | Actual terminal INDEX identity, also present in the selection |

The operator verifies the INDEX before downloading the full closure. Only the
fixed verification roles, twelve complete native case groups and declared public
prefix pages are accepted. All placements are canonical and distinct. It invokes
the existing strict unpacker, then the downloaded, hash-selected `eaf2fd95…`
bootstrap over the complete retained main and post-query pages. The latter keeps
financial execution inside a namespace with original paths, network, GPU,
backups, private witnesses and proving keys absent.

Success also requires exact generated HISTORY/CHECKPOINT hashes and all twelve
whole `case.json` file identities to match the INDEX. A transaction ID alone is
insufficient because version1 IDs omit the proof witness and compute budget.

The disposable Ubuntu24.04 job installs `bubblewrap` and `zstd`. It runs the
trusted public operator with `sudo` so Ubuntu's unprivileged-user-namespace
policy need not be altered. The exact namespace smoke test precedes large
downloads. Only public source/data is supplied; child commands receive a clean
environment. Neither Forge packages nor kernel/AppArmor settings are changed.

Disk availability and an estimate for staging copies are recorded, rather than
being a new arbitrary trial-abort cap. The job retains only its small `RESULT.json`
and an aggregate log line. The compressed history and restored runtime are not
uploaded as Actions artifacts. The 120-minute job budget is operational headroom,
not a verification claim or a change to the financial trial.

Run the harmless configuration check with:

```sh
python3 -B poc/owner-private-lifecycle/recovery/public_verify.py \
  --config research/next-session/owner-private-lifecycle/availability/PUBLIC-CI-VERIFICATION.json \
  --check-config
```

Actual public verification requires explicit `--execute --output FRESH_PATH` on
a fresh host. The operator refuses execution when original Forge paths exist.
No actual off-host run is established by these source/metadata controls.

A successful hosted run demonstrates replay of the recorded public financial
evidence on another machine. It does not demonstrate off-host seed recovery,
independent administration, durable retention, independent consensus or
continuous currentness. Overall privacy and sender anonymity remain unqualified.
The manifest's `owner_client_associations_selected: false` means no additional
private recovery-client-to-note/nullifier/exit/payout mapping artifacts were
selected. Public protocol pseudonyms and the documented ordered-input linkage
remain visible.
