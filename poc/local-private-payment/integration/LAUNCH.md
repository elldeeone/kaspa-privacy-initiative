# Confirmed trial02 release interface

Reviewed caller: `campaign.py`, SHA256
`32c8f9888f6b8025cc259e981b18d28c2226c4a5e1bce9116f999d0f627c358f`.
Producer/launcher: `launch_campaign.py`, SHA256
`20399a06eebb18e7721a547e66cbf6475c3439a0599a27b215acafd394c2503b`.
Frozen public proposal:
`/var/tmp/kpi-local-private-payment-01/campaign/trial-02/PROPOSAL-03.json`, SHA256
`526b5bc25dbf92a367fdf7ad2482cadcf840fcb4c9b430997b861042f2e3b5db`.

The earlier70ee/proposal02 execution freeze is revoked and retained. The
corrected caller binds every reserve input field to the pinned CURRENT-ENTRY
and CONTEXT, including actual birth DAA606339508, before owner authority and
passes that birth score explicitly to the unchanged generic native builder.
Both payment and downloaded cold-exit paths use the same binding.

The proposal selects actual confirmed GEN3 handoff SHA256
`29d6925fb33fe4ce0b51f08f0ae12d9095ff0d5ae1d78795514ab14b3ed718de`,
60testKAS, the reviewed new financial image/profile, fixed fee cap and complete
static driver closure. It contains no private schedule or backup contents/hash.
Actual TorTLS receipt92e2a5ac…a34a37 and cold selector8b17fe64…ba5894 are
authenticated. The real materialized selection is `CAMPAIGN-SELECTION-03.json`,
SHA256 `d26e172f0c526b96af4e0f0135aacc9133870e8fa603e7c3a402a7fcdd599111`;
its adjacent validation receipt SHA256 is
`3cc61ad86e161c4698e0a1dd21694c445ab8bec3379ff8ca9598f567c9142fcc`.
A template or locally unpacked build cannot pass materialization.

1. After the real download, use `recovery/cold_campaign_selector.py materialize`
   with the real receipt path/pin. It emits the exact cold object. Supply that
   public file/pin to `launch_campaign.py materialize --proposal PUBLIC_PROPOSAL
   --proposal-sha256 PROPOSAL_SHA --cold-selector ACTUAL_COLD_SELECTOR
   --cold-selector-sha256 ACTUAL_COLD_SHA --output
   /var/tmp/kpi-local-private-payment-01/campaign/trial-02/CAMPAIGN-SELECTION-03.json`.
   The producer rechecks all frozen sources and the reviewed caller's actual
   archive/ExitPK/inventory/finite-owner/native gates. It writes the selection
   plus adjacent `CAMPAIGN-SELECTION-03.json.VALIDATED.json`. Read/pin that public
   validation receipt through the guarded reader.
2. Preflight with `launch_campaign.py launch` using the same proposal path/pin,
   `--materialization PUBLIC_VALIDATION_RECEIPT --materialization-sha256 SHA`,
   `--private-directory
   /var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01/campaign-trial-02`,
   `--trial-private-directory
   /var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01/local-pay-testnet-02`,
   `--output /var/tmp/kpi-local-private-payment-01/campaign/trial-02/run`, and
   `--unit local-payment-campaign-02`. No owner preparation, service or financial
   operation starts without `--execute`.
3. Root releases the same command with `--execute`. A separate caller process
   creates the private plan from metadata-checked party interfaces. The launcher
   never opens/hashes that plan or any backup/invoice. It then starts a detached
   user service with explicit `Restart=no`, `UMask=0077`, private append-only
   stdout/stderr destinations and one sequential GPU pipeline.

Use `systemctl --user show local-payment-campaign-02.service` with
`ActiveState`, `SubState`, `ExecMainStatus` for metadata-only monitoring. Public
`action-NNNN/CONFIRMED.json` and final `RESULTS.json` provide permitted progress.
Do not open/hash private plan/state/logs or original backup/invoice files.

A stopped service is never automatically restarted. An operator-authorized
`launch --resume --execute` delegates resumption to the same reviewed caller
without opening its private state. A consumed submission can only be confirmed
read-only. An incomplete pre-submission action remains retained; use a fresh
trial if that state cannot be resumed. Never retransmit a used submission.

Source controls: `python3 -m unittest -v test_campaign.py test_launch_campaign.py`
from this directory. Nine controls pass. The actual campaign and its private
plan have not been started by proposal generation or these controls.
