# Cold campaign selector handoff

The frozen caller interface is [CAMPAIGN.md](../../../../poc/local-private-payment/integration/CAMPAIGN.md).
It binds 24 owner-stage leaves (22 software payloads, inventory, ExitPK), exactly
7 Native Full leaves, and 4 native public selectors to a pinned acquisition
receipt. Source agreement does not establish actual acquisition or recovery.

Use `poc/local-private-payment/recovery/cold_campaign_selector.py`, source SHA256
`77147ec94848d01d462102bec0c34df54ebd38d78b59af9fd16f657ce0c64bdf`.
It makes no network requests and never creates a download receipt.

```sh
python3 cold_campaign_selector.py template \
  --download-root /ABS/FUTURE-DOWNLOAD/unpacked \
  --receipt /ABS/FUTURE-DOWNLOAD/DOWNLOAD-RECEIPT.json \
  --receipt-sha256 ROOT_SELECTED_RECEIPT_SHA256 \
  --exit-pk /ABS/FUTURE-DOWNLOAD/parameters-exit.pk \
  --output /ABS/COLD-SELECTOR-TEMPLATE.json
```

Template mode emits a wrapper classified
`TEMPLATE_ONLY_NOT_DOWNLOADED_OR_CAMPAIGN_RELEASED`. Its `cold` member has the
future caller layout. The retained template01 uses a zero placeholder receipt
pin and a nonexistent acquisition path; no actual receipt was created.

After root releases real acquisition and its producer has retained the exact
receipt, software archive, ExitPK and authenticated unpacked files:

```sh
python3 cold_campaign_selector.py materialize \
  --receipt /ABS/ACTUAL-DOWNLOAD/DOWNLOAD-RECEIPT.json \
  --receipt-sha256 ROOT_SELECTED_ACTUAL_RECEIPT_SHA256 \
  --output /ABS/COLD-CAMPAIGN-SELECTOR.json
```

Materialize emits the exact caller `cold` object. It requires receipt schema
`kpxa-downloaded-recovery-receipt/v1`, classification
`ACTUAL_TOR_TLS_DOWNLOAD_AND_INVENTORY_VERIFIED`, transport `TOR_SOCKS5H_TLS`,
the exact software02 inventory/tar identities, and exact fresh ExitPK identity.
It authenticates all mounted leaves and both retained artifacts through guard09.
HTTPS origin rows and their honest Tor acquisition remain the root-selected
producer's provenance boundary; bytes and flags alone do not prove transport.

No software02 source/package change is required. Actual upload, download,
original-seed recovery and native exit execution remain separately released
steps. Same-host execution is not physical off-host recovery.
