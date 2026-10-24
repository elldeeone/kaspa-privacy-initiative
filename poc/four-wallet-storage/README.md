# Public recovery replica exercise

This harness restores exact caller-selected public bytes while an issuer is
excluded. It reuses the pinned existing HTTPS transport and keeps fetched code,
parameters and history opaque. It does not select a financial profile, load a
PK, read a backup, reconcile an accepted head or authorize spending.

The selection schema is `four-wallet-public-recovery-selection/v1`:

- `profile_reference_sha256`: a public reference, not financial authorization.
- `providers`: explicit IDs, redirect host allowlists and **reported**
  infrastructure/administration/deletion/retention labels.
- `assets`: exact IDs/kinds/integer byte lengths/SHA256 values and per-provider
  initial public HTTPS URLs. Initial URLs have no credentials, query or fragment;
  the existing transport may follow verified allowlisted CDN redirects without
  exporting their signed queries.

Pass the complete selection's independently chosen SHA256. Required object
coverage is the caller's responsibility; success says every selected object
was restored, not that an arbitrary list is sufficient to recover funds.

```sh
python3 -B poc/four-wallet-storage/restore.py \
  --selection /outside/reviewed-public-selection.json \
  --selection-sha256 EXTERNALLY_SELECTED_SHA256 \
  --exclude-provider issuer \
  --deny-host issuer.example \
  --output /outside/fresh-public-restore
```

Use a fresh namespace with private/original repository, producer, cache and PK
paths absent for an actual failure-domain trial. The trusted bootstrap and OS
remain dependencies. A different hostname, future date or policy hash never
creates an independent-operator or retention guarantee. Expired/unknown/malformed
retention and policy-digest claims do not block authentic available bytes.

```sh
python3 -B poc/four-wallet-storage/test_storage.py
```

The small controls use explicit fake public objects and memory/local files.
They demonstrate no actual TLS, independent provider, retained real parameters,
owner recovery or confirmed payout. The protocol/evidence plan lives in
`research/next-session/four-wallet-testnet/storage/DESIGN.md`.
