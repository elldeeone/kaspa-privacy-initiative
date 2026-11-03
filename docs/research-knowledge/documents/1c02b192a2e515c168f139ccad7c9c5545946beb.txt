# Public recovery-data acquisition

`recovery_data_download.py` is a separate data-only acquisition and container
verifier. It leaves the pinned software/ExitPK downloader and its 24-leaf receipt
unchanged. Public fixture controls do not demonstrate actual network acquisition.
Actual final-data transfer requires Root's final audit, exact public asset pins
and publication release. No actual data transfer has been performed by preparing
this source.

The producer contract is `prepare_data_packet.py` SHA256
`239bb48bfc25a65390940d7fcdc9c128437e82ed12702aeb73d7d38ba9c72de0`,
with `DATA-PACKET-INTERFACE.md` SHA256
`6253af8e56d8288194d04b6de4839ccf81f6f35389113bc0460b89050a326eb2`.
The consumer authenticates byte identities and declared container metadata. It
does not replace the original financial/native verifier or its runtime adapter.

Root supplies a pinned public JSON selection with exactly `schema`,
`domain_hex32` and `artifacts`:

```json
{
  "schema": "kpxa-root-public-recovery-data-download-selection/v1",
  "domain_hex32": "b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c",
  "artifacts": [
    {"name": "data.tar", "origin_url": "https://github.com/elldeeone/kaspa-privacy-initiative/releases/download/ROOT_SELECTED_TAG/data.tar", "bytes": 1, "sha256": "ROOT_SELECTED_64_LOWERCASE_HEX"},
    {"name": "DATA-INVENTORY.json", "origin_url": "https://github.com/elldeeone/kaspa-privacy-initiative/releases/download/ROOT_SELECTED_TAG/DATA-INVENTORY.json", "bytes": 1, "sha256": "ROOT_SELECTED_64_LOWERCASE_HEX"},
    {"name": "PACKET.json", "origin_url": "https://github.com/elldeeone/kaspa-privacy-initiative/releases/download/ROOT_SELECTED_TAG/PACKET.json", "bytes": 1, "sha256": "ROOT_SELECTED_64_LOWERCASE_HEX"},
    {"name": "SHA256SUMS", "origin_url": "https://github.com/elldeeone/kaspa-privacy-initiative/releases/download/ROOT_SELECTED_TAG/DATA-SHA256SUMS", "bytes": 1, "sha256": "ROOT_SELECTED_64_LOWERCASE_HEX"}
  ]
}
```

This is a shape example, not executable pins. The four rows must be exactly the
listed local names, positive integer byte lengths and lowercase SHA256 pins, at
one selected release in this repository. The sums asset is remotely named
`DATA-SHA256SUMS` to preserve the existing software `SHA256SUMS`; its retained
local name and the builder's three sums lines remain unchanged. Downloaded
metadata cannot supply new origins or replace external pins.

After audit and publication release, the command is:

```text
python3 recovery_data_download.py --execute --source-sha256 REVIEWED_SOURCE_SHA256
  --release-selection ROOT_PUBLIC_SELECTION_JSON
  --release-selection-sha256 ROOT_PUBLIC_SELECTION_SHA256
  --output /var/tmp/kpi-local-private-payment-01/recovery-data-downloads/acquisition-NN
```

The launcher guard-authenticates source and selection, stages those exact bytes,
and creates a fresh acquisition namespace. Its child starts in an empty
filesystem with public OS runtime, only those two reviewed inputs and the fresh
output. No `/home`, host `/var`, original packet, software archive, proving key,
private parent or producer selector target is mounted. The existing loopback Tor
SOCKS port19050 is the sole configured outbound transport.

Each transfer uses curl's established SOCKS5 remote DNS and verified TLS, clean
environment and fresh Tor SOCKS isolation. Redirects are checked individually:
exact selected GitHub origins or HTTPS
`release-assets.githubusercontent.com/github-production-release-asset/...`.
Signed CDN queries and response headers stay in memory; URLs/isolation secrets
enter curl stdin rather than arguments or logs. No redirect auto-follow, ambient
proxy bypass, direct retry, auth, cookie, netrc or TLS override is enabled. Failure
emits no acquisition receipt. These are the existing reviewed software transport
controls adapted to the data-specific four-origin selection.

All four network artifacts are retained and externally size/hash authenticated.
The sums object must contain exactly the archive, inventory and packet lines in
producer order. The standalone inventory and packet are authenticated before
extraction. Inventory schemas, domain, uint64 counts/lengths, kinds, exact role
identities and declared evidence boundaries must agree. Finite timing floats are
allowed in opaque JSON; consumed count/length fields reject booleans and floats.
Monetary claims inside preserved documents remain for the original verifier.

The archive walker compares each raw512-byte header to the producer's canonical
USTAR header for the exact sorted inventory member. It requires mode0400,
uid/gid/mtime0 and empty names; no links, extension headers, duplicate, unsafe,
ancestor, reserved, extra or missing members pass. Every leaf's full hash and
length, zero member padding and the exact canonical zero trailer are checked.
Pinned empty regular payloads are supported. The archive's inventory bytes must
equal the independently acquired inventory identity.

The `fetch` role is fixed at `chain/fetch.json`. Every record from both main
`pages` and `current_view.post_query_delta.pages` must map unchanged to
`chain/<record.path>`, match all and only `full-source-page` inventory rows and
agree exactly with `PACKET.pages`. Every compressed page is authenticated again,
then all concatenated gzip members are decoded unchanged and checked against the
whole decoded length/SHA. Gzip zero padding is accepted as in the producer;
non-gzip trailing bytes and truncated/corrupt members fail. Decoded chunks are
discarded after hashing; no decoded page copies or fake decoded-file paths are
retained. The producer's separate prepublication audit of decoded objects remains
a distinct requirement. JSON is never parsed and reserialized as page output.
Preserved host selectors are provenance bytes and are never followed.

`DATA-DOWNLOAD-RECEIPT.json` is created only after all four transfers and all
verification finish. It has exactly eight top-level fields:

- `schema`: `kpxa-downloaded-public-recovery-data-receipt/v1`.
- `classification`:
  `ACTUAL_TOR_TLS_PUBLIC_DATA_DOWNLOAD_INVENTORY_AND_DECODED_PAGES_VERIFIED`.
- `transport`: `TOR_SOCKS5H_TLS`.
- `inventory`, `packet`: retained standalone `{path,bytes,sha256}` identities.
- `artifacts`: exact four `{name,path,origin_url,bytes,sha256}` rows; original
  public query-free URLs only.
- `files`: exact extracted member map `{member,path,bytes,sha256}`, including the
  archive's `DATA-INVENTORY.json`.
- `pages`: `{packet_path,compressed:{path,bytes,sha256},decoded:{bytes,sha256,retained:false}}`
  rows, joining every retained compressed member to its stream-verified decoded
  identity. There is no decoded path or claim of retaining a decoded artifact.

The receipt is deliberately incompatible with the software campaign's six-field
receipt. It supports bounded same-host Tor byte acquisition and page decoding,
without claiming financial acceptance, native execution, consensus/currentness,
portable replay, off-host execution, independent administration or durable
retention. Tor routing also does not prove privacy against global traffic
observation.

Run the synthetic controls with:

```text
python3 -B -m unittest -v test_recovery_data_download.py
```

They use deliberately public byte fixtures, mocked transport and temporary
outputs. Any receipt-shaped fixture output exists only in a temporary directory
and is not actual-acquisition evidence. Independent review and its control report
must name the exact source/test pins used.
