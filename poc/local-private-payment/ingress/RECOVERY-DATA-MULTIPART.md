# Multipart public recovery-data transport

This separate resource transport preserves the original canonical `data.tar`
bytes. `recovery_data_download.py` SHA256
`aa4c01b423a656e2005d18e316521383daad5efd4cfdb8d82804d6a0348cfac7`
and its four-asset contract remain unchanged. Use that original mode when Root
selects a logical archive below GitHub's per-asset limit. Multipart mode has its
own selection, output namespace and receipt; neither mode is a financial verifier.

GitHub's official documentation, checked2026-10-26, requires each release asset
to be under2GiB, allows up to1000 assets per release, and gives no total release
size limit. [GitHub release storage quotas](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas).
Asset availability, rate limits and remaining release slots remain publication
concerns. No account, service, upload or actual download is created by this source.

The publisher selects deterministic256MiB chunks named
`data.tar.part-00000`, `data.tar.part-00001`, and so on. Ordered concatenation
must equal the exact existing canonical archive, including its whole size and
SHA256. `PACKET.json`, `DATA-INVENTORY.json` and the original three lines of
`SHA256SUMS` remain unchanged: they identify the logical whole `data.tar`.
Remote sums remain `DATA-SHA256SUMS` to preserve the software release asset.
No recompression, JSON reserialization or new financial interpretation occurs.

Root's externally pinned public selection has exactly six top-level fields:

```text
schema = kpxa-root-multipart-public-recovery-data-download-selection/v1
domain_hex32 = b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c
part_bytes = 268435456
archive = {name: data.tar, bytes: WHOLE_INTEGER, sha256: WHOLE_HEX64}
parts = ordered [{name: data.tar.part-00000, origin_url: EXACT_PUBLIC_HTTPS,
                  bytes: PART_INTEGER, sha256: PART_HEX64}, ...]
artifacts = [{name: DATA-INVENTORY.json|PACKET.json|SHA256SUMS,
              origin_url: EXACT_PUBLIC_HTTPS, bytes: INTEGER, sha256: HEX64}]
```

The `artifacts` list selects exactly the three metadata objects. Every origin
must name the exact selected asset in one GitHub release of
`elldeeone/kaspa-privacy-initiative`; private/authenticated URLs, queries,
fragments, alternate repositories and local artifact inputs fail. Parts must be
consecutive, begin at00000 and have exactly the count implied by the archive
length. Every nonfinal part has `part_bytes` bytes; the final part is nonempty
and at most that size. All network asset lengths and the selected chunk size
must be strictly below2GiB. `part_bytes` is externally selected rather than a
hidden operational constant; smaller known-public fixtures exercise the same
partition contract. The production publisher's selected size is256MiB.

A producer part manifest is an audit input to Root, not a downloaded authority.
Root supplies and pins the final finite URL/size/hash selection after whole
data and source audit. Untrusted downloaded metadata cannot add parts or origins.
There is deliberately no fabricated `data.tar` network URL in the multipart
selection: only parts and the three metadata assets are downloaded.

After final audit, publication and explicit network release:

```text
python3 recovery_data_multipart.py --execute --source-sha256 REVIEWED_MULTIPART_SHA
  --release-selection ROOT_PUBLIC_MULTIPART_SELECTION_JSON
  --release-selection-sha256 ROOT_SELECTION_SHA
  --output /var/tmp/kpi-local-private-payment-01/recovery-data-multipart-downloads/acquisition-NN
```

The alternative exact output parent is
`/dev/shm/kpi-local-private-payment-recovery-data-01`, again with only a fresh
`acquisition-NN` child. Both approved parents must be real directories owned by
the invoking effective UID with exact mode0700; every output ancestor must be
free of symlinks. A missing approved parent can be created at0700; existing
mode/owner mismatches are refused rather than changed. Used output identities,
dangling symlinks and alternate paths fail. Source/selection staging and receipt
paths use the actual selected host parent, including tmpfs when selected.

Before transfers, the launcher and child check the selected filesystem's actual
available capacity against the logical byte estimate
`2*A + min(part_bytes,A) + three_metadata_bytes + 1MiB`. The uncompressed USTAR
byte length bounds logical extracted payload bytes. This estimate is not a
universal physical-space upper bound: filesystem block rounding, directories,
many tiny files and receipt size can require more. Root must check the actual
selected data shape and keep generous measured filesystem and host/tmpfs memory
headroom, while avoiding concurrent consumption of that capacity. This recovery
publication preflight does not change or abort the frozen financial campaign.
A later filesystem failure still stops
without a receipt. No real acquisition preflight or transfer is claimed by the
public synthetic controls.

The outer launcher guard-authenticates its own source, the unchanged base source
at the full SHA above, and Root's selection. The sandbox starts with an empty
filesystem and only public OS runtime, those two pinned source files, the public
selection and a fresh writable output. No `/home`, host `/var`, original packet,
private parent, software archive, key, producer selector target or uploaded code
is mounted. Only the explicitly staged reviewed source is executed.

The sibling directly reuses the base's established curl transport: SOCKS5 remote
DNS over loopback Tor19050, verified TLS, clean environment, fresh Tor SOCKS
isolation, manually checked exact GitHub/CDN HTTPS redirects, and signed queries
and headers confined to RAM/stdin. No direct fallback, replay/retry, ambient
proxy bypass, auth, cookies, netrc, insecure TLS or signed-query logging is added.
Network/part failure stops without a receipt; a new attempt needs a fresh output.

After the three externally pinned metadata transfers, their inventory and packet
identities are checked. Each ordered part then downloads into a single fresh
temporary file. The base transport authenticates its full size/SHA before it is
read and appended in1MiB chunks to one archive. The temporary part is deleted
after append, before the next transfer. A whole concatenated size/SHA mismatch
fails before any tar parsing. On success there is one retained logical archive,
three retained metadata downloads, and no retained N-part duplicate set. Peak
extra part storage is one externally selected chunk. A failed attempt can leave
its one temporary part and partial archive as incomplete evidence, never a receipt.

The pinned base then reauthenticates the assembled file and performs its entire
existing verification contract: exact external inventory/PACKET/sums, all12
distinct role identities, sorted raw canonical regular-USTAR headers and leaves,
both fetch page arrays, exact compressed page membership and all concatenated
gzip members' decoded length/SHA. Gzip zero padding is accepted as before;
non-gzip trailing data, corruption and truncation fail. Decoded chunks are
discarded after hashing. Raw extracted members, compressed pages and the whole
archive are retained, so storage still includes archive plus extracted payloads.
This extension avoids a second retained part set and decoded copies; it does not
eliminate the existing archive/extraction storage cost.

Only successful transfers and complete verification produce
`MULTIPART-DATA-DOWNLOAD-RECEIPT.json`, with exactly nine top-level fields:

- `schema`: `kpxa-downloaded-multipart-public-recovery-data-receipt/v1`.
- `classification`:
  `ACTUAL_TOR_TLS_MULTIPART_PUBLIC_DATA_DOWNLOAD_INVENTORY_AND_DECODED_PAGES_VERIFIED`.
- `transport`: `TOR_SOCKS5H_TLS`.
- `archive`: `{path,bytes,sha256,part_bytes,parts:[ordered_part_names]}` for the
  retained reconstructed archive. It is never labelled directly downloaded.
- `inventory`, `packet`: retained `{path,bytes,sha256}` metadata identities.
- `artifacts`: the three metadata rows
  `{name,path,origin_url,bytes,sha256,retained:true}`, then the ordered actual
  part acquisitions `{name,origin_url,bytes,sha256,retained:false}`. Part rows have
  no retained path. Only original query-free public origins are recorded.
- `files`: exact extracted `{member,path,bytes,sha256}` map including inventory.
- `pages`: `{packet_path,compressed:{path,bytes,sha256},
  decoded:{bytes,sha256,retained:false}}`, with no decoded-file path.

This distinct receipt cannot stand in for either the original software24-leaf
receipt or the four-asset data receipt. It documents bounded same-host Tor byte
acquisition, assembly and page decoding. It makes no financial/native acceptance,
chain-currentness, portable replay, off-host execution, independent administration,
durable retention or global traffic privacy claim. Producer decoded-object audit
and the original financial/native replay remain separate obligations.

Public controls run with:

```text
python3 -B -m unittest -v test_recovery_data_multipart.py
```

The fixture helper is the unchanged data test source SHA256
`d6381d3309fc9fc98236a2f9f589b603761dcefd31cbdef1bc5327d2e451036e`.
Controls use only deliberately public byte fixtures and mocked transfers;
temporary receipt-shaped outputs make no actual network acquisition claim.
Independent review must name the exact sibling, dependency and test pins.
