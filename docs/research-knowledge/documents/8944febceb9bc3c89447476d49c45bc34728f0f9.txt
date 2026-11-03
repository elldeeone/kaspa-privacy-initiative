# Actual public recovery acquisition

`recovery_download.py` prepares or performs the root-selected GitHub release
acquisition. Preparation and local fixture tests make no acquisition claim.
Execution requires the root's publication confirmation and a reviewed source
SHA256. It never consumes local software archives, local public PKs, wallets,
backups, attempt logs or an old unpack directory.

The selected assets are fixed in source: `software.tar` (29,849,600 bytes),
separate Exit `parameters.pk` (591,206,448 bytes), and the archive's exact
`INVENTORY.json` (3,594 bytes). All three identities match the public cold
selector contract. The software's 22 payload files plus INVENTORY and separate
ExitPK produce exactly 24 receipt leaves; both acquired artifacts are retained.

The downloader uses curl's established SOCKS5 remote-DNS support with verified
TLS and fresh Tor isolation labels. Redirects are processed individually; only
the exact selected GitHub origins and
`release-assets.githubusercontent.com/github-production-release-asset/...`
are accepted. No `-L`, cookies, netrc, bearer credentials, TLS override, ambient
proxy bypass or direct retry is enabled. Signed redirect queries stay in memory
and curl's stdin; they never enter process arguments, retained headers or logs.
The receipt records only the original query-free public GitHub URLs.

GitHub documents that public release downloads can return either content or an
HTTP redirect, and public assets need no authentication. [Release asset API](https://docs.github.com/en/rest/releases/assets#download-a-release-asset).
Its current runner documentation explicitly identifies
`release-assets.githubusercontent.com` for release downloads. [GitHub network requirements](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

The execution child starts in an empty filesystem with only public OS runtime,
this pinned source and a fresh writable output. No `/home`, host `/var`, old
compound, protected private parent or guard09 private directory is mounted.
The existing loopback Tor proxy remains reachable. Acquisition does not execute
any downloaded software.

After complete artifact size/SHA verification, the uncompressed USTAR parser
requires exactly 23 distinct regular members, canonical relative names, no
links, no PAX/GNU metadata, exact sizes/modes, authenticated inventory/member
correspondence and a zero trailer. Each extracted leaf is independently hashed
before immutable-mode creation. Any failure leaves no actual-download receipt.

After publication confirmation, use a fresh numbered acquisition root:

```text
python3 recovery_download.py --execute --source-sha256 <reviewed-downloader-sha256>
  --output /var/tmp/kpi-local-private-payment-01/recovery-downloads/acquisition-01
```

The resulting `DOWNLOAD-RECEIPT.json` has exactly `schema`, `classification`,
`transport`, `inventory`, `artifacts` and `files`. Its classification is emitted
only after both actual network transfers and all verification complete. Pass its
path/SHA to `recovery/cold_campaign_selector.py materialize`; the selector and
campaign independently verify the inventory and every retained/mounted leaf.
This is same-host Tor download/availability evidence, not independently
administered archival retention or off-host recovery evidence.

Nine synthetic controls passed. A separate actual empty-filesystem sandbox
control confirmed runtime availability, loopback Tor reachability and absence of
all protected paths. Neither control downloaded a release asset or issued an
actual-download receipt.
