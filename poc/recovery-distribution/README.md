# Public recovery distribution

This additive adapter prepares exact public release/CAS/offline bytes and
retrieves them against **externally selected** roots. It does not select or run
downloaded software, read backups, prove, broadcast or establish current state.
The selected development parameters and known public canary are **DO NOT FUND**.

`prepare.py` validates the separately pinned capsule selection and four small
public objects before reading the genuine compact PK. It invokes the unchanged
fixed1GiB chunker, makes independently hashed full CAS/asset copies, and returns
an unpublished finite inventory. `PUBLICATION.json` is an additional delivery
index; it cannot authorize a different complete PK, domain, VK, role or software.
Root reviews exact named assets before any external upload.

`public_fetch.py` accepts exact byte length/SHA and selected HTTPS hosts. System
TLS and hostname verification are mandatory; every redirect must stay HTTPS and
within those hosts, with at most five hops. It uses no auth, cookie or proxy,
never records redirect URLs/queries, streams at most1MiB at a time and atomically
publishes a read-only output only after the complete identity matches. Existing
targets and symbolic-link parents are rejected.

```text
python3 public_fetch.py --url PUBLIC_PUBLICATION_URL \
  --expected-bytes EXTERNALLY_SELECTED_BYTES --expected-sha256 EXTERNAL_SHA \
  --allowed-host github.com --allowed-host release-assets.githubusercontent.com \
  --output NEW_PUBLICATION_FILE

python3 retrieve.py --publication NEW_PUBLICATION_FILE \
  --expected-publication-sha256 EXTERNAL_PUBLICATION_SHA \
  --selection INSTALLED_SELECTION --expected-selection-sha256 EXTERNAL_SELECTION_SHA \
  --source-kind release --source https://github.com/OWNER/REPO/releases/download/TAG \
  --allowed-host github.com --allowed-host release-assets.githubusercontent.com \
  --mode spend_material --output NEW_OUTPUT
```

For an ordinary HTTPS CAS, use `--source-kind cas --source https://HOST/ROOT`;
objects are requested at `ROOT/objects/sha256/DIGEST`. Mirror locations are hints,
not authority. Repeated `--forbidden OWN_BACKUP_PATH` metadata/inode exclusions
are frozen once and applied before caller-public content reads. The trusted
installed caller authenticates software and selection before this adapter; the
mirror must not supply both a selection and its supposed authority.

Recognition downloads only the capsule index and four small objects, never PK
chunks. Spend-material mode preflights those objects first, verifies each chunk,
uses the fixed authenticated chunker to reassemble the complete PK, then stages
the exact five objects through the unchanged capsule API. Missing/corrupt data
means incomplete, never zero balance. The real owner loader still authenticates
its complete owned PK/decode/VK/dimensions before reading a backup or witness.

The prepared root is also a network-free package: its full CAS and external
selection can be mounted alone with selected installed capsule code. Actual
offline restoration with original source/cache/repository paths absent is
retained in the new evidence packet. That same-host namespace result is not a
second operator, offsite copy or retention guarantee.

The current capsule inventory binds the wallet's separate software bundle03.
The parameter generation includes the software **inventory**, not the full
245.7MB source/runtime bundle. That archive has its own externally pinned whole
identity and typed wallet restorer; this module only retrieves its exact bytes
and never extracts or launches it. A complete cold owner restoration requires
that separate software material plus the owner's private backup.

Selected utility copies in `vendor/` are byte-identical capsule `ba6fba07…` and
chunker `c713a487…`; they are hashed before import/launch. No old module globals
are changed. Installed source/runtime and the private read-only staging tree
remain subject to ADR0054's trusted-host/release-owner mutation assumption.

Currentness is separate. The supplied public canary is synthetic, not accepted
backing or a live balance. TLS, hashes, a restored seed or an intact archive
cannot establish a fresh accepted head, reorg/removal state or current UTXOs.
