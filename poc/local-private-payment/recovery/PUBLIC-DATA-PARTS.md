# Byte-preserving public data parts

This separate transport producer preserves the logical `data.tar` bytes. It
does not change the packet format, verify a ledger, read an original seed,
publish an asset or execute downloaded software.

Use the existing four-asset transport when the actual completed archive is
strictly smaller than 2,147,483,648 bytes. GitHub requires each release asset
to be under 2GiB; total release size is unlimited.
[GitHub release documentation](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)

For a larger measured archive, `split_public_data_archive.py` authenticates its
whole external SHA/size through unchanged guard09 before creating any output.
It writes ordered `data.tar.part-00000` files, normally 256MiB each, and a
path-free `DATA-PARTS.json`. Every nonfinal part has the selected part size;
the final part is nonempty and no larger. Each part is strictly under 2GiB.
Concatenating the ordered parts must reproduce the original whole-archive
length and SHA256. Splitting introduces no codec or new archive bytes.

```text
python3 split_public_data_archive.py --archive ABS/data.tar \
  --archive-sha256 HEX64 --archive-bytes INTEGER \
  --output /dev/shm/kpi-local-private-payment-publication-01/FRESH_PARTS
```

Only fresh children of the two existing exact public output parents are
accepted. Symlinks, reused destinations and known local-only source prefixes
are refused. The established disk parent retains the old producer's trusted
host boundary; the exact tmpfs parent must be operator-owned mode0700.

The part manifest has exactly:

```text
schema: kpxa-public-recovery-data-parts/v1
domain_hex32: the unchanged local-payment domain
part_bytes: positive integer below 2GiB
archive: {name: data.tar, bytes: INTEGER, sha256: HEX64}
parts: ordered [{name: data.tar.part-NNNNN, bytes: INTEGER, sha256: HEX64}]
```

It contains no local source paths or network origins. After audit and release,
Root supplies the canonical HTTPS origins in a separately pinned multipart
download selection. That consumer authenticates each ordered part, appends it
to one assembled archive and checks the whole archive identity before invoking
the unchanged strict packet verifier. Its receipt must distinguish an assembled
archive from a directly downloaded asset, and must not invent retained paths
for deleted temporary parts.

The producer currently holds one guard-admitted whole-archive bytes object;
memory is bounded by the measured archive, not by the part size. Retaining all
part files adds exactly one archive's payload bytes plus filesystem overhead.
Check current disk/tmpfs/RAM headroom before actual production; the splitter
does not establish that an unknown future archive will fit.

The full logical raw archive remains an audit candidate so matches crossing a
transport boundary cannot disappear. Part metadata and names also require
explicit audit coverage. Decoded gzip pages remain separate whole-file audit
batches; multipart transport never substitutes for their decoded coverage.

The public controls use deliberately known synthetic bytes. They are evidence
about byte transport and input refusal, not financial acceptance, general
privacy, cryptographic correctness, physical off-host recovery, independent
administration or durable external retention. No actual final archive is
selected by these controls.
