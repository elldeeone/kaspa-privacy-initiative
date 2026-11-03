# Prepared full public recovery objects

2026-10-24 UTC. **Byte preparation and opaque restoration passed. Independent
retention, accepted history and a funded recovery using these objects remain
unverified.** Nothing was uploaded or published to a service.

The outside-Git handoff is `/var/tmp/kpi-four-wallet-public-recovery-objects-02/objects`.
It contains the complete selected public compact PK, its VK/manifest, financial
profile, software archive and inventories. The PK is a public proving parameter,
not an owner's funding secret. No original backup, private witness, owner map,
controller plan, raw command line or accepted/LOCAL history is included.

| Object | Bytes | SHA256 |
| --- | ---: | --- |
| `compact2.pk` | 1,307,894,256 | `793cf0bf9456cc4187719b8e23dcf35402410c5c9006ac4c06de303d2a5a3ee0` |
| `four-wallet-recovery-software.tar.zst` | 54,038,796 | `de236c116febd7927f53eaffa9fa27b7be332c10f7c30daa0975e7cf5629aaad` |
| `compact2.vk` | 328 | `2b385052a622057c1863c3f71930fd040e82e1885cbaac914abf3348e7734406` |
| `compact2-parameters.json` | 2,738 | `923900f528483e20e1de4134ae4ef786f76cf3ce947e37058bb1e34d7c8a7e8c` |
| `financial-profile.json` | 82,179 | `41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a` |

The complete [object index](metadata/RECOVERY-OBJECTS.json) has SHA256
`c6a706e05653aa1da1196fbc05668d46e4138f3fadd1e816e10b439e12009ece`.
Its seven assets total 1,362,043,926 bytes. The object index itself is 1,846
bytes and must also be retained. Large objects stay outside Git.

## What was checked

All eight original backup identities and complete owner directories were
excluded by metadata before public source/parameter/software reads. Whole
stable opened-file SHA256 and size checks authenticated the PK during copying,
then independently authenticated the copy. No backup was opened or hashed.

The software archive preserves the immutable 68-file selected runtime and adds
three exact existing public sources: the host owner launcher, its installation
helper and the strict unpack helper. The [typed inventory](metadata/SOFTWARE-BUNDLE.json)
contains 71 files, SHA256
`2837d0d8d02533f9d38c4afe8a9898c37ecc3df88a068d31568311b5c07881af`.
The archive adds three metadata sidecars, for 74 regular members. Canonical
USTAR metadata and zstd compression follow the existing current-W packaging
design. Existing pinned `software_bundle.py` and `unpack_bundle.py` verified
and restored every selected member into a fresh directory.

The trusted packaging/verification/unpack helpers executed; restored wallet
source, SDK, ELF tools and prover did **not** execute. The result therefore
establishes selected-byte availability on this host, not successful cold wallet
execution, current chain backing or cryptographic correctness.

Build02 used 5.187 CPU seconds, peaked at 2,655,690,752 bytes of host memory and
used zero swap under a four-core/four-GiB allocation. Both owned build services
were stopped and had MainPID zero. Build01's operational failure is retained:
the existing strict unpacker required the sidecar name
`DEPENDENCY-ACQUISITION.json`; source02 corrects only that filename. No helper,
financial source, parameter or check was weakened.

## Handoff and remaining obligations

An operator must retain all seven assets and the index, plus the separately
selected actual LIVE descriptor and complete accepted Full-history data when
available. That later history slot is explicitly absent; LOCAL supplied
contexts are not substituted. Currentness must still be acquired/reconciled
before any spend. A missing or pruned history is INCOMPLETE, never an empty
wallet.

Expected index/object hashes and financial authority must be selected outside
the downloaded bundle. A provider serving its own manifest does not create
that authority. The package uses selected Linux x86_64 prebuilt binaries and
still trusts compatible OS/system libraries, Python, bwrap, zstd and TLS trust.
The development setup and software remain unqualified for production security.
Outer proving/compression assets, GPU, Rust builds and package registries are
unnecessary for the selected private exit path; its public PK remains required
and cannot be recreated merely from an owner backup.

Separately administered destination/access and stated retention are still
missing. The later qualification must retrieve the actual full selected
objects while the issuer is unavailable, then exercise the complete accepted
original-backup recovery and confirmed payout path. A local archive/restoration,
different hostname or same-administrator mirror does not establish that result.
