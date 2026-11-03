# Finite recovery software preparation

2026-10-25 UTC. **Local archive prepared; publication and cold recovery are pending.**

[prepare_release.py](../../../../poc/local-private-payment/recovery/prepare_release.py)
builds a finite public-only archive from explicit source mappings. Producer source
SHA256: `567066181cb45ff3761b5f37d19158cf5084159c00891e06aee05ca3b490bceb`.
Every source/asset read used guard09. No original wallet, backup, private request,
plan, event, view seal, truth, log or PK bytes were read or hashed. No Git staging,
commit, upload, network access or publication occurred.

## Prepared artifacts

Directory: `/var/tmp/kpi-local-private-payment-01/recovery-release/software-01`.

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| `software.tar` | 29,839,360 | `d6c6b94420d67c019202791f932025d2240138064ad32a43d53ffc44f8a32164` |
| `INVENTORY.json` | 3,594 | `c307b5e468b31be1dab9b4c7f6dec04f94f95943b9742a33847f3934379096b0` |
| `RELEASE-SELECTION.json` | 7,192 | `6e94f5c18093e32ace1b43407d09fd34286b3fb378cf12b149aaf95b7897d8b9` |

The USTAR archive has **22 payload files plus INVENTORY.json**, with sorted names,
uid/gid/mtime zero, empty owner/group names and modes0400 or0500. The exact
per-file byte counts, SHA256 values and modes are in the inventory. The external
selection records each finite public source path and pin, original selector pins,
relocated selector pins and separate PK release metadata. There is no recursive
collection and no selection from unrelated untracked files.

The payload is exactly:

- `wallet/{worker,payment,support}.py`, `recovery/history.py`,
  `integration/{trees,native_fees}.py`, `verification/{wire,native_case}.py`,
  pinned `recipient.py`, and `verification/native/validate_selected_case.py`.
- Four ELFs: `bin/{relation,crypto,native-codec,native-engine}`.
- `parameters/{spend,output,exit}/manifest.json`,
  `verification/{component-profile,outer-selection}.json`.
- `templates/payment-shape.bin`, `WALLET-ASSETS.json`, `NATIVE-FEE-POLICY.json`.

Source files match the selected stage03 pins. Only selector path fields changed:
all runtime paths now live under `/public`. Immutable manifest bytes, D, VKs,
ELF identities, native tail, image, budgets and fee rate remain unchanged.
Relocated wallet selector SHA256 is
`df7ec243515d19e18a3ff3d9196d0c83b969a3a56255e47773d97de20b6f1e50`;
relocated fee selector SHA256 is
`433c6ca7b53addb3943ac29ba0356a70005ace9800964fd07c3afc3121a501d8`.

## Separate public proving-key assets

These values were checked against pinned new-domain `SELECTED.json`
SHA256`713554f69e328d9462f62fd4a30207f7ff1f6f5ef2db40449f7daf172e79f4e8`
and unchanged role manifests. **They are metadata checks, not new PK byte/hash
verification.** No PK is in the software tar.

| Separate asset | Bytes | SHA256 |
| --- | ---: | --- |
| `parameters-spend.pk` | 601,785,008 | `45ae6cd5110b09466c19de8c1f0cf89ec93f6c0d853f232773801e19bd0d62bd` |
| `parameters-output.pk` | 85,578,096 | `887573cf53559e969007857cd50284db9948204390389fc6e85dd75644b1241d` |
| `parameters-exit.pk` | 591,206,448 | `fc531fcdb192dba2123bb13a02f78aa019cd5299e6905ad7ab4a5c6afdf481b1` |

Scan needs the three manifests/VKs. Direct Exit additionally needs only Exit PK,
mounted as `/public/parameters/exit/parameters.pk`. Spend/Output PKs are separate
assets for later repeated payments. All three fit individually below2GB.

## Checks and remaining work

The prepared tar was read through guard09 and checked without extraction: all23
members are regular files, exact names/modes match the inventory, every payload
hash/length matches, and deterministic metadata is fixed. This checks archive
integrity; it does not execute recovery or validate financial state.

The runtime layout must retain the relative source directories. The owner worker
and Native Full validator avoid the host guard; do not use the unchanged host
chain replay/launcher inside the portable cold namespace. Native Full needs only
the public validator, engine, codec, component/outer selections and generated
exact CASE/projection/journal; direct Exit mounts no outer prover.

Linux x86_64, Python3 with its standard library, loader
`/lib64/ld-linux-x86-64.so.2`, libc, libgcc, libm and libstdc++ are explicit OS
runtime dependencies. ELF program headers were inspected; binaries were not
executed. No physical off-host or cross-distribution compatibility is established.

The template is a **quote-only public fixture shape**, never accepted history.
No wallet or history is packaged. Genuine accepted-history download, selected
original-seed cold restore, scan/replay, fresh Exit proof, Native Full and confirmed
payout remain pending. Root separately reviews/releases any restricted checker
and actual original-leaf namespace. A new quote/recovery helper, if selected,
requires a new finite archive; it is not silently included here.
