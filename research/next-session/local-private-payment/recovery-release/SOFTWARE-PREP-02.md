# Recovery software02: authenticated local unpack

2026-10-25 UTC. **Software02 is prepared and unpacked locally. Owner recovery,
history replay, Exit proof execution and network download remain pending.**

Software01 and its evidence remain unchanged. The explicit producer mapping
changes only these three released source pins; all other selected source/assets,
parameters and path relocations remain the same as software01:

| Source | SHA256 |
| --- | --- |
| `wallet/worker.py` | `4707057d33ca1a5154017c9bdff5f75c14fccf6398f8c5cdf9812461a6239785` |
| `wallet/payment.py` | `5ff0774fd1bb67ebc5ed5ec246ce2434082bfc4ce82dad9e58047b34232d2bda` |
| `recovery/history.py` | `3e637e52ff598ef875b9b50c129e5b8da2057726458af631c788b13cacbab542` |

These sources include the selected owner-local recovery-exit request with
`fee_cap_sompi`, reuse existing private claim/fee selection and recheck the exact
completed effects before genuine Exit authority. Packaging this code does not
establish that the path executed. Adversarial review is a separate root workstream.

[prepare_release.py](../../../../poc/local-private-payment/recovery/prepare_release.py)
now defaults to software02. Producer SHA256:
`2689e4c2ba3f3bebfe8660f5eaf7a2ffa39439952184dd81e355b773ac52fd1c`.

## Exact artifacts

Base: `/var/tmp/kpi-local-private-payment-01/recovery-release/software-02`.

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `software.tar` | 29,849,600 | `d85ad87f7b3094c5ee8747ba8f3c5e774895bd63f958fd1ca5fd845b1095d89a` |
| `INVENTORY.json` | 3,594 | `707cff8442c1617fc526d9d83659dcdba32d966d4dc89d0f1f27aee825822376` |
| `RELEASE-SELECTION.json` | 7,192 | `835d5bf0e72054aecb270671631a90fa5be65fe1a75704a0ee0be2e67ec60877` |
| `UNPACK-RESULT.json` | 3,955 | `27d23c28f2191d2b6a263da65ff12eb7d6fdf3c11c91f7ffbc35913c553338f1` |

The archive still contains **22 payload files plus INVENTORY.json**. Payload
bytes total29,820,894. Its finite membership and OS dependencies are described in
[software01 preparation](SOFTWARE-PREP-01.md); the current exact per-file
hashes/modes are in software02's inventory and unpack result.

All tar/selection/inventory bytes were authenticated through guard09 before
unpacking. Every member was checked as an exact allowlisted regular file with a
canonical relative path, expected bytes/hash, mode0400 or0500 and fixed USTAR
metadata. Files were created individually with exclusive/no-follow opens under
the fresh directory `software-02/unpacked`; no general tar extraction was used.
Every unpacked file was then re-read through guard09 against its exact inventory
pin and its mode checked. **23/23 files agree.**

The relocated selectors still refer only to `/public` paths. Wallet selector
SHA256 remains`df7ec243515d19e18a3ff3d9196d0c83b969a3a56255e47773d97de20b6f1e50`;
fee selector SHA256 remains
`433c6ca7b53addb3943ac29ba0356a70005ace9800964fd07c3afc3121a501d8`.
These pins and the per-file inventory support later finite read-only namespace
mounts; they are not authorization to read an original backup.

No PK bytes were reread or included. The three separate PK identities remain the
exact pinned metadata recorded in software01 and software02 release selection;
direct Exit needs only the fresh Exit PK. No wallet or accepted history is in
the archive. The public template remains a quote-only fixture shape. No original
leaf, owner namespace, actual chain replay, Exit proof, Git staging, commit,
upload or network download was performed in this packaging step.
