# New-domain publication checks

2026-10-25 UTC. Public source inspection and intentionally public fixture
controls only. No protected original backup, private plan, witness, key file,
event record, view seal, truth or log was read or hashed by this workstream.

The canonical worker
`poc/owner-private-lifecycle/wallet/export_seed_worker.py`, SHA256
`64527cadcd85df584fd3c36b945c2c263978cdd6d055376631027d616c8e6711`,
performs a **literal seed-byte/hex search only**. It does no derivation or
decryption. It strictly accepts the old D and four-field
`kpx8-owner-seed-backup/v1`, including a participant ID. It rejects the new
three-field `kpxa-original-seed-backup/v1`. The old data adapter3537c424… and
launcher7a3db6ac… also pin the old domain/profile/cohort. Their existing evidence
does not establish fresh-D literal or derived-secret coverage.

The new `recovery/publication_literal.py` is a narrow derivative: new D, exact
three-field backup/schema and new result schema. Numeric manifest validation,
complete public candidate authentication before the single private read, raw/
lowercase-hex/uppercase-hex scanning and aggregate-only output remain unchanged.
The existing numeric manifest schema is retained for exact shared candidate rows.
Known-public controls and independent review cover these changes; they do not
authorize a protected-original execution by themselves.

The separate `recovery/publication_derived.py` reuses the selected wallet,
authenticated public history and unchanged recipient/crypto derivation. It checks
delivery/view and owner/NF/native/incoming keys, complete invoice/descriptor,
Note168, Receipt216 and rho forms for initial/funding indices and indices found
by decrypting public authenticated ciphertext history. It scans full raw bytes
and lowercase/uppercase hex; an amount alone is never a secret needle. This is
finite recoverable-material coverage. Unpublished indices, random proving
blinds and other material absent from seed plus selected history are excluded.
Literal seed coverage is reported separately.

Before any protected-original check, root must select the exact public artifact
manifest and reviewed source closure. The launcher must bind each selected
public file read-only and one exact original backup leaf read-only, without a
private parent, sibling, repository, home or general `/var/tmp` mount. Only typed
aggregate results may leave that namespace. The independent adversarial review
must give GO for the full checker/launcher/manifest composition. Actual original
paths, contents, private hashes, matched locations, notes, keys and indices must
not enter public reports or the software archive.

The three fresh proving keys are public setup assets pinned by SELECTED713554f6…:

| Role | Bytes | SHA256 |
| --- | ---: | --- |
| Spend | 601785008 | `45ae6cd5110b09466c19de8c1f0cf89ec93f6c0d853f232773801e19bd0d62bd` |
| Output | 85578096 | `887573cf53559e969007857cd50284db9948204390389fc6e85dd75644b1241d` |
| Exit | 591206448 | `fc531fcdb192dba2123bb13a02f78aa019cd5299e6905ad7ab4a5c6afdf481b1` |

Their setup predates creation of the fresh protected originals according to the
root workstream. A reviewer may accept explicit source/chronology noninterference
for those exact assets instead of a redundant secret scan. That decision is
separate evidence and does not cover later changed assets or establish general
absence of secrets. No such reviewer decision is asserted here.

No Git staging, commit, push, upload or final publication has occurred.
