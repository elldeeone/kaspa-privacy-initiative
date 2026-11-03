# Finite owner-side derived-byte publication check

2026-10-25 UTC. **PUBLIC FIXTURE CONTROLS PASS; ACTUAL ORIGINALS NOT EXECUTED.**
Independent adversarial review and root release are required before any actual
original backup is mounted. This report authorizes no private read or publication.

The old canonical worker `64527cadcd85df584fd3c36b945c2c263978cdd6d055376631027d616c8e6711`
checks literal seed bytes only under the old domain/BCK schema. Its numeric
candidate framing and raw/lowercase-hex/uppercase-hex scan are reused here. The
new checker uses the existing wallet's `support.Assets`, `history.load`,
`history.claims` and unchanged recipient/crypto derivation and decryption.

| Artifact | SHA256 |
| --- | --- |
| `poc/local-private-payment/recovery/publication_derived.py` | `e4c466cdbcb849d2249832f4c42efab97ea7d43039a55095948888710b67a489` |
| `poc/local-private-payment/recovery/test_publication_derived.py` | `d12ee046ca4e90ab960f3aaddfd28a3a4fac31e31a4658007dd197bd8c54cce7` |
| `DERIVED-PUBLIC-CONTROLS-05.json` | `ffb4d8278ca77d96337e56f3aa6966a7ee203ec213e393ddef880d47eb4dfc3b` |
| `DERIVED-PUBLIC-SOURCE-05.json` | `0835598c6f75d59ee6b310ac2270795da699def9e49db06154b23b0ca5f2b8ba` |

The checker requires `/BACKUP.json` to be the sole selected private leaf, mode0600
and one link; `/home`, `/var`, `/root`, `/owner` and `/private` must be absent.
Root's launcher must authenticate and bind each finite source/asset independently
read-only. Inputs use fixed `/public/ASSETS.json`, `/public/HISTORY.json`,
`/public/CONTEXT.json`, `/ALLOWLIST.json` and numeric `/candidates/N.bin`.
Every transitive selected public path stays under `/public`; public files and
numeric candidates cannot alias the selected backup inode.

Before its single private content read, the checker authenticates the exact
candidate manifest and all candidate bytes, selected wallet assets/parameters,
and complete public history against the caller-pinned genesis and checkpoint.
The existing history predicate verifies component proofs, public conservation,
state updates, exact heads and duplicate actions. This is not independent chain
selection or Native Full. The caller must supply genuine accepted history for an
actual recovery claim; the controls use supplied-context public history only.

The exact new backup schema is `{schema,domain_hex32,seed_hex32}`, with schema
`kpxa-original-seed-backup/v1` and financial D
`b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c`.
The backup's content is never hashed by this checker or exported. Its seed must
decrypt at least one authenticated historical receipt, including spent receipts;
a wrong seed cannot claim successful empty ownership.

Finite derived material covers indices0 and `0xffffffff` plus every index
recovered from the owner's authenticated public ciphertexts, plus all owned
historical exit payout-key indices. Payouts are reconciled through existing
`payment.reconcile_payouts`; the behavior-preserving shared `payout_index`
helper selects the same historical keys without duplicating derivation. The
covered material is owner, NF, native,
domain-stable delivery and incoming key bytes; complete Invoice208 and combined
160-byte descriptor; complete recovered Note168/Receipt216; receipt rho32.
Each is scanned as bytes, lowercase hex and uppercase hex, including across
chunk boundaries, in the raw candidate manifest and in decoded candidate path
strings (JSON escaping cannot hide a path hit). No standalone small amount is
treated as a secret canary. Literal root-seed coverage is explicitly separate.
Random proving blinds, unpublished invoice indices, future payout keys not
represented by an owned historical exit, encodings other than these three forms and other material not
recoverable from seed plus selected history are outside this finite coverage.
No general secret-completeness, security or privacy claim follows.

Thirteen known-public controls passed: clean miss; raw/lower/upper key hits;
historical payout-native-secret hit; escaped decoded-manifest-path hit;
Note168 and hex-Receipt216 chunk-boundary hits; wrong-domain backup refusal;
sibling backup-path refusal; backup-as-public-history refusal; backup-inode-as-
candidate refusal; and modified candidate refusal. Seven separate namespace
absence checks passed. Controls use the intentionally public fixture-A seed
already defined in `integration/public_fixture.py`; no protected original was
read or mounted. The checker exports only typed aggregate status/counts and
fixed scope, never note/key bytes, indices, owner paths/hashes or hit locations.

Full public control source/snapshots remain under
`/var/tmp/kpi-local-private-payment-01/results/public/derived-export-known-public-05/`.
Public-only suites01–03 remain retained. Suite04 stopped on an unexpected public
payment-source pin change before namespace controls; the explicit source-refusal
record is retained. Suite05 uses the newly selected payment source pin
`5ff0774fd1bb67ebc5ed5ec246ce2434082bfc4ce82dad9e58047b34232d2bda`
and is the final source/control pair listed above. No run establishes
actual-original coverage. Source inventory records every finite public mount.

The scanner does not decompress or traverse archives. Release checks must select
all decoded archive members and generated selectors/metadata, not only compressed
archive byte streams, before claiming finite software-member coverage.
