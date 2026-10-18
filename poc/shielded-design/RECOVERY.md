# Offline model recovery prototype

**R01–R04 have executable model-level coverage.** The subsequent
[R05/R06 extension](TRANSITIONS.md) adds restored spends and pending credit/refund
races and v2 formats. [R07](PAYOUTS.md) adds paid-claim recovery and terminal
reserve drain with its 66-test evidence and v3 effects. The later
[R08–R16 programme](PROGRAMME.md) has current 80-test evidence. This page retains
the original R01–R04 format and historical results.

A fresh process restores the worked three-user checkpoint using only accepted-model-effect records, a
separately supplied trusted checkpoint and that user's backup. It loads no Pool
object, original wallet database or producer proof registry.

This prototype does not verify ZK proofs, Kaspa acceptance or current-chain state.
The checkpoint's authenticity and the ideal model's acceptance are trusted test
inputs. Replacing both archive and checkpoint defeats this assumption. This is
not the N-user independent native-payout gate, a production wallet backup tool
or a selected private-note construction. [ADR-0011](../../docs/adr/0011-offline-model-recovery.md)
records this bounded decision; [the source review](../../research/recovery-source-review-2026-10-18.md)
records reused requirements and excluded assumptions.

## Run it

From the repository root, using the existing model dependency setup:

```bash
python3 -m pip install --target .local/shielded-design/python -r poc/shielded-design/requirements.txt
PYTHONPATH=.local/shielded-design/python python3 poc/shielded-design/recovery_fixture.py .local/recovery-NEW
PYTHONPATH=.local/shielded-design/python python3 poc/shielded-design/recovery.py \
  --archive .local/recovery-NEW/archive.json \
  --checkpoint .local/recovery-NEW/checkpoint.json \
  --backup .local/recovery-NEW/bob-backup.json \
  --output .local/recovery-NEW/bob-restored.json
PYTHONPATH=.local/shielded-design/python python3 -m unittest discover -s poc/shielded-design -p 'test_*.py' -v
```

Use a **new** fixture directory and output filename. Creation and restoration
finish in seconds for these tiny fixtures; setup/download time depends on the
environment. To restore another user, select `alice-backup.json` or
`carol-backup.json` and a new output. For the fresh-directory test, copy only
archive, the selected backup and the separately retained checkpoint to the
recovery inputs. The automated CLI test and recorded three-process demonstration
exercise this separation. Same-machine processes/directories are not independent
operators or OS-enforced filesystem isolation.

The generator emits synthetic model records only, including one rejected no-op.
Its checkpoint is made by the fixture producer. In an adversarial archive test,
retain that checkpoint separately **before** editing archive data. Never
recompute it from the untrusted replacement and call the result authenticated.
The convenient command above places both files together for a local demo;
that layout is not an independent trust bootstrap.

Stdout contains a public scope/status/checkpoint verdict with
`chain_or_zk_verified: false`. The `--output` file contains **private derived
wallet information**, including note contents and witnesses/positions. It and
backups are created mode 0600, refuse overwrite/symlinks, and must not be
published. Fixture directories are mode 0700. A rejected/incomplete run exits 2
without creating a wallet report; stdout never substitutes a complete zero
balance. Existing output files remain untouched. Writes are not crash-qualified
or claimed fsync-durable; that remains R09.

## Version 1 formats

All files are JSON objects with an exact schema and
`scope: OFFLINE_MODEL_ONLY_NO_CHAIN_OR_ZK`. Unknown/missing fields, duplicate JSON
keys, floating-point/nonfinite JSON numbers and malformed required fields are
rejected or reported incomplete. Amounts and counts use JSON integers, with
strict u64 amount/sum semantics; booleans are not integers. Hash/key encodings
are lowercase 64-character hex. Canonical digest encoding is UTF-8 JSON with
sorted keys, compact separators and no nonfinite values, hashed using SHA-256.
Whitespace/object key order in the transport does not change that digest.

| File / schema | Exact fields and meaning |
| --- | --- |
| Backup / `kpi-model-backup/v1` | `schema`, `scope`, `descriptor_hash`, `owner`, `incoming`, `spending_seed`, `incoming_secret`, `expected_receipts`. The two private seeds restore existing PyNaCl model keys; derived public identities must match. `expected_receipts` is a list of unique commitment hashes privately known to the user. It may be empty/stale; it is not a wallet balance cache or proof of unknown-sender delivery. Backups are **unencrypted** and support only synthetic model keys. |
| Archive / `kpi-model-records/v1` | `schema`, `scope`, `descriptor`, `records`. Descriptor is exactly `DESCRIPTOR` in [recovery_format.py](recovery_format.py): existing model network/pool/version, explicit non-chain genesis and lane, and model note-format identity. Records are ordered from `seq=0`, without gaps or duplicates. No supplied snapshot, validity flag, alternate descriptor, embedded checkpoint or operator database is accepted. |
| Trusted checkpoint / `kpi-model-checkpoint/v1` | `schema`, `scope`, `descriptor_hash`, `record_count`, `archive_hash`. Binds the complete canonical archive, including ciphertexts, order and domain, at this model horizon. No signature/chain/proof or freshness guarantee is implied. A new trusted horizon must be obtained outside the untrusted archive; the backup need not change to scan later records. |

Public event variants have exact fields:

| `kind` | Fields after `seq`, `kind` | Interpretation |
| --- | --- | --- |
| `deposit` | `event`: `id`, `amount`, `commitment`, `refund_owner` | A trusted model-native deposit observation creates equal pending liability and reserve. IDs are synthetic hashes, not real outpoints. |
| `operation` | `public`: the existing model's exact credit/spend statement | Reconstruct an accepted model effect. Credit requires one matching pending deposit. Spend requires an allowed model anchor, fresh nullifiers, explicit exit/fee terms and funded permission rent. Full hidden membership/authorization/conservation is assumed from ideal model acceptance, not verified here. |
| `rent_funding` | `amount` | External model rent funding, separate from native principal. |
| `rejection` | `operation_hash` | An ordered rejected-model-operation no-op. The checkpoint, not a host validity bit, binds this retained effect. It does not prove cryptographic invalidity. |

Credit statement fields: `kind`, `network`, `pool`, `version`, `deposit`,
`outputs`. Spend statement fields: `kind`, `network`, `pool`, `version`, `anchor`,
`nullifiers`, `outputs`, `withdrawal`, `fee`, `fee_recipient`. `withdrawal` has
`recipient`, `amount`; each output has `commitment`, `ciphertext`. Reuse existing
model commitment/nullifier/delivery semantics, not a new production encoding.
Model native recipients are labelled `model-native:<owner>` and are not Kaspa
addresses. Refunds/payouts, snapshots, migrations and reorg events are
unsupported in this first slice, rather than silently treated as completed.

## Restore meaning and delivery limit

`reconstruct_public` validates archive coverage/integrity against the separate
checkpoint, replays public effects, and reconciles reserve/pending/private-total/
exit/fee/rent ledgers. It reconstructs no other user's hidden notes or balances.
Its small public transition checks do not certify a malicious checkpoint's
hidden-value predicates or create a settlement authority.

`restore_wallet` restores keys, opens authenticated output records, checks exact
decrypted model encoding/owner/commitment, derives this user's nullifiers and
filters current spentness. The private result reports spendable notes separately
from pending deposits and unpaid exit principal. Positions and the model's
list-hash anchor permit a new ideal-model spend; they are not a Merkle proof.

| Status | Meaning |
| --- | --- |
| `complete_at_model_checkpoint` | All archive bytes match the supplied trusted model horizon, and known expected receipts were recovered. The horizon need not be current. |
| `incomplete_data` | Required file, fields, range or delivery bytes are absent; no wallet balance returned. |
| `rejected_unverifiable_input` | Wrong domain/version, altered archive, invalid record/numeric format or decryptable bad recipient data; no wallet balance returned. |
| `incomplete_wallet_data` | A user-known expected commitment cannot be recovered, including wrong-key delivery or a never-accepted expected receipt; no complete wallet balance returned. |
| `io_error` | Input/output access failure or output already exists; never overwrite private output. |

Successful decryption followed by bad encoding/owner/commitment binding is an
error. An authentication failure under the incoming key is indistinguishable
from a ciphertext for another recipient. Expected receipt metadata detects this
for **known** payments. Without such metadata, unknown-sender wrong-key delivery
remains undetectable; every successful report explicitly states
`unknown_sender_delivery_guaranteed: false`. Neither the archive digest nor a
complete scan establishes I-14 against a malicious sender. A final constrained
delivery or recipient acceptance protocol remains open in RFC-0002.

## Observed result and test coverage

[offline-recovery.json](evidence/offline-recovery.json) retains source hashes and
the synthetic three-user demonstration: one producer process and three fresh
restore processes, with private output permissions checked. No backup or raw
private wallet report is published there.

The exact public [records](evidence/offline-recovery-records.json) and
[checkpoint](evidence/offline-recovery-checkpoint.json) from that run are retained
with byte lengths and SHA-256 hashes in the result. After generating a new fixture
directory above, its deterministic synthetic backup keys/receipt commitments also
restore these retained records: select the retained paths for `--archive` and
`--checkpoint` and the new fixture's user backup. Ciphertext randomness may make
newly generated archive bytes differ; key/note identity and expected accounting
remain the same. The checked-in checkpoint is a reference model trust input,
not independently authenticated chain state.

| User | Spendable sompi | Pending deposit sompi | Unpaid exit principal sompi |
| --- | ---: | ---: | ---: |
| Alice | 600_000_000 | 0 | 0 |
| Bob | 899_999_000 | 0 | 200_000_000 |
| Carol | 0 | 300_000_000 | 0 |

Reserve is `2_000_000_000` sompi; private liabilities `1_499_999_000`, pending
deposits `300_000_000`, exits `200_000_000` and unpaid fee `1_000` reconcile
exactly. Permission rent `50_000_000` is funded/locked separately.

**42 tests passed: 24 existing model tests and 18 new recovery tests.** R01
checks fresh subprocess restoration, exact independent ledger expectations and a
new ideal-model spend without a producer oracle. R02 checks missing ranges and
delivery. R03 checks retained-horizon/domain binding, replacement, ordering,
duplicates, controlled malformed-input errors, strict JSON, u64 maximum and
overflow. R04 checks unaccepted/duplicate/spent records, originally bad
decryptable delivery and the known/unknown wrong-key distinction. Additional
controls cover backup key identity, private file modes/no-overwrite, sanitized
CLI failure and fixture execution under Python `-O`.

Two implementation regressions were observed failing before fixes: a malformed
deposit-reference list caused an uncontrolled TypeError; producer calls inside
assertions disappeared under `-O`. A deeply nested decrypted JSON input also
raised RecursionError before normalization. The regression controls now pass.
No test timeout is counted as rejection. CI's existing model discovery includes
the new tests and existing Python syntax checks include the new modules.

## Adversarial second pass and remaining work

- **Inflation/double spend:** reject malformed amounts, duplicate economic
  records/nullifiers and incorrect public liability accounting. Hidden predicate
  soundness and original accepted effects remain trusted-model assumptions.
- **Reserve release:** no native transaction or withdrawal authority exists in
  this module. Pending liabilities are reported, never labelled paid.
- **Privacy:** protect backups and derived reports; public stdout is a verdict
  only. Public evidence contains deliberately synthetic per-user values. No
  network access, remote proving, query-privacy or anonymity claim.
- **Missing dependencies/stale state:** absence fails explicitly against the
  supplied horizon. The checkpoint has no independent freshness/chain guarantee;
  losing both ciphertexts and every independent copy remains unrecoverable.
- **Reorgs/crashes:** no rollback, durable checkpoint writer, archive networking
  or general native payout reconciliation in this initial slice. Later
  [R08–R16 controls](PROGRAMME.md) add bounded offline fork/crash handling;
  full proof/native recovery remains open.
- **Trust:** full-archive hashing protects integrity/completeness only relative
  to the separately trusted checkpoint. A malicious checkpoint/model producer
  can assert invalid effects. Real L1/proof authentication must replace that
  assumption before any actual-protocol recovery claim.

The [R05/R06 extension](TRANSITIONS.md) now covers restored current spentness
and pending-credit/refund-request races. [R07](PAYOUTS.md) adds paid-claim
replay and terminal drain. Model conformance remains separate from native authorization;
these results do not warrant an operator network or a funded trial.
