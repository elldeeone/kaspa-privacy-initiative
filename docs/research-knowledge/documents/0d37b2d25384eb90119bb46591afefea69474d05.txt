# Offline recovery continuation: R05 and R06

**R05 and R06 have executable model coverage.** The later [R07 extension](PAYOUTS.md)
adds paid-claim recovery and terminal reserve drain with its 66-test report. The
[later programme](PROGRAMME.md) has current 80-test evidence. This page
retains the original R05/R06 results and v2 format scope.

After a fresh-process restore, current spentness prevents a second spend using
an old allowed root. For a pending
deposit, credit and refund request compete for the same single-use state; either
can win, and the other then fails without changing economic state.

This remains an offline ideal model. It verifies no ZK proof, authenticates no
Kaspa state and pays no native KAS. Acceptance of historical hidden predicates
and authenticity/freshness of the separately retained model checkpoint remain
assumptions. [ADR-0012](../../docs/adr/0012-offline-restored-transitions.md)
records the extension to [R01–R04](RECOVERY.md). The real-proof/native acceptance
requirements in the [test design](../../docs/shielded-recovery-test-design.md)
remain open.

## Reproduce

Use the existing [dependency setup](RECOVERY.md#run-it), then run from the
repository root. Dependencies must already be available for an offline run.
Each command creates a **new** directory; change `NEW` when repeating.

```bash
export PYTHONPATH=.local/shielded-design/python
python3 -O poc/shielded-design/recovery_fixture.py .local/recovery-base-NEW
python3 -O poc/shielded-design/recovery_trials.py r05-first .local/recovery-base-NEW .local/r05-first-NEW
python3 -O poc/shielded-design/recovery_trials.py r05-second .local/r05-first-NEW .local/r05-second-NEW
python3 -O poc/shielded-design/recovery_trials.py r06-credit-first .local/recovery-base-NEW .local/credit-first-NEW
python3 -O poc/shielded-design/recovery_trials.py r06-credit-second .local/credit-first-NEW .local/credit-second-NEW
python3 -O poc/shielded-design/recovery_trials.py r06-refund-first .local/recovery-base-NEW .local/refund-first-NEW
python3 -O poc/shielded-design/recovery_trials.py r06-refund-second .local/refund-first-NEW .local/refund-second-NEW
python3 -m unittest discover -s poc/shielded-design -p 'test_*.py' -v
```

Each trial loads only the declared archive, checkpoint and synthetic user backups.
It reconstructs public economic state and starts an **empty** ideal proof oracle;
no original Pool or saved proof registry crosses the process boundary. The fixed
R05 workload uses the first nine public records as its old allowed snapshot.
Wallet and executor roles share each harness process; this is not enforced
confidential witness separation or independent-operator recovery.

Directories are mode 0700; copied backups and private `result.json` files are
0600 and refuse overwrite. They contain unencrypted synthetic secrets/derived
wallet data. Stdout contains only case, scope, acceptance outcomes and the
no-chain/no-payout declaration. Do not publish backups or private reports.

## Formats and state transitions

`RecoverySession` uses the same note/nullifier derivation and statement domain
version 1. Archive/checkpoint **v2** only adds a public `refund_request` event
with exact fields `seq`, `kind`, `deposit`, `recipient`, `signature`; matching v2
profiles are required. Existing v1 archives remain readable. This wire-version
change does not create a new economic spend domain or migration path.

The refund signature is canonical lowercase hex for the existing model Ed25519
key. It binds `MODEL-REFUND-REQUEST-v1`, network, pool, statement version, deposit
ID, the recorded exact principal and recipient. Both execution and public replay
verify the recorded refund owner's signature and current pending state.

```text
pending deposit -> credited private liability
               -> refund_pending, equally backed unpaid refund claim
```

The refund request locks 50,000,000 sompi of separately funded model rent. It
leaves principal reserve unchanged. A request is **not payment**; the legacy
immediate `Pool.refund` simulation is not used by this recovery interface.
Invalid credit/refund attempts consume neither pending liability nor rent.

Backup **v2** adds `pending_notes`: unique entries with `deposit` and private
`note` fields (`owner`, `value`, `randomness`). Values and encodings are checked;
retrying credit additionally checks the note against the recorded deposit ID,
amount, commitment and refund owner. This metadata is essential: an unpublished
pending note cannot be recovered from a commitment or spending seed alone. A v1
key-only backup can authorize a refund request but cannot recreate the missing
credit witness. No arbitrary sender/recipient funding pattern is qualified.

Wallet reports keep `unpaid_exit_sompi` and `unpaid_refund_sompi` separate, without
double counting. They recognize this wallet's `model-native:<owner>` recipient;
these labels are not Kaspa addresses. Unknown-sender delivery remains unguaranteed.

## Observed results

[offline-transitions.json](evidence/offline-transitions.json) records current
source hashes, public archive/checkpoint hashes and the six fresh continuation
processes, each run with Python `-O`. Only deliberately synthetic summary values
are published; the prior [42-test report](evidence/offline-recovery.json) remains
historical evidence for its original source hashes.

| Case | Observed outcome |
| --- | --- |
| R05, batch one | Alice's first spend succeeds. |
| R05, fresh batch two | An individually valid competing spend fails on current nullifier state; an unrelated valid spend succeeds. Final spendables: Alice 350,000,000; Bob 1,049,999,000; Carol 100,000,000 sompi. |
| R06, credit wins | Invalid credit fails, valid credit succeeds; after restart refund and duplicate credit fail, then unrelated work succeeds. Carol has 300,000,000 spendable sompi. |
| R06, refund request wins | Invalid credit fails, authorized request succeeds; after restart credit and duplicate refund fail, then unrelated work succeeds. Carol has an unpaid 300,000,000-sompi refund claim. |

In both R06 orders principal reserve remains 2,000,000,000 sompi. Credit-first
leaves private liabilities 1,799,999,000 and unpaid exit claims 200,000,000;
refund-first leaves private liabilities 1,499,999,000 and unpaid exit/refund
claims 500,000,000. Each has a separate 1,000-sompi unpaid fee and no pending
deposit. Rent funding is separately 100,000,000: credit-first locks 50,000,000;
refund-first locks all 100,000,000.

**56 tests passed in that report: 24 original model, 18 R01–R04 and 14 R05/R06 tests.** Controls
include same-batch competition, fresh-process continuation, rejected-credit
restart, changed public intents, wrong refund authority/domain/amount/destination,
missing pending-note data, malformed signatures, duplicate accepted records,
profile mismatch and insufficient rent. A seeded 40-vector check covers both
race orders over 20 u64 principals, including 1 and the u64 maximum. This tests
model liability arithmetic; a native output containing principal plus rent at
that maximum is not qualified. No timeout is treated as a rejection.

## Adversarial second pass and limits

- **Inflation/double spending:** current nullifiers, processed operation IDs,
  pending-deposit consumption and exact allowed historical roots survive replay.
  Competing valid proofs still need that current state. Historical hidden
  predicates remain trusted ideal-model effects, not cryptographically verified.
- **Reserve release:** refund claims preserve backing and cannot be credited
  again. There is no native reserve authority, actual payout or admin path here.
- **Privacy:** backups include private pending-note data; derived reports remain
  private. Synthetic wallet/executor co-location proves no anonymity or service
  privacy. Existing unknown-sender wrong-key delivery limitations remain.
- **Dependency loss/stale state:** complete retained history, user secrets and a
  separately trusted checkpoint are required. A self-generated next checkpoint
  is a harness output, not an independent trust bootstrap or current-chain proof.
- **Reorg/crash:** this v2 slice has no paid-claim events, rollback, durable
  recovery journal or filesystem crash qualification. The later v3/R07 extension
  represents paid state; rollback and crash qualification remain open.
  Missing data must halt; a stale but internally valid horizon is not detected.

The later [R07 model slice](PAYOUTS.md) now covers unpaid exits, paid-claim replay
and terminal drain. The later [R08–R16 programme](PROGRAMME.md) adds bounded
offline controls; all full real-proof/native recovery gates remain open. These results do
not justify a funded trial or production safety claim.
