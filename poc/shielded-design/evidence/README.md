# Local model and real composition evidence

- [model-cycle.json](model-cycle.json): simulated Alice/Bob principal lifecycle
  and separate permission-rent funding; not a chain payout or cryptographic test.
- [offline-recovery.json](offline-recovery.json): synthetic three-user fresh-process
  restore results and source hashes for R01–R04, under a separately trusted model
  checkpoint. No private backups/reports, ZK verification or native recovery.
  Its exact public [records](offline-recovery-records.json) and reference
  [checkpoint](offline-recovery-checkpoint.json) are retained for replay; the
  result records their byte lengths and SHA-256 hashes. No private seeds included.
- [offline-transitions.json](offline-transitions.json): historical R05/R06 results,
  source hashes and six fresh continuation processes using Python `-O`. Both
  credit/refund orders preserve backing; no refund is paid. It hashes the retained
  public final records/checkpoint pairs for R05, credit-first and refund-first.
  No backups or private reports are published. The earlier 42-test report above
  remains historical evidence; the extension records 56 passing tests.
- [offline-payouts.json](offline-payouts.json): R07 paid-claim/terminal-drain
  results and current source hashes; 66 tests and 14 fresh continuation/audit
  processes. It hashes public fee-last, user-last and fee-free terminal histories
  and checkpoints. Payments are synthetic effects; native payouts remain zero.
  The earlier 42-test and 56-test artifacts remain unchanged.
- [offline-programme.json](offline-programme.json): current R08–R16 bounded
  offline results, 80 passing tests and a separate three-user process rehearsal.
  It hashes the public terminal [records](offline-programme-records.json) and
  [checkpoint](offline-programme-checkpoint.json). Private test logs/backups/
  wallet reports are excluded. Every full proof/native gate remains false.
- [source-review.json](source-review.json): dated upstream refs, selected file
  hashes, bounded retrieval failures and code-rights boundary. Restricted source
  files are not redistributed.
- [compatibility.json](compatibility.json): four-proof local chain, isolated
  repeated wallet measurement, actual abort errors, matched execution cycles,
  exact source/program/prover hashes and explicit blockers.
- [local-compatibility-artifacts.tar.gz](local-compatibility-artifacts.tar.gz):
  real receipts, journals, profiles, rejection errors, public prepared reference
  input, reference/compatibility programs, exact source snapshots and logs.

The first four-proof host source snapshot is frozen separately from the later
host that adds an isolated wallet/profile measurement command. Both content-hash
maps are retained; no earlier run is attributed to the later source bytes.
Synthetic preimages and deterministic wallet keys are public test fixtures.
No real signing key, secret environment or restricted third-party circuit source
is included. Native script checks use a local accessor; there was no new native
submission, private payment, independent operator or anonymity measurement.

Integrity check from repository root, without executing any archive member:

```python
from pathlib import Path
import hashlib, json, tarfile
root = Path('poc/shielded-design/evidence')
result = json.loads((root / 'compatibility.json').read_text())
archive = root / result['artifactArchive']['path']
assert archive.stat().st_size == result['artifactArchive']['bytes']
assert hashlib.sha256(archive.read_bytes()).hexdigest() == result['artifactArchive']['sha256']
with tarfile.open(archive) as t:
    manifest = json.load(t.extractfile('manifest.json'))
    assert set(t.getnames()) == set(manifest) | {'manifest.json'}
    for name, expected in manifest.items():
        raw = t.extractfile(name).read()
        assert len(raw) == expected['bytes']
        assert hashlib.sha256(raw).hexdigest() == expected['sha256']
print('Integrity checked; this is not a cryptographic audit.')
```
