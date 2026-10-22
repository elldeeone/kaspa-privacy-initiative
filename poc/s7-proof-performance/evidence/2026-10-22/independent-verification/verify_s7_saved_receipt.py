#!/usr/bin/env python3
"""Run only a root-selected existing fresh Succinct verifier; never prove/build."""
import argparse
import hashlib
import json
import os
import resource
import struct
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

IMAGE = 'e21ab79e3aebdaba0355680d6a17bf0142bf0b3b5bbb687a6f2726499282a0d3'
JOIN = '7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e'
J_SHA = '699697f07565d28faad6e45b9e6daa0a09dbcea3f475d51880a75289f7e49b57'
CLAIM = '88f54f54030b2fc884c777a872262679fa15bffca8e613a0f6d40f7d90e92aaa'
P_SHA = '70d89b257a6ec611db4775b4c8b0c0db2372cf8f75d084325be89d7d455c6cca'
CASES = [('pool', 42), ('outpoint-txid', 74), ('outpoint-index', 106),
         ('prior-state', 110), ('next-state', 215), ('reserve', 320),
         ('successor-amount', 328), ('successor-amount-high-byte', 335)]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(path):
    raw = path.read_bytes()
    return {'sha256': sha(raw), 'bytes': len(raw)}


def claim(journal):
    h = lambda raw: hashlib.sha256(raw).digest()
    post = h(h(b'risc0.SystemState')+bytes(32)+struct.pack('<IH', 0, 1))
    output = h(h(b'risc0.Output')+h(journal)+bytes(32)+struct.pack('<H', 2))
    return h(h(b'risc0.ReceiptClaim')+bytes(32)+bytes.fromhex(IMAGE)+post+output+struct.pack('<IIH', 0, 0, 4)).hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('expected_binary_sha')
    parser.add_argument('receipt', type=Path)
    parser.add_argument('expected_receipt_sha')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    assert args.binary.is_absolute() and args.receipt.is_absolute()
    before = {str(p): identity(p) for p in [args.binary, args.receipt]}
    assert before[str(args.binary)]['sha256'] == args.expected_binary_sha
    assert before[str(args.receipt)]['sha256'] == args.expected_receipt_sha
    expected_path = Path(__file__).with_name('s7-actual-context-claim-independent.json')
    expected_raw = expected_path.read_bytes()
    expected = json.loads(expected_raw)
    journal = bytes.fromhex(expected['J336_hex'])
    assert len(journal) == 336 and sha(journal) == J_SHA and claim(journal) == CLAIM
    raw = args.receipt.read_bytes()
    # Pinned bincode Receipt: inner, Journal(Vec), ReceiptMetadata(Digest32).
    # Target the outer Journal only, preserving the proved inner claim.
    start = len(raw)-32-len(journal)
    assert start >= 8 and raw[start:start+336] == journal
    assert raw[start-8:start] == struct.pack('<Q', 336)
    args.output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env.pop('RISC0_DEV_MODE', None)
    for name in ['RAYON_NUM_THREADS', 'OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS']:
        env[name] = '1'
    affinity = min(os.sched_getaffinity(0))
    deadline = time.monotonic()+600

    def limits():
        os.sched_setaffinity(0, {affinity})
        resource.setrlimit(resource.RLIMIT_AS, (2*1024**3, 2*1024**3))
        resource.setrlimit(resource.RLIMIT_CPU, (600, 600))

    def run(receipt, output, log):
        command = [str(args.binary), 'verify', 'initial-pair', str(receipt), str(output)]
        remaining = deadline-time.monotonic()
        assert remaining > 0, '600-second overall verification deadline exceeded'
        result = subprocess.run(command, env=env, preexec_fn=limits, capture_output=True, timeout=remaining)
        with log.open('xb') as stream:
            stream.write(result.stdout+result.stderr)
        return result

    positive_dir = args.output/'positive'
    result = run(args.receipt, positive_dir, args.output/'positive.log')
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    verified = json.loads((positive_dir/'verified.json').read_bytes())
    assert verified['image'] == IMAGE and verified['context'] == 'initial-pair'
    assert verified['expected_control'] == JOIN and verified['receipt_sha256'] == args.expected_receipt_sha
    assert verified['development_mode'] is False and verified['no_unresolved_assumptions'] is True
    assert (positive_dir/'journal.bin').read_bytes() == journal
    assert sha((positive_dir/'public.bin').read_bytes()) == P_SHA
    cases = []
    for label, offset in CASES:
        mutated_journal = bytearray(journal)
        mutated_journal[offset] ^= 1
        changed = bytearray(raw)
        changed[start+offset] ^= 1
        target = args.output/(label+'.bin')
        target.write_bytes(changed)
        output = args.output/(label+'-unexpected-output')
        result = run(target, output, args.output/(label+'.log'))
        expected_changed_claim = claim(mutated_journal)
        exact_error = f'Error: claim digest does not match the expected digest {CLAIM}; expected {expected_changed_claim}\n'
        assert result.returncode == 1 and result.stderr.decode() == exact_error and not output.exists()
        cases.append({'case': label, 'journal_offset': offset, 'input_sha256': sha(changed),
            'exit_code': result.returncode, 'sdk_error': 'ClaimDigestMismatch', 'proved_claim': CLAIM,
            'independent_changed_claim': expected_changed_claim, 'exact_sdk_error_match': True})
    after = {str(p): identity(p) for p in [args.binary, args.receipt]}
    assert before == after and expected_path.read_bytes() == expected_raw
    report = {'verified_utc': datetime.now(timezone.utc).isoformat(), 'identities': before,
        'identities_unchanged': True, 'image': IMAGE, 'journal_sha256': J_SHA, 'claim_digest': CLAIM,
        'official_control': JOIN, 'cpu_affinity': [affinity], 'address_space_limit': 2*1024**3,
        'thread_env_limit': 1, 'cpu_seconds_limit': 600, 'development_mode': False,
        'serialized_outer_journal_start': start, 'target': 'outer Journal only; proved inner claim unchanged',
        'exact_field_negatives': cases, 'no_build_proof_native_or_owner_workflow': True}
    with (args.output/'independent-report.json').open('x') as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps({'independent_verification': 'PASS', 'exact_context_negatives': len(cases), 'claim': CLAIM}))


if __name__ == '__main__':
    main()
