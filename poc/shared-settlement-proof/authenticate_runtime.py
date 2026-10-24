#!/usr/bin/env python3
"""Reauthenticate retained official public prover assets; never execute a proof."""
from pathlib import Path
import datetime
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PREP = Path('/home/luke/projects/kpi-intensive-2026-10-22/observer/artifacts/groth16-compression-preparation')
WORKER = Path('/home/luke/projects/kpi-intensive-2026-10-22/proof-target/tools/r0vm-cuda')
MEMBERS = {
    'stark_verify_final.zkey': (3620786504, 'f525bfbcadcd01339a243db59213f213a357adbaaff7b4203c9c57ce25e91d5c'),
    'fuzzed_msm_results.bin': (576, '5c31207007ab5489bddf60594434c161739baca4cde6786f493ffa44aaebcc43'),
    'preprocessed_coeffs.bin': (1442123704, '424368948ad64d7cdd6632fc9efa9b1a52f45ea8b5bf1d568682a7eaa91efbb0'),
    'stark_verify_graph.bin': (251721088, '51020d6fd9ded9627ed08044fb428bca46ee2bfcc90f5819469601564050315f'),
}

def check(path, size, digest):
    assert path.is_file() and not path.is_symlink(), path
    assert path.stat().st_size == size, path
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    assert actual == digest, path
    return {'path': str(path), 'bytes': size, 'sha256': actual}

def main():
    out = Path(sys.argv[1]); assert not out.exists()
    rows = []
    for name, digest in {
        'official-distribution_manifest.json': '92398d7623b5fbd3732d8b5fcaf614e8e407a27d79bb61af495e4f8b2e927235',
        'official-manifest-signable.json': '478ba3f07a5d721d6c610e390ccd05afbe014c86f3097e51688f0d41ea25d1f2',
        'official-rzup-v3.0.3-public_key.pem': 'ef3cafeb1e540719b0187b5879359128d289ac2bcfa64f010f7998422960f491',
    }.items():
        p = PREP / name; rows.append(check(p, p.stat().st_size, digest))
    command = ['openssl', 'dgst', '-sha256', '-verify', str(PREP/'official-rzup-v3.0.3-public_key.pem'),
               '-signature', str(PREP/'official-manifest-signature.bin'), '-sigopt', 'rsa_padding_mode:pss',
               '-sigopt', 'rsa_pss_saltlen:32', str(PREP/'official-manifest-signable.json')]
    verified = subprocess.run(command, check=True, capture_output=True, text=True)
    manifest = json.loads((PREP/'official-distribution_manifest.json').read_bytes())
    signable = json.loads((PREP/'official-manifest-signable.json').read_bytes())
    del manifest['signature']; assert manifest == signable
    archive_sha = '4b4f2b2fb8380369ed14f0dc48380a1bbcbc82c7d553f1888b47d0a9f8e72e4d'
    assert signable['releases']['0.1.0']['target_agnostic']['artifact']['sha256_blobs'] == [archive_sha]
    rows.append(check(PREP/'risc0-groth16-v0.1.0.tar.xz', 2335797480, archive_sha))
    # The retained extraction report links these exact regular-member hashes to
    # the authenticated archive; no extraction or executable install is done.
    extraction = json.loads((ROOT/'poc/two-v6-binding/evidence/groth16-receipt/official-extraction-metadata.json').read_bytes())
    assert extraction['archive_sha256'] == archive_sha
    recorded = {Path(r['path']).name: (r['bytes'], r['sha256']) for r in extraction['members']}
    assert recorded == MEMBERS
    for name, (size, digest) in MEMBERS.items():
        rows.append(check(PREP/'risc0-home/extensions/v0.1.0-risc0-groth16'/name, size, digest))
    rows.append(check(WORKER, 165756672, '3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7'))
    report = {'schema': 'kpx5-public-R0-runtime-authentication/v1',
              'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'signature_verification': verified.stdout.strip(), 'signature_command': command,
              'official_signed_archive_and_retained_member_chain': True,
              'whole_bytes_reauthenticated': rows, 'proof_or_guest_execution': False,
              'extraction_or_installation': False}
    out.write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
    print(json.dumps({'authenticated_files': len(rows), 'proof_or_guest_execution': False}))

if __name__ == '__main__':
    main()
