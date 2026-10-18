#!/usr/bin/env python3
"""Generate depth-32 interoperability fixtures with Zcash's Python reference.

These are public primitive/path fixtures, not accepted pool states or proofs.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

REFERENCE = '78321beacb0e0477e33cd002b56585a107c2708c'


def main():
    reference, corpus, output = map(Path, sys.argv[1:])
    pin = subprocess.check_output(['git', '-C', str(reference), 'rev-parse', 'HEAD'], text=True).strip()
    if pin != REFERENCE: raise RuntimeError('wrong reference source pin')
    if subprocess.check_output(['git', '-C', str(reference), 'status', '--porcelain']):
        raise RuntimeError('modified reference checkout')
    data = json.loads(corpus.read_text())
    comparisons = {}; additional_encryption = []
    for section, name in [('keys', 'orchard_key_components'), ('note_encryption', 'orchard_note_encryption'),
                          ('commitment_tree', 'orchard_empty_roots'), ('merkle_path', 'orchard_merkle_tree')]:
        relative = f'test-vectors/json/{name}.json'
        raw = (reference / relative).read_bytes(); published = json.loads(raw)
        fields = published[1][0].replace('\n', '').split(', ')
        rows = [dict(zip(fields, row, strict=True)) for row in published[2:]]
        if len(rows) != len(data[section]): raise RuntimeError('reference vector count mismatch')
        if section == 'note_encryption':
            # The official Python JSON and current Rust embedded encryption
            # corpora use different rho/nf_old values (and derived ciphertexts).
            # Retain both complete corpora and check both against the Rust APIs;
            # do not claim their different expected bytes are identical.
            additional_encryption = [dict(row, nf_old=row['rho']) for row in rows]
            comparisons[relative] = {'sha256': hashlib.sha256(raw).hexdigest(),
                'comparison': 'separate independently published encryption corpus; verify every vector',
                'vectors': len(rows)}
            continue
        compared = 0
        for local, expected in zip(data[section], rows, strict=True):
            for key, value in local.items():
                external = key
                if external not in expected: continue  # New V3-only fields are outside the V2 candidate.
                if expected[external] != value: raise RuntimeError(f'published corpus differs: {section}/{key}')
                compared += 1
        comparisons[relative] = {'sha256': hashlib.sha256(raw).hexdigest(), 'comparedFields': compared}
    sys.path.insert(0, str(reference))
    from zcash_test_vectors.orchard.merkle_tree import empty_roots, merkle_crh
    from zcash_test_vectors.utils import leos2bsp
    siblings = [bytes(root).hex() for root in empty_roots()]
    if siblings != data['commitment_tree'][0]['empty_roots']:
        raise RuntimeError('independent empty-root outputs differ')
    leaf = data['keys'][0]['note_cmx']
    vectors = []
    for position in (0, 1, (1 << 32) - 1):
        node = bytes.fromhex(leaf)
        for height, sibling in enumerate(siblings[:32]):
            left, right = node, bytes.fromhex(sibling)
            if (position >> height) & 1: left, right = right, left
            node = bytes(merkle_crh(31-height, leos2bsp(left)[:255], leos2bsp(right)[:255]))
        vectors.append({'position': position, 'leaf': leaf, 'siblings': siblings[:32], 'root': node.hex()})
    result = {'scope': 'PUBLIC_INDEPENDENT_REFERENCE_DEPTH32_PATH_FIXTURES_NOT_ACCEPTED_POOL_STATE',
              'referenceCommit': REFERENCE, 'upstreamPublishedCorpusComparison': comparisons,
              'additionalNoteEncryptionVectors': additional_encryption,
              'vectors': vectors}
    with output.open('x') as f: json.dump(result, f, indent=2); f.write('\n')
    print(json.dumps({'independentDepth32Vectors': len(vectors), 'publishedSourcesCompared': len(comparisons)}))


if __name__ == '__main__': main()
