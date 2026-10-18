#!/usr/bin/env python3
"""Prepare a public primitive measurement case, never a wallet/trial identity."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

WRAPPER = 'ee60c3fb5ff9fc6c125ad41019e74188d68814f1b1a2fc6bc101ddab184202a7'
PIN = '616a669df8c9a59c33d47064d3ce04b25d026b2e'
TAG = b'KPI/P1/OrchardV2/primitive-check/v1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('elf', 'pinned_wrapper', 'output'):
        p.add_argument(name, type=Path)
    a = p.parse_args()
    if a.output.exists(): p.error('output exists; choose a fresh directory')
    if sha(a.pinned_wrapper.read_bytes()) != WRAPPER:
        p.error('original pinned CPU wrapper identity mismatch')
    corpus_raw = (Path(__file__).parent/'vectors/upstream-orchard.json').read_bytes()
    corpus = json.loads(corpus_raw)
    if corpus['orchardCommit'] != PIN: p.error('wrong Orchard corpus pin')
    v = corpus['keys'][0]
    raw_input = (bytes.fromhex(v['sk']) + v['note_v'].to_bytes(8, 'little')
                 + bytes.fromhex(v['note_rho'] + v['note_rseed'] + v['default_d']))
    journal = TAG + bytes.fromhex(v['note_cmx'] + v['note_nf'])
    if len(raw_input) != 115: p.error('wrong fixture length')
    a.output.mkdir()
    image = subprocess.check_output([str(a.pinned_wrapper.resolve()), 'wrap',
        str(a.elf.resolve()), str((a.output/'program.bin').resolve())], text=True).strip()
    if not re.fullmatch('[0-9a-f]{64}', image): raise RuntimeError('invalid image output')
    for name, raw in [('input.bin', raw_input), ('expected-journal.bin', journal)]:
        with (a.output/name).open('xb') as f: f.write(raw)
    case = {'program_sha256': sha((a.output/'program.bin').read_bytes()),
        'input_sha256': sha(raw_input), 'expected_journal_sha256': sha(journal),
        'expected_program_image': image}
    provenance = {'scope':'PUBLIC_UPSTREAM_TEST_KEY_PRIMITIVE_CASE_NEVER_FUND',
        'orchardCommit': PIN, 'corpusSha256': sha(corpus_raw),
        'wrapperSha256': WRAPPER, 'rawElfSha256': sha(a.elf.read_bytes()),
        'expectedOutputOrigin':'published upstream vector, not execution/receipt data',
        'nativeTransactions':0}
    for name, value in [('case.json',case), ('provenance.json',provenance)]:
        with (a.output/name).open('x') as f: json.dump(value,f,indent=2); f.write('\n')
    print(json.dumps(case))


if __name__ == '__main__': main()
