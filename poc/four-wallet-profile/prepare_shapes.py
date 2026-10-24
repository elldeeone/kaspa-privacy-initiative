#!/usr/bin/env python3
"""Prepare public unsafe compact shape inputs; no setup, PK, proof or wallet.

All nominal secrets are deterministic fixture values. They are not the owner
seeds/keys of any financial trial. Requests stay outside Git and are not hashed
or published. Validity must be checked by the new compiled relation separately.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CAPACITY = ROOT / 'poc/private-exit-stress/capacity.py'
CAPACITY_SHA256 = '3ce1111b4cbe6ce9c24312e5ce46c1f94a414d78f12e7a9de57e44fa805006f0'


def need(value, code):
    if not value:
        raise ValueError(code)


def save(path, value):
    with path.open('x') as file:
        json.dump(value, file, sort_keys=True, separators=(',', ':'))
        file.write('\n')


def main(output):
    output = Path(output)
    need('..' not in output.parts, 'canonical-shape-output')
    output = output.absolute()
    need(not output.is_relative_to(ROOT) and not output.exists()
         and not any(p.is_symlink() for p in (output, *output.parents)), 'fresh-shapes-outside-Git')
    raw = CAPACITY.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == CAPACITY_SHA256, 'selected-public-fixture-source')
    module_spec = importlib.util.spec_from_file_location('four_wallet_public_capacity_fixture', CAPACITY)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    identity = json.loads((HERE / 'profile-identity.json').read_bytes())
    domain = bytes.fromhex(identity['child_domain_hex32'])
    need(len(domain) == 32 and domain != bytes(32), 'selected-public-domain')
    output.mkdir(parents=True, mode=0o700)
    before, append = module.append_fixture(domain, 2)
    cases = [('compact-append', before, append)]
    for unspent, label in ((2, 'noappend-continuing'), (1, 'noappend-terminal')):
        snapshot = module.construct(domain, unspent, cm_max=7)
        previous = {'transactionId': module.sample(domain, 'PUBLIC-SHAPE/' + label).hex(), 'index': 0}
        candidate = module.cashout(domain, snapshot, 7 - unspent,
                                   unspent * module.VALUE, previous)
        cases.append((label, snapshot, candidate))
    summaries = []
    for label, snapshot, candidate in cases:
        save(output / (label + '.json'), candidate.private_witness())
        summaries.append({'label': label, 'role': 'compact2',
                          **module.summary(domain, snapshot, candidate)})
    save(output / 'PUBLIC-SHAPES.json', {'schema': 'kpx6-financial-public-shape-inputs/v1',
        'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND_NOMINAL_FIXTURE_SECRETS',
        'financial_profile_id': identity['financial_profile_id'], 'cases': summaries,
        'nominal_request_secret_witness_hash_or_owner_backup_included': False,
        'setup_proof_native_or_network_execution': False,
        'constraint_satisfaction_or_matrix_identity_claimed': False})
    print(json.dumps({'public_shape_inputs': len(cases), 'setup_proof_native_or_network_execution': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    main(parser.parse_args().output)
