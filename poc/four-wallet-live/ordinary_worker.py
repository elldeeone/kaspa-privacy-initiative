#!/usr/bin/env python3
"""Closed ordinary funding quote/signer. Never run against a host backup."""
import argparse
import copy
import os
from pathlib import Path
import stat
import sys

from ordinary_common import (PROFILE_SHA, PLACEHOLDER, digest, encoded, need,
    observation, parse, sdk_body, selection, uint, validate_case, draft)

ROOT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(ROOT / 'poc/four-wallet-bootstrap'))
from gn2_backup import decode_backup
from gn2_common import public_bytes, regular, write_new
from gn2_owner import _private_backup
from gn2_runtime import Runtime, SDK_PINS


def native_full(runtime, case, output):
    output.mkdir(mode=0o700)
    path = output / 'case.json'
    write_new(path, encoded(case) + b'\n')
    runtime.executables['native-validator'].run(['validate-transaction', path, output / 'native'])
    report = parse((output / 'native/native-validation.json').read_bytes())
    metrics = parse((output / 'native/metrics.json').read_bytes())
    engines = report['per_input_ScriptEngine']
    need(report['isolation'] == 'PASS' and report['Full']['accepted'] is True
         and report['all_input_engines_accepted'] is True and type(engines) is list
         and len(engines) == len(case['entries'])
         and {r['input_index'] for r in engines} == set(range(len(engines)))
         and all(r['accepted'] is True for r in engines), 'ordinary-Full-and-every-ALL-engine')
    return metrics


def sdk(runtime, operation, case, chosen, profile_raw, identity_raw, daa, mass=None,
        index=None, key=None):
    body, contexts = sdk_body(case)
    request = {'schema': 'kpx6-ordinary-coinbase-sdk/v1', 'operation': operation,
        'network_id': 'testnet-10', 'trial_id': chosen['trial_id'],
        'financial_profile_raw_utf8': profile_raw.decode(),
        'funding_identity_raw_utf8': identity_raw.decode(),
        'funding_identity_sha256': chosen['identity_sha256'], 'transaction': body,
        'contexts': contexts, 'observed_daa_score': str(daa)}
    if mass is not None:
        request['reference_mining_mass'] = str(mass)
    if index is not None:
        request['input_index'] = index
        request['funding_secret_hex32'] = key.hex()
    result = runtime.executables['node'].run(
        [ROOT / 'poc/four-wallet-live/ordinary_sdk.mjs', '--sdk-dir', str(runtime.sdk_dir)], request=request)
    return parse(result.stdout)


def run(a):
    need(str(ROOT) == '/work' and str(a.output) == '/out/run', 'closed-synthetic-worker-paths-only')
    backup_info = None
    forbidden = ()
    if a.operation == 'sign':
        _, backup_info = regular(Path('/owner/backup.json'))
        need(stat.S_IMODE(backup_info.st_mode) == 0o600, 'original-A-backup-mode')
        forbidden = ((backup_info.st_dev, backup_info.st_ino),)
    public = [a.profile, a.identity, a.observation,
              *(p for p in (a.case, a.quote) if p is not None),
              Path('/runtime/crypto'), Path('/runtime/node'), Path('/runtime/native-validator'),
              *(Path('/runtime/sdk') / name for name in SDK_PINS),
              ROOT / 'poc/four-wallet-live/ordinary_sdk.mjs']
    # Whole public ingress is checked before any public byte or private read.
    for path in public:
        regular(path, forbidden)
    profile_raw = public_bytes(a.profile, forbidden)
    identity_raw = public_bytes(a.identity, forbidden)
    chosen = selection(profile_raw, identity_raw, a.identity_sha256)
    observed = parse(public_bytes(a.observation, forbidden))
    points, entries, daa = observation(observed, chosen)
    runtime = Runtime(paths={r: Path('/runtime') / r for r in
        ('crypto', 'node', 'native-validator')}, sdk_dir=Path('/runtime/sdk'), forbidden=forbidden)
    need(not a.output.exists(), 'fresh-ordinary-worker-output')
    a.output.mkdir(mode=0o700)
    if a.operation == 'quote':
        fee, seen, ordinal = 0, set(), 0
        while True:
            need(fee not in seen, 'exact-reference-fee-fixed-point-does-not-exist')
            seen.add(fee)
            case = draft(points, entries, chosen, fee)
            case, metrics = runtime.normalize(case, a.output / ('quote-' + str(ordinal)))
            mass = uint(metrics['mining_mass'])
            required = uint(100 * mass)
            if required == fee:
                break
            fee, ordinal = required, ordinal + 1
        validate_case(case, chosen, daa, mass)
        roundtrip = sdk(runtime, 'roundtrip', case, chosen, profile_raw, identity_raw, daa, mass)
        need(roundtrip['transaction'] == sdk_body(case)[0]
             and roundtrip['lossless_safe_roundtrip'] is True, 'ordinary-quote-SDK-exact-roundtrip')
        case_raw = encoded(case) + b'\n'
        quote = {'schema': 'kpx6-ordinary-mined-funding-quote/v1',
            'financial_profile_sha256': PROFILE_SHA, 'funding_identity_sha256': chosen['identity_sha256'],
            'trial_id': chosen['trial_id'], 'virtual_daa_score': str(daa),
            'case_sha256': digest(case_raw), 'reference_fee_rate': 100,
            'mining_mass': mass, 'actual_fee_sompi': fee, 'input_count': len(entries),
            'genuine_signatures_or_accepted_currentness': False}
        write_new(a.output / 'validation-case.json', case_raw)
        write_new(a.output / 'QUOTE.json', encoded(quote) + b'\n')
        return {'status': 'QUOTED_NOT_SIGNED_OR_SUBMITTED', 'input_count': len(entries)}

    need(a.operation in ('sign', 'check') and a.case is not None and a.quote is not None,
         'fixed-ordinary-sign-operation')
    case_raw, quote_raw = public_bytes(a.case, forbidden), public_bytes(a.quote, forbidden)
    case, quote = parse(case_raw), parse(quote_raw)
    quoted_case = copy.deepcopy(case)
    if a.operation == 'check':
        for inp in quoted_case['transaction']['inputs']:
            inp['signatureScript'] = PLACEHOLDER
    quote_case_sha = digest(encoded(quoted_case) + b'\n')
    need(quote['schema'] == 'kpx6-ordinary-mined-funding-quote/v1'
         and quote['financial_profile_sha256'] == PROFILE_SHA
         and quote['funding_identity_sha256'] == chosen['identity_sha256']
         and quote['trial_id'] == chosen['trial_id'] and quote['case_sha256'] == quote_case_sha
         and quote['virtual_daa_score'] == str(daa) and quote['reference_fee_rate'] == 100,
         'selected-public-quote-case-and-identity')
    mass = uint(quote['mining_mass'])
    fee = validate_case(case, chosen, daa, mass, signed=a.operation == 'check')
    need([i['previousOutpoint'] for i in case['transaction']['inputs']] == points
         and case['entries'] == entries and quote['actual_fee_sompi'] == fee
         and quote['input_count'] == len(entries), 'exact-quoted-observed-sources')
    normalized, metrics = runtime.normalize(case, a.output / 'independent-quote')
    need(normalized == case and metrics['mining_mass'] == mass, 'fresh-native-exact-own-quote')
    rt = sdk(runtime, 'roundtrip', case, chosen, profile_raw, identity_raw, daa, mass)
    need(rt['transaction'] == sdk_body(case)[0] and rt['lossless_safe_roundtrip'] is True,
         'own-unsigned-SDK-roundtrip')
    if a.operation == 'check':
        metrics = native_full(runtime, case, a.output / 'public-Full')
        need(metrics['mining_mass'] == mass, 'public-Full-preserves-reference-quote')
        return {'status': 'PUBLIC_SIGNED_FULL_CHECKED_NOT_SUBMITTED', 'input_count': len(entries)}
    # This is the first private byte read. The shielded seed is never used.
    own = decode_backup(_private_backup(Path('/owner/backup.json'), backup_info),
                        chosen['domain'], chosen['trial_id'])
    funding_public = runtime.crypto.xonly(own.funding_key)
    need('000020' + funding_public.hex() + 'ac' == chosen['wallets']['A']['script_public_key'],
         'one-original-LIVE-A-funding-key-matches-all-inputs-and-refund')
    signed = copy.deepcopy(case)
    for index in range(len(entries)):
        result = sdk(runtime, 'sign-input', signed, chosen, profile_raw, identity_raw,
                     daa, mass, index, own.funding_key)
        need(result['input_index'] == index and result['network_or_broadcast'] is False
             and result['secret_material_emitted'] is False, 'own-ALL-signature-only-response')
        signed['transaction']['inputs'][index]['signatureScript'] = result['signature_script_hex66']
    validate_case(signed, chosen, daa, mass, signed=True)
    normalized, metrics = runtime.normalize(signed, a.output / 'signed-normalize')
    need(normalized == signed and metrics['mining_mass'] == mass, 'signatures-preserve-exact-body-and-quote')
    final_metrics = native_full(runtime, signed, a.output / 'signed-Full')
    need(final_metrics['mining_mass'] == mass, 'Full-preserves-reference-quote')
    rt = sdk(runtime, 'roundtrip', signed, chosen, profile_raw, identity_raw, daa, mass)
    need(rt['transaction'] == sdk_body(signed)[0] and rt['lossless_safe_roundtrip'] is True,
         'own-signed-SDK-roundtrip')
    write_new(a.output / 'validation-case.json', encoded(signed) + b'\n')
    receipt = {'schema': 'kpx6-ordinary-mined-funding-signed/v1', 'input_count': len(entries),
        'all_input_engines_accepted': True, 'reference_fee_rate': 100,
        'mining_mass': mass, 'actual_fee_sompi': fee, 'PK_or_shielded_seed_used': False,
        'secret_material_emitted': False, 'network_or_broadcast': False}
    write_new(a.output / 'RESULTS.json', encoded(receipt) + b'\n')
    return {'status': 'SIGNED_AND_NATIVE_FULL_VALID_NOT_SUBMITTED', 'input_count': len(entries)}


if __name__ == '__main__':
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('quote', 'sign', 'check'))
    p.add_argument('--identity-sha256', required=True)
    for name in ('profile', 'identity', 'observation', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('case', 'quote'):
        p.add_argument('--' + name, type=Path)
    try:
        print(encoded(run(p.parse_args())).decode())
    except Exception:
        # Never emit a scalar, seed, private request, exception repr or traceback.
        p.exit(1, 'ordinary funding worker refused\n')
