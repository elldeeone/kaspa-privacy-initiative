#!/usr/bin/env python3
"""Known PUBLIC seed controls for publication_derived; never mount originals.

All host public reads pass guard09. Namespace workers use only the finite public
copies selected here and an intentionally public fixture BACKUP. This is not
accepted-chain, privacy or actual-original coverage.
"""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
BASE = Path('/var/tmp/kpi-local-private-payment-01')
READ = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
ASSETS = BASE / 'assets/wallet-public-fixture-stage-03/WALLET-ASSETS.json'
ASSETS_SHA = 'edcc3179315a9b256b62f7ce22639ff1323c14444a43e426d292db8a294faf22'
HISTORY = BASE / 'results/public/wallet-component-fixture-02/EXIT-05-HISTORY.json'
CONTEXT = BASE / 'results/public/wallet-component-fixture-02/EXIT-05-CONTEXT.json'
DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
PUBLIC_SEED = hashlib.sha256(b'KPXA KNOWN PUBLIC FIXTURE SEED A NOT PRIVATE').digest()
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def save(path, raw, mode=0o400):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
    os.chmod(path, mode)


def prepare(output):
    assert not output.exists(), 'fresh-public-control-output-required'
    output.mkdir(mode=0o700)
    files = {}
    sources = []
    for name in ('wallet/support.py', 'wallet/payment.py', 'recovery/history.py', 'recovery/publication_derived.py',
                 'integration/trees.py', 'verification/wire.py'):
        path = ROOT / 'poc/local-private-payment' / name
        raw = READ(path, '5ff0774fd1bb67ebc5ed5ec246ce2434082bfc4ce82dad9e58047b34232d2bda'
                   if name == 'wallet/payment.py' else None)
        save(output / 'software' / name, raw)
        files['/public/' + name] = output / 'software' / name
        sources.append({'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    assets = json.loads(READ(ASSETS, ASSETS_SHA))
    for key in ('relation', 'crypto', 'recipient', 'wire', 'trees'):
        row = assets[key]
        raw = READ(row['path'], row['sha256'])
        relative = {'relation': 'bin/relation', 'crypto': 'bin/crypto', 'recipient': 'recipient.py',
                    'wire': 'verification/wire.py', 'trees': 'integration/trees.py'}[key]
        target = output / 'software' / relative
        if not target.exists():
            save(target, raw, 0o500 if key in ('relation', 'crypto') else 0o400)
        else:
            assert hashlib.sha256(READ(target)).hexdigest() == row['sha256']
        row['path'] = '/public/' + relative
        files[row['path']] = target
    for role in ('spend', 'output', 'exit'):
        row = assets[role]
        raw = READ(row['manifest'], row['manifest_sha256'])
        path = output / 'software/parameters' / (role + '-manifest.json')
        save(path, raw)
        row['manifest'] = '/public/parameters/' + role + '-manifest.json'
        row['pk'] = '/public/parameters/' + role + '.pk'  # Scan never opens a PK.
        files[row['manifest']] = path
    for name, raw in [('ASSETS.json', encoded(assets)), ('HISTORY.json', READ(HISTORY)),
                      ('CONTEXT.json', READ(CONTEXT))]:
        target = output / 'software' / name
        save(target, raw)
        files['/public/' + name] = target
    own_source = READ(Path(__file__).absolute())
    sources.append({'path': str(Path(__file__).absolute()), 'bytes': len(own_source),
                    'sha256': hashlib.sha256(own_source).hexdigest()})
    mounted = []
    for name, path in sorted(files.items()):
        raw = READ(path)
        mounted.append({'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    save(output / 'SOURCE.json', encoded({'schema': 'kpxa-known-public-derived-control-source/v1',
         'classification': 'KNOWN_PUBLIC_SEED_ONLY_NO_PROTECTED_ORIGINALS', 'sources': sources,
         'original_wallet_assets_sha256': ASSETS_SHA, 'finite_public_mounts': mounted}))
    return files


def base_command(files, out):
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
               '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
               '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
               '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
               '--setenv', 'LANG', 'C.UTF-8', '--dir', '/public', '--dir', '/public/wallet',
               '--dir', '/public/recovery', '--dir', '/public/integration', '--dir', '/public/verification',
               '--dir', '/public/bin', '--dir', '/public/parameters', '--dir', '/candidates', '--dir', '/out']
    for mount, source in sorted(files.items()):
        command += ['--ro-bind', str(source), mount]
    command += ['--bind', str(out), '/out']
    return command


def material(files, output):
    """Separate producer has a hardcoded PUBLIC fixture seed and no backup mount."""
    out = output / 'material'
    out.mkdir(mode=0o700)
    code = """import hashlib,json,sys
from pathlib import Path
sys.path[:0]=['/public/wallet','/public/recovery']
import support,history,payment
raw=Path('/public/ASSETS.json').read_bytes()
assets=support.Assets(raw,hashlib.sha256(raw).hexdigest())
context=support.parse(Path('/public/CONTEXT.json').read_bytes())
accepted=history.load(Path('/public/HISTORY.json').read_bytes(),context['checkpoint'],context['genesis_sha256'],assets)
receiver=assets.receiver(hashlib.sha256(b'KPXA KNOWN PUBLIC FIXTURE SEED A NOT PRIVATE').digest())
claim=history.claims(accepted,receiver,assets)[0]
owned=history.claims(accepted,receiver,assets)
payment.reconcile_payouts(accepted,receiver,assets)
by_nf={c.nf:c for c in owned}
event=next(e for e in accepted.exits if e['nf'] in by_nf)
prefix=history.History(accepted.state,1,event['point'],accepted.deliveries[:event['delivery_count']])
earlier=history.claims(prefix,receiver,assets)
payout_key=receiver.keys(payment.payout_index(prefix,earlier,by_nf[event['nf']])).native_secret
items={'key':receiver.keys(claim.receipt.index).nf_secret,'note':claim.receipt.note_bytes(),'receipt':claim.receipt.encode(),'payout-key':payout_key}
for name,raw in items.items():Path('/out/'+name+'.bin').write_bytes(raw)
probe={'no_home':not Path('/home').exists(),'no_var':not Path('/var').exists(),'no_root':not Path('/root').exists(),'no_owner_parent':not Path('/owner').exists(),'no_private_parent':not Path('/private').exists(),'no_backup':not Path('/BACKUP.json').exists(),'no_sibling':not Path('/SIBLING.json').exists()}
Path('/out/PROBE.json').write_text(json.dumps(probe,sort_keys=True))
"""
    result = subprocess.run(base_command(files, out) + ['/usr/bin/python3', '-B', '-c', code],
                            stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
    assert result.returncode == 0, 'public-material-producer-refused'
    probe = json.loads(READ(out / 'PROBE.json'))
    assert probe and all(v is True for v in probe.values()), 'namespace-root-sibling-control'
    return {name: READ(out / (name + '.bin')) for name in ('key', 'note', 'receipt', 'payout-key')}, probe


def one_case(files, output, name, payload, *, wrong_domain=False, wrong_owner=False,
             wrong_public_path=False, alias_backup=False, tamper=False,
             manifest_path=None, escape_manifest_path=False, expected='PASS'):
    root = output / name
    root.mkdir(mode=0o700)
    out = root / 'out'
    out.mkdir(mode=0o700)
    candidate = root / '0.bin'
    save(candidate, payload)
    row = {'path': name + '.bin' if manifest_path is None else manifest_path,
           'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}
    allowlist = encoded({'schema': 'kpxa-derived-export-candidates/v1', 'files': [row]})
    if escape_manifest_path:
        escaped = '"' + ''.join('\\u%04x' % ord(c) for c in row['path']) + '"'
        allowlist = allowlist.replace(json.dumps(row['path']).encode(), escaped.encode())
    save(root / 'ALLOWLIST.json', allowlist)
    save(root / 'PUBLIC-BACKUP.json', encoded({'schema': 'kpxa-original-seed-backup/v1',
         'domain_hex32': '00' * 32 if wrong_domain else DOMAIN,
         'seed_hex32': PUBLIC_SEED.hex()}), 0o600)
    if tamper:
        os.chmod(candidate, 0o600)
        candidate.write_bytes(b'changed after selection')
        os.chmod(candidate, 0o400)
    command = base_command(files, out) + [
        '--ro-bind', str(root / 'PUBLIC-BACKUP.json'), '/BACKUP.json',
        '--ro-bind', str(root / 'ALLOWLIST.json'), '/ALLOWLIST.json',
        '--ro-bind', str(root / 'PUBLIC-BACKUP.json') if alias_backup else str(candidate),
        '/candidates/0.bin', '/usr/bin/python3', '-B',
        '/public/recovery/publication_derived.py', '--owner', '/SIBLING.json' if wrong_owner else '/BACKUP.json',
        '--allowlist', '/ALLOWLIST.json', '--allowlist-sha256', hashlib.sha256(allowlist).hexdigest(),
        '--candidates', '/candidates', '--output', '/out/RESULTS.json', '--assets', '/public/ASSETS.json',
        '--assets-sha256', hashlib.sha256(READ(files['/public/ASSETS.json'])).hexdigest(),
        '--history', '/BACKUP.json' if wrong_public_path else '/public/HISTORY.json',
        '--history-sha256', hashlib.sha256(READ(files['/public/HISTORY.json'])).hexdigest(),
        '--context', '/public/CONTEXT.json', '--context-sha256', hashlib.sha256(READ(files['/public/CONTEXT.json'])).hexdigest()]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
    if expected == 'REFUSE':
        assert result.returncode == 2 and not (out / 'RESULTS.json').exists(), name
        return {'name': name, 'status': 'PASS', 'expected': 'REFUSE', 'no_result': True}
    assert result.returncode == 0, name
    observed = json.loads(READ(out / 'RESULTS.json'))
    assert observed['status'] == expected and observed['literal_seed_coverage'] is False, name
    assert observed['matched_candidate_count'] == (0 if expected == 'PASS' else 1), name
    return {'name': name, 'status': 'PASS', 'expected': expected,
            'matched_candidate_count': observed['matched_candidate_count']}


def run(output):
    files = prepare(output)
    samples, probe = material(files, output)
    cases = [one_case(files, output, 'clean-miss', b'ordinary selected PUBLIC research bytes'),
             one_case(files, output, 'key-raw-hit', samples['key'], expected='FAIL'),
             one_case(files, output, 'key-lower-hex-hit', samples['key'].hex().encode(), expected='FAIL'),
             one_case(files, output, 'key-upper-hex-hit', samples['key'].hex().upper().encode(), expected='FAIL'),
             one_case(files, output, 'payout-native-key-hit', samples['payout-key'], expected='FAIL'),
             one_case(files, output, 'escaped-manifest-path-hit', b'clean',
                      manifest_path=samples['key'].hex(), escape_manifest_path=True, expected='FAIL'),
             one_case(files, output, 'note-chunk-boundary-hit', b'x' * (65536 - 83) + samples['note'], expected='FAIL'),
             one_case(files, output, 'receipt-hex-boundary-hit', b'x' * (65536 - 200) + samples['receipt'].hex().encode(), expected='FAIL'),
             one_case(files, output, 'wrong-domain-refused', b'clean', wrong_domain=True, expected='REFUSE'),
             one_case(files, output, 'sibling-path-refused', b'clean', wrong_owner=True, expected='REFUSE'),
             one_case(files, output, 'backup-as-public-history-refused', b'clean', wrong_public_path=True, expected='REFUSE'),
             one_case(files, output, 'backup-as-candidate-refused', b'clean', alias_backup=True, expected='REFUSE'),
             one_case(files, output, 'changed-candidate-refused', b'clean', tamper=True, expected='REFUSE')]
    report = {'schema': 'kpxa-known-public-derived-controls/v1', 'status': 'PASS',
              'classification': 'KNOWN_PUBLIC_SEEDS_SUPPLIED_CONTEXT_ONLY',
              'controls': cases, 'namespace_absence_controls': probe,
              'actual_originals_read_or_mounted': False, 'accepted_chain_claim': False,
              'all_possible_secret_coverage_claim': False}
    save(output / 'RESULTS.json', encoded(report))
    print(json.dumps({'status': 'PASS', 'controls': len(cases), 'namespace_absence_controls': len(probe),
                      'actual_originals_read_or_mounted': False}, sort_keys=True))


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    run(p.parse_args().output)
