#!/usr/bin/env python3
"""Finite fresh-domain TN10 lifecycle. No broadcast occurs without chain release.

Private seeds, witnesses and keys remain in the constructor's private trial.
The six native bodies use the reviewed candidate-C value/ownership/NF rules.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time

import trial as identities
from core import (Core, Crypto, Delivery, ExpectedState, GENESIS_VALUE, NFEntry,
                  RATE, Receiver, Receipt, Snapshot, ZERO, dump_snapshot, exact,
                  load, native_call, outpoint, parse_snapshot, quote, recover,
                  save, sompi, u32, verify_link)

HERE = Path(__file__).resolve().parent
ROOT = identities.ROOT
DEFAULT_PAYMENT = 100_000_000  # Separate TN10 liveness pilot, not fee qualification.
NATIVE_TARGET = ROOT.parent / 'future-union-target'
PROOF_TARGET = ROOT.parent / 'future-lifecycle-target'


def sha(path):
    with Path(path).open('rb') as f:
        h = hashlib.sha256()
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def child(root, name):
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('private output name must stay relative to trial')
    p = root / relative
    identities.no_symlinks(p)
    if root not in p.absolute().parents:
        raise ValueError('private output escaped trial')
    return p


class Context:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()
        self.profile = identities.load_profile(self.directory)
        self.core = Core(self.profile['domain_hex32'], self.profile['trial_id'])
        p = self.profile
        bridge = Path(p['runtime']['bridge_path'])
        if sha(bridge) != p['runtime']['bridge_sha256']:
            raise ValueError('recipient bridge identity changed')
        v2 = ROOT / 'poc/future-recipient/v2/recipient.py'
        if sha(v2) != p['source_provenance']['files'][str(v2.relative_to(ROOT))]:
            raise ValueError('recipient source changed')
        self.crypto = Crypto(bridge)
        self.wallets = {}
        for label in ('alice', 'bob', 'charlie'):
            backup = load(self.directory / 'backups' / (label + '.json'))
            seed = exact(p['secrets'][label + '_seed_hex32'], 32)
            if (backup['schema'] != 'kpx2-tn10-seed-backup/v1'
                    or backup['domain_hex32'] != p['domain_hex32']
                    or backup['genesis_hash_hex'] != identities.GENESIS
                    or backup['seed_hex32'] != seed.hex()):
                raise ValueError('pre-payment seed backup mismatch')
            receiver = Receiver(seed, self.core.domain, self.crypto)
            identity = p['identities'][label]
            invoice = receiver.invoice(0)
            if (invoice.encode().hex() != identity['invoice_hex208']
                    or invoice.native_pk.hex() != identity['xonly_hex32']
                    or identity['spk_version'] != 0
                    or identity['spk_hex'] != '20' + invoice.native_pk.hex() + 'ac'):
                raise ValueError('recipient public identity is not derived from backup')
            self.wallets[label] = receiver
        funding_pk = self.crypto.xonly(exact(p['secrets']['funding_secret_hex32'], 32))
        funding = p['identities']['funding']
        if (funding['xonly_hex32'] != funding_pk.hex() or funding['spk_version'] != 0
                or funding['spk_hex'] != '20' + funding_pk.hex() + 'ac'):
            raise ValueError('funding identity/key mismatch')

    def suite(self):
        s = load(self.directory / 'suite.json')
        if (s['trial_id'] != self.profile['trial_id']
                or s['domain_hex32'] != self.profile['domain_hex32']
                or sha(self.directory / 'source-workspace/domain-source-manifest.json') != s['domain_source_sha256']):
            raise ValueError('matching domain suite missing')
        for key in ('native', 'prover'):
            if sha(s[key]['path']) != s[key]['sha256']:
                raise ValueError('selected trial binary changed')
        return s

    def initial(self, payment, fee, entropy):
        payment, fee = sompi(payment), sompi(fee)
        if payment < GENESIS_VALUE:
            raise ValueError('positive recipient note below unchanged minimum')
        specs = [('alice', 0, GENESIS_VALUE),
                 ('alice', 1, 2 * payment + fee - GENESIS_VALUE),
                 ('bob', 0, payment), ('charlie', 0, payment)]
        notes, records = [], []
        for position, (label, index, value) in enumerate(specs):
            sompi(value)
            invoice = self.wallets[label].invoice(index)
            note = Receipt.for_invoice(invoice, value, exact(entropy[position], 32))
            cipher = self.crypto.seal(invoice.delivery_pk, note.encode())
            notes.append(note)
            records.append(Delivery(position, note.commitment(), cipher))
        before = Snapshot(records[:2], [NFEntry(ZERO, ZERO, 0)])
        after, fixture, vector = self.core.private_case(before, self.wallets,
            [(0, self.wallets['alice'], 0), (1, self.wallets['alice'], 1)],
            records[2:], notes[2:], bytes(36), 2 * payment + fee, fee)
        return notes, records, before, after, fixture, vector


def run_logged(command, cwd, path, env=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        p = subprocess.run(command, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT)
    if p.returncode:
        raise ValueError('build/operation failed; private log: ' + str(path))


def prepare_suite(ctx, jobs):
    t = ctx.directory
    if not (t / 'source-workspace').exists():
        identities.materialize(t)
    source = t / 'source-workspace'
    manifest = load(source / 'domain-source-manifest.json')
    for item in manifest['files']:
        if sha(source / item['path']) != item['generated_sha256']:
            raise ValueError('materialized source changed')
    bin_dir = child(t, 'bin')
    bin_dir.mkdir(mode=0o700, exist_ok=True)
    # Reuse only Cargo dependency build caches. Selected trial executables are
    # copied privately and independently hashed; no prior PK/VK is loaded.
    plans = [('native', 'future-native-union', NATIVE_TARGET, 'kpi-future-native-union', True),
             ('prover', 'future-testnet/runner', PROOF_TARGET, 'kpi-tn10-private-proof', False)]
    selected = {}
    for name, package, target, binary, explicit_target in plans:
        mount = '/src' if explicit_target else '/workspace'
        mount_source = source / 'poc' / package if explicit_target else source
        manifest_path = '/src/Cargo.toml' if explicit_target else '/workspace/poc/future-testnet/runner/Cargo.toml'
        # Keep the dependency-cache paths identical to the original isolated
        # build. Host Cargo paths would needlessly rebuild RocksDB/Kaspa.
        toolchain = Path('/home/luke/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu')
        cmd = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--ro-bind', '/etc/alternatives', '/etc/alternatives', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--tmpfs', '/cargo',
            '--ro-bind', '/home/luke/.cargo/registry', '/cargo/registry',
            '--ro-bind', '/home/luke/.cargo/git', '/cargo/git',
            '--ro-bind', str(toolchain), '/toolchain', '--ro-bind', str(mount_source), mount,
            '--bind', str(target), '/target', '--setenv', 'PATH', '/toolchain/bin:/usr/bin:/bin',
            '--setenv', 'RUSTC', '/toolchain/bin/rustc', '--setenv', 'CARGO_HOME', '/cargo',
            '--setenv', 'CARGO_TARGET_DIR', '/target', '--setenv', 'TMPDIR', '/tmp', '--chdir', mount,
            '/toolchain/bin/cargo', 'build', '--frozen', '--offline', '--release', '-j', str(jobs),
            '--manifest-path', manifest_path]
        if explicit_target:
            cmd += ['--target', 'x86_64-unknown-linux-gnu']
        log_index = 1
        while (t / (name + '-build-' + str(log_index) + '.log')).exists():
            log_index += 1
        run_logged(cmd, source, t / (name + '-build-' + str(log_index) + '.log'))
        built = target / ('x86_64-unknown-linux-gnu/release' if explicit_target else 'release') / binary
        destination = bin_dir / binary
        if destination.exists():
            destination.unlink()
        shutil.copyfile(built, destination)
        destination.chmod(0o500)
        selected[name] = {'path': str(destination), 'sha256': sha(destination)}
    result = {'schema': 'kpx2-tn10-matching-suite/v1', 'trial_id': ctx.profile['trial_id'],
              'domain_hex32': ctx.profile['domain_hex32'],
              'domain_source_sha256': sha(source / 'domain-source-manifest.json'), **selected}
    save(t / 'suite.json', result)
    return result


def source_record(ctx, amount):
    """Local-only source fixture; never accepted as an observed funded source."""
    f = ctx.profile['identities']['funding']
    return {'oracle_stage': 'LOCAL_SUPPLIED_CONTEXT', 'transaction_id': os.urandom(32).hex(),
            'index': 0, 'amount_sompi': sompi(amount), 'spk_version': 0,
            'spk_hex': f['spk_hex'], 'source_key': 'TRIAL_FUNDING_KEY'}


def source_secret(ctx, source):
    if source['source_key'] == 'TRIAL_FUNDING_KEY':
        secret = exact(ctx.profile['secrets']['funding_secret_hex32'], 32)
    else:
        path = Path(source['source_key']).absolute()
        identities.outside_git(path)
        identities.no_symlinks(path)
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise ValueError('source key file must be private 0600')
        raw = path.read_bytes()
        if len(raw) == 32:
            secret = raw
        else:
            text = raw.decode().strip()
            secret = exact(json.loads(text)['source_secret_hex32'] if text.startswith('{') else text, 32)
    if (source['spk_version'] != 0
            or source['spk_hex'] != '20' + ctx.crypto.xonly(secret).hex() + 'ac'):
        raise ValueError('actual source UTXO does not belong to source signing key')
    exact(source['transaction_id'], 32)
    u32(source['index'])
    sompi(source['amount_sompi'])
    if source['oracle_stage'] not in ('LOCAL_SUPPLIED_CONTEXT', 'TRUSTED_TN10_ACCEPTED_NODE'):
        raise ValueError('unrecognized source acceptance boundary')
    return secret


def import_source(ctx, receipt_path, key_path, txid, index):
    receipt = load(receipt_path)
    if (receipt['server_info']['networkId'] != 'testnet-10'
            or receipt['server_info']['serverVersion'] != '2.1.0'
            or receipt['server_info']['isSynced'] is not True
            or receipt['server_info']['hasUtxoIndex'] is not True):
        raise ValueError('source observation network/runtime mismatch')
    entries = [x.get('entry', x) for x in receipt['utxos']['entries']]
    matches = [x for x in entries if x['outpoint'] == {'transactionId': txid, 'index': index}]
    if len(matches) != 1:
        raise ValueError('exact selected source UTXO absent or ambiguous')
    e = matches[0]
    amount = int(e['amount'])
    if str(amount) != str(e['amount']) or e['isCoinbase'] is not False or e.get('covenantId') is not None:
        raise ValueError('source amount/coinbase/covenant unsupported')
    source = {'oracle_stage': 'TRUSTED_TN10_ACCEPTED_NODE', 'transaction_id': txid,
        'index': index, 'amount_sompi': sompi(amount),
        'spk_version': e['scriptPublicKey']['version'], 'spk_hex': e['scriptPublicKey']['script'],
        'source_key': str(key_path.absolute()), 'source_observation_path': str(receipt_path.absolute()),
        'source_observation_sha256': sha(receipt_path),
        'source_observed_sink': receipt['dag']['sink'], 'source_observed_utc': receipt['observed_utc']}
    source_secret(ctx, source)
    save(ctx.directory / 'source.json', source)
    return {k: source[k] for k in ('oracle_stage', 'transaction_id', 'index', 'amount_sompi')}


def materialize(ctx, source, output, payment=DEFAULT_PAYMENT):
    """Price complete actual bodies and bind the real prepared outpoints."""
    output.mkdir(mode=0o700)
    suite = ctx.suite()
    native = Path(suite['native']['path'])
    vk = (ctx.directory / 'setup/verification-key.bin').read_bytes()
    if len(vk) != 328:
        raise ValueError('fresh trial VK width')
    selection = load(ctx.directory / 'setup/new-key-selection.json')
    if (selection['trial_id'] != ctx.profile['trial_id']
            or selection['domain_hex32'] != ctx.profile['domain_hex32']
            or selection['vk_hex328'] != vk.hex()):
        raise ValueError('fresh trial key selection mismatch')
    entropy = [os.urandom(32).hex() for _ in range(4)]
    save(output / 'private-rho.json', entropy)
    prepared = {}

    def private_vector(fee):
        items = ctx.initial(payment, fee, entropy)
        items[-1]['vk_hex'] = vk.hex()
        prepared[fee] = items
        return items[-1]

    private_fee, _, _ = quote(native, 'private', private_vector, output)
    notes, records, before, after, fixture, vector = prepared[private_fee]
    founding = Snapshot(records[:1], [NFEntry(ZERO, ZERO, 0)])
    funding_secret = exact(ctx.profile['secrets']['funding_secret_hex32'], 32)
    funding_pk = ctx.crypto.xonly(funding_secret).hex()
    # Quote-only fixed-width outpoint, replaced before the actual Auth/proof.
    placeholder = bytes(32).hex()
    def founding_vector(fee):
        return {'note_hex': notes[0].note_bytes().hex(), 'cipher_hex': records[0].ciphertext.hex(),
            'funding_previous_txid_raw_hex': placeholder, 'funding_previous_index': 0,
            'funding_amount_sompi': GENESIS_VALUE + fee, 'funding_secret_hex': funding_secret.hex(),
            'fee_sompi': fee, 'change_sompi': 0, 'vk_hex': vk.hex()}

    founding_fee, fv, fd = quote(native, 'founding', founding_vector, output)
    founding_amount = GENESIS_VALUE + founding_fee

    def admit_vector(fee):
        return {'state_hex': ctx.core.state(founding).hex(),
            'previous_txid_raw_hex': outpoint(fd)[:32].hex(), 'previous_index': 0,
            'reserve_sompi': GENESIS_VALUE,
            'payload_hex': ctx.core.admit_payload(notes[0], notes[1], records[1], founding, before, fee, 0).hex(),
            'funding_previous_txid_raw_hex': placeholder, 'funding_previous_index': 1,
            'funding_amount_sompi': notes[1].value_sompi + fee,
            'funding_secret_hex': funding_secret.hex(), 'vk_hex': vk.hex()}

    admit_fee, av, _ = quote(native, 'admit', admit_vector, output)
    admission_amount = notes[1].value_sompi + admit_fee
    signing_secret = source_secret(ctx, source)

    def prep_vector(fee):
        change = source['amount_sompi'] - founding_amount - admission_amount - fee
        sompi(change)
        return {'source_previous_txid_raw_hex': source['transaction_id'],
            'source_previous_index': source['index'], 'source_amount_sompi': source['amount_sompi'],
            'source_secret_hex': signing_secret.hex(), 'outputs': [
                {'value_sompi': founding_amount, 'xonly_public_key_hex': funding_pk},
                {'value_sompi': admission_amount, 'xonly_public_key_hex': funding_pk}],
            'fee_sompi': fee, 'source_change_sompi': change}

    prep_fee, pv, pd = quote(native, 'funding-prep', prep_vector, output)
    fv['funding_previous_txid_raw_hex'] = outpoint(pd)[:32].hex()
    fd = output / 'founding-final'
    native_call(native, 'founding-freeze', fv, fd)
    av['previous_txid_raw_hex'] = outpoint(fd)[:32].hex()
    av['funding_previous_txid_raw_hex'] = outpoint(pd)[:32].hex()
    ad = output / 'admit-final'
    native_call(native, 'admit-freeze', av, ad)
    after, fixture, vector = ctx.core.private_case(before, ctx.wallets,
        [(0, ctx.wallets['alice'], 0), (1, ctx.wallets['alice'], 1)],
        records[2:], notes[2:], outpoint(ad), 2 * payment + private_fee, private_fee)
    vector['vk_hex'] = vk.hex()
    metrics = native_call(native, 'private-freeze', vector, output / 'private-placeholder')
    if private_fee < RATE * metrics['mining_mass']:
        raise ValueError('final actual-context private fee insufficient')
    for kind, v in [('funding-prep', pv), ('founding', fv), ('admit', av), ('private', vector)]:
        save(output / (kind + '-vector.json'), v)
    save(output / 'private-fixture.json', fixture)
    save(output / 'records.json', {'founding': dump_snapshot(founding),
        'before-private': dump_snapshot(before), 'after-private': dump_snapshot(after)})
    save(output / 'plan.json', {'trial_id': ctx.profile['trial_id'],
        'domain_hex32': ctx.profile['domain_hex32'], 'oracle_stage': source['oracle_stage'],
        'source': source, 'payment_value_sompi': payment,
        'fees_sompi': {'fundingprep': prep_fee, 'founding': founding_fee,
                       'admit': admit_fee, 'private': private_fee},
        'fundingprep_quote_directory': pd.name, 'private_fixture_sha256': sha(output / 'private-fixture.json'),
        'private_authorization_bound_previous_outpoint_hex36': outpoint(ad).hex(),
        'fee_qualification': 'NOT_QUALIFIED_SMALL_TESTNET_LIVENESS_PILOT'})
    return output


def pid_identity(pid):
    return (Path('/proc') / str(pid) / 'stat').read_text().rsplit(') ', 1)[1].split()[19]


def server_alive(server):
    try:
        process = (Path('/proc') / str(server['pid']) / 'stat').read_text().rsplit(') ', 1)[1].split()
        return process[0] != 'Z' and process[19] == server['start_ticks']
    except (FileNotFoundError, ProcessLookupError):
        return False


def wait_file(path, server):
    # Operational slowness does not turn a valid trial into a failure. The
    # process exits only on an actual child failure or completed artifact.
    while not path.exists():
        if not server_alive(server):
            raise ValueError('prover exited; retained private prover-session.log')
        time.sleep(0.2)


def wait_event(ctx, event, field, expected, server):
    log = ctx.directory / 'prover-session.log'
    while True:
        for line in log.read_text().splitlines():
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get('event') == event and message.get(field) == str(expected):
                return
        if not server_alive(server):
            raise ValueError('prover exited; retained private prover-session.log')
        time.sleep(0.2)


def start_prover(ctx, payment, cpus):
    suite = ctx.suite()
    shape = child(ctx.directory, 'shape')
    shape.mkdir(mode=0o700)
    fixture = ctx.initial(payment, 1, [os.urandom(32).hex() for _ in range(4)])[-2]
    save(shape / 'fixture.json', fixture)
    fifo = ctx.directory / 'prover-control.fifo'
    os.mkfifo(fifo, 0o600)
    control = os.open(fifo, os.O_RDWR)
    fd = os.open(ctx.directory / 'prover-session.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    env = dict(os.environ, RAYON_NUM_THREADS=str(cpus))
    with os.fdopen(fd, 'wb') as log:
        p = subprocess.Popen([suite['prover']['path'], 'session', str(shape / 'fixture.json'),
            str(ctx.directory / 'setup'), str(ctx.directory / 'fresh-key.uncompressed')],
            stdin=control, stdout=log, stderr=subprocess.STDOUT,
            cwd=ctx.directory / 'source-workspace', env=env, start_new_session=True)
    os.close(control)
    server = {'pid': p.pid, 'start_ticks': pid_identity(p.pid),
              'binary_sha256': suite['prover']['sha256'], 'trial_id': ctx.profile['trial_id']}
    save(ctx.directory / 'prover-session.json', server)
    wait_event(ctx, 'ready', 'selection_path', ctx.directory / 'setup/new-key-selection.json', server)
    return server


def prove(ctx, fixture, output):
    server = load(ctx.directory / 'prover-session.json')
    if not server_alive(server) or server['trial_id'] != ctx.profile['trial_id']:
        raise ValueError('matching resident fresh-key prover not available')
    if sha(Path('/proc') / str(server['pid']) / 'exe') != server['binary_sha256']:
        raise ValueError('resident prover binary changed')
    with (ctx.directory / 'prover-control.fifo').open('w') as f:
        f.write(json.dumps({'fixture': str(fixture), 'output': str(output)}) + '\n')
        f.flush()
    wait_event(ctx, 'proof-complete', 'report_path', output / 'report.json', server)
    return load(output / 'report.json')


def stop_prover(ctx):
    server = load(ctx.directory / 'prover-session.json')
    if server_alive(server):
        if sha(Path('/proc') / str(server['pid']) / 'exe') != server['binary_sha256']:
            raise ValueError('resident prover identity changed before stop')
        os.killpg(server['pid'], signal.SIGTERM)
        while server_alive(server):
            time.sleep(0.05)
    save(ctx.directory / 'prover-stopped.json', {'trial_id': ctx.profile['trial_id'],
         'pid': server['pid'], 'process_stopped': True,
         'before_recipient_authorization': True})


def adapter_call(ctx, request, output):
    command = ['node', str(ROOT / 'poc/future-native-chain/adapter.mjs')]
    request = dict(request, profile_path=str(ctx.directory / 'public/identity.json'),
        rpc_url='wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh')
    p = subprocess.run(command, input=json.dumps(request), text=True, capture_output=True)
    if p.returncode:
        save(output.with_suffix('.failure.json'), {'returncode': p.returncode,
             'stdout': p.stdout, 'stderr': p.stderr})
        raise ValueError('chain adapter failed; private failure retained')
    result = json.loads(p.stdout)
    save(output, result)
    return result


def local_prefix(ctx, prepared, output):
    output.mkdir(mode=0o700)
    native = Path(ctx.suite()['native']['path'])
    for kind in ('funding-prep', 'founding', 'admit'):
        native_call(native, kind + '-run', load(prepared / (kind + '-vector.json')), output / kind)
    links = [verify_link(output / 'funding-prep', output / 'founding'),
             verify_link(output / 'founding', output / 'admit'),
             verify_link(output / 'funding-prep', output / 'admit', 1, 1)]
    if outpoint(output / 'admit') != outpoint(prepared / 'admit-final'):
        raise ValueError('validated actual prefix changed private authorization outpoint')
    return links


def local_payment(ctx, prepared, output, proof):
    native = Path(ctx.suite()['native']['path'])
    vector = load(prepared / 'private-vector.json')
    report = load(proof / 'report.json')
    raw = (proof / 'proof128.bin').read_bytes()
    if (len(raw) != 128 or report['genuine_Groth16_verified'] is not True
            or report['fixture_sha256'] != sha(prepared / 'private-fixture.json')
            or report['vk_hex328'] != vector['vk_hex'] or report['proof_hex128'] != raw.hex()):
        raise ValueError('genuine proof/source/authorization identity mismatch')
    vector['proof_hex'] = raw.hex()
    native_call(native, 'private-run', vector, output / 'private')
    return verify_link(output / 'admit', output / 'private')


def local_exits(ctx, prepared, execution):
    suite = ctx.suite()
    inputs_root = child(ctx.directory, 'exit-inputs')
    inputs_root.mkdir(mode=0o700)
    output = child(ctx.directory, 'exits')
    output.mkdir(mode=0o700)
    records = load(prepared / 'records.json')
    plan = load(prepared / 'plan.json')
    private = load(prepared / 'private-vector.json')
    snapshot = parse_snapshot(records['after-private'])
    previous = execution / 'private'
    public = load(ctx.directory / 'public/identity.json')
    public['runtime_pins'] = {'bridge_sha256': ctx.profile['runtime']['bridge_sha256']}
    save(ctx.directory / 'public/recovery-identity.json', public)
    combined = {'trial_id': ctx.profile['trial_id'], 'recipients': {}, 'snapshots': {},
                'native_Full_operations': 0, 'links': []}
    for label in ('bob', 'charlie'):
        inputs = inputs_root / label
        inputs.mkdir(mode=0o700)
        stage = output / (label + '-stage')
        stage.mkdir(mode=0o700)
        for name, original in [('native', suite['native']['path']),
                               ('crypto', ctx.profile['runtime']['bridge_path'])]:
            shutil.copyfile(original, inputs / name)
            (inputs / name).chmod(0o500)
        shutil.copyfile(ctx.directory / 'public/recovery-identity.json', inputs / 'identity.json')
        (inputs / 'identity.json').chmod(0o600)
        (inputs / 'backups').mkdir(mode=0o700)
        shutil.copyfile(ctx.directory / 'backups' / (label + '.json'), inputs / 'backups' / (label + '.json'))
        (inputs / 'backups' / (label + '.json')).chmod(0o600)
        (inputs / 'previous').mkdir(mode=0o700)
        for name in ('transaction.json', 'supplied-context.json', 'txid-raw.hex'):
            shutil.copyfile(previous / name, inputs / 'previous' / name)
            (inputs / 'previous' / name).chmod(0o600)
        save(inputs / 'head.json', {'trial_id': ctx.profile['trial_id'], 'recipient': label,
            'domain_hex32': ctx.profile['domain_hex32'], 'oracle_stage': 'LOCAL_SUPPLIED_CONTEXT',
            'snapshot': dump_snapshot(snapshot), 'state_hex112': ctx.core.state(snapshot).hex(),
            'reserve_sompi': (2 if label == 'bob' else 1) * plan['payment_value_sompi'],
            'payment_value_sompi': plan['payment_value_sompi'], 'vk_hex328': private['vk_hex'],
            'excluded_paths': [str(ctx.directory / 'profile.json'),
                str(ctx.directory / 'fresh-key.uncompressed'), suite['prover']['path'],
                str(ctx.directory / 'prover-control.fifo'),
                str(ctx.directory / 'backups' / (('charlie' if label == 'bob' else 'bob') + '.json'))]})
        command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--ro-bind', '/etc/alternatives', '/etc/alternatives', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--ro-bind', str(ROOT), str(ROOT), '--ro-bind', str(inputs), '/in',
            '--bind', str(stage), '/out', '--setenv', 'PATH', '/usr/bin:/bin',
            '--setenv', 'PYTHONDONTWRITEBYTECODE', '1', '--chdir', str(HERE),
            '/usr/bin/python3', '-B', str(HERE / 'exit_worker.py'), '/in', '/out']
        run_logged(command, ROOT, ctx.directory / (label + '-exit-worker.log'))
        result = load(stage / 'RESULTS.json')
        directory = stage / (label + '-reveal')
        combined['links'].append(verify_link(previous, directory))
        combined['recipients'].update(result['recipients'])
        combined['snapshots'].update(result['snapshots'])
        combined['native_Full_operations'] += 1
        key = 'after-bob' if label == 'bob' else 'terminal'
        snapshot = parse_snapshot(result['snapshots'][key])
        previous = directory
    if result['reserve_sompi'] != 0 or result['liability_sompi'] != 0:
        raise ValueError('local terminal reserve/liability remains')
    combined.update({'reserve_sompi': 0, 'liability_sompi': 0,
        'final_state_hex112': result['final_state_hex112'],
        'one_recipient_seed_per_exit_process': True,
        'prover_or_pk_available_during_exit': False, 'testnet_payout_confirmed': False})
    save(output / 'RESULTS.json', combined)
    return combined


def close_local(ctx, prepared, execution):
    plan = load(prepared / 'plan.json')
    exits = load(ctx.directory / 'exits/RESULTS.json')
    records = load(prepared / 'records.json')
    operations = []
    profile_hash = sha(ctx.directory / 'public/identity.json')
    native_hash = ctx.suite()['native']['sha256']
    for kind, directory in [('fundingprep', execution / 'funding-prep'),
            ('founding', execution / 'founding'), ('admit', execution / 'admit'),
            ('private', execution / 'private'), ('bob-reveal', ctx.directory / 'exits/bob-stage/bob-reveal'),
            ('charlie-reveal', ctx.directory / 'exits/charlie-stage/charlie-reveal')]:
        body_path = directory / 'transaction.json'
        body = load(body_path)
        validation = load(directory / 'native-validation.json')
        supplied = load(directory / 'supplied-context.json')
        full = validation['Full']
        if full['accepted'] is not True:
            raise ValueError('native Full did not accept all six bodies')
        # Native ScriptEngine fields are retained and must all be accepted.
        engines = validation.get('per_input_ScriptEngine', [])
        if (validation.get('all_input_engines_accepted') is not True
                or len(engines) != len(body['inputs'])
                or any(e.get('accepted') is not True for e in engines)):
            raise ValueError('native script engine rejected an input')
        checked = {'body_sha256': sha(body_path), 'transaction_id': body['id'],
            'profile_sha256': profile_hash, 'native_full_accepted': True,
            'all_input_engines_accepted': True, 'native_binary_sha256': native_hash,
            'inputs': [{'outpoint': inp['previousOutpoint'], 'amount_sompi': str(entry['amount_sompi']),
                'script_public_key': entry['script_public_key'], 'block_daa_score': str(entry.get('block_daa_score', 0)), 'is_coinbase': False, 'covenant_id': None}
                for inp, entry in zip(body['inputs'], supplied)]}
        if kind == 'founding':
            next_admit = load(execution / 'admit/transaction.json')
            checked['output0_redeem_hex'] = next_admit['inputs'][0]['signatureScript'][398:]
        save(directory / 'local-check.json', checked)
        roundtrip = adapter_call(ctx, {'op': 'roundtrip', 'body_path': str(body_path)}, directory / 'sdk-roundtrip.json')
        if roundtrip['lossless_native_roundtrip'] is not True:
            raise ValueError('SDK did not preserve native body')
        operations.append({'kind': kind, 'directory': str(directory), 'txid_raw_hex': body['id'],
            'accepted_body_path': str(body_path), 'accepted_body_sha256': sha(body_path),
            'local_check_path': str(directory / 'local-check.json'),
            'local_check_sha256': sha(directory / 'local-check.json'),
            'native_validation_path': str(directory / 'native-validation.json'),
            'native_validation_sha256': sha(directory / 'native-validation.json')})
    snapshots = dict(records, **exits['snapshots'])
    archive = {'schema': 'kpx2-tn10-accepted-archive/v1', 'oracle_stage': 'LOCAL_SUPPLIED_CONTEXT',
        'trial_id': ctx.profile['trial_id'], 'domain_hex32': ctx.profile['domain_hex32'],
        'network_id': 'testnet-10', 'genesis_hash_hex': identities.GENESIS,
        'expected_payments_sompi': {'bob': plan['payment_value_sompi'], 'charlie': plan['payment_value_sompi']},
        'operations': operations, 'snapshots': snapshots,
        'head': {'state_hex112': exits['final_state_hex112'], 'reserve_sompi': 0,
                 'outpoint': None, 'accepted_operation_index': 5}}
    save(ctx.directory / 'local-archive.json', archive)
    fees = dict(plan['fees_sompi'], **{label + '_reveal': exits['recipients'][label]['fee_sompi']
                                    for label in ('bob', 'charlie')})
    payouts = sum(x['payout_sompi'] for x in exits['recipients'].values())
    prep = load(execution / 'funding-prep/transaction.json')
    source_change = prep['outputs'][2]['value'] if len(prep['outputs']) == 3 else 0
    if source_change + payouts + sum(fees.values()) != plan['source']['amount_sompi']:
        raise ValueError('whole external source/ordinary change/payout/fees mismatch')
    result = {'schema': 'kpx2-tn10-local-terminal-rehearsal/v1',
        'trial_id': ctx.profile['trial_id'], 'domain_hex32': ctx.profile['domain_hex32'],
        'native_Full_operations': 6, 'sdk_lossless_roundtrips': 6,
        'genuine_private_proofs': 1, 'terminal_reserve_sompi': 0, 'terminal_liability_sompi': 0,
        'fees_sompi': fees, 'total_fees_sompi': sum(fees.values()),
        'source_amount_sompi': plan['source']['amount_sompi'], 'ordinary_source_change_sompi': source_change,
        'payouts_sompi': {label: exits['recipients'][label]['payout_sompi'] for label in ('bob', 'charlie')},
        'payment_value_sompi': plan['payment_value_sompi'], 'all_six_body_ids_frozen': True,
        'preferred_service_prover_pk_absent_for_exit': True,
        'fee_qualification': plan['fee_qualification'], 'broadcast': False, 'testnet_payout_confirmed': False}
    save(ctx.directory / 'LOCAL-COMPLETE.json', result)
    return result


def rehearse(ctx, source, payment, jobs, cpus):
    """One automated matching build/setup/actual-body terminal rehearsal."""
    if (ctx.directory / 'LOCAL-COMPLETE.json').exists():
        raise ValueError('trial already rehearsed; retain its exact six bodies')
    if not (ctx.directory / 'suite.json').exists():
        prepare_suite(ctx, jobs)
    start_prover(ctx, payment, cpus)
    prepared = materialize(ctx, source, child(ctx.directory, 'actual-prepared'), payment)
    execution = child(ctx.directory, 'actual-execution')
    proof = child(ctx.directory, 'actual-proof')
    local_prefix(ctx, prepared, execution)
    prove(ctx, prepared / 'private-fixture.json', proof)
    local_payment(ctx, prepared, execution, proof)
    stop_prover(ctx)
    local_exits(ctx, prepared, execution)
    return close_local(ctx, prepared, execution)


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    s = p.add_subparsers(dest='command', required=True)
    for name in ('prepare-suite', 'start-prover', 'source', 'materialize', 'prefix', 'prove', 'payment', 'exits', 'close-local', 'rehearse'):
        a = s.add_parser(name)
        a.add_argument('trial', type=Path)
        if name == 'prepare-suite':
            a.add_argument('--jobs', type=int, default=8)
        if name == 'rehearse':
            a.add_argument('--source', type=Path, required=True)
            a.add_argument('--payment-sompi', type=int, default=DEFAULT_PAYMENT)
            a.add_argument('--jobs', type=int, default=8)
            a.add_argument('--cpus', type=int, default=14)
        if name == 'start-prover':
            a.add_argument('--cpus', type=int, default=14)
            a.add_argument('--payment-sompi', type=int, default=DEFAULT_PAYMENT)
        if name == 'source':
            a.add_argument('--receipt', required=True, type=Path)
            a.add_argument('--key-path', required=True, type=Path)
            a.add_argument('--txid', required=True)
            a.add_argument('--index', required=True, type=int)
        if name == 'materialize':
            a.add_argument('--source', type=Path)
            a.add_argument('--local-source-sompi', type=int, default=306_866_100)
            a.add_argument('--payment-sompi', type=int, default=DEFAULT_PAYMENT)
            a.add_argument('--name', default='local-prepared')
        if name in ('prefix', 'prove', 'payment', 'exits', 'close-local'):
            a.add_argument('--prepared', default='local-prepared')
            a.add_argument('--execution', default='local-execution')
            a.add_argument('--proof', default='local-proof')
    a = p.parse_args()
    try:
        ctx = Context(a.trial)
        if a.command == 'prepare-suite':
            r = prepare_suite(ctx, a.jobs)
        elif a.command == 'start-prover':
            r = start_prover(ctx, a.payment_sompi, a.cpus)
        elif a.command == 'source':
            r = import_source(ctx, a.receipt, a.key_path, a.txid, a.index)
        elif a.command == 'rehearse':
            r = rehearse(ctx, load(a.source), a.payment_sompi, a.jobs, a.cpus)
        elif a.command == 'materialize':
            source = load(a.source) if a.source else source_record(ctx, a.local_source_sompi)
            r = {'prepared': str(materialize(ctx, source, child(ctx.directory, a.name), a.payment_sompi))}
        elif a.command == 'prefix':
            r = {'links': local_prefix(ctx, child(ctx.directory, a.prepared), child(ctx.directory, a.execution))}
        elif a.command == 'prove':
            r = prove(ctx, child(ctx.directory, a.prepared) / 'private-fixture.json', child(ctx.directory, a.proof))
            r = {k: r[k] for k in ('trial_id', 'domain_hex32', 'genuine_Groth16_verified', 'wall_seconds')}
        elif a.command == 'payment':
            r = local_payment(ctx, child(ctx.directory, a.prepared), child(ctx.directory, a.execution), child(ctx.directory, a.proof))
        elif a.command == 'exits':
            r = local_exits(ctx, child(ctx.directory, a.prepared), child(ctx.directory, a.execution))
            r = {k: r[k] for k in ('trial_id', 'native_Full_operations', 'reserve_sompi', 'liability_sompi')}
        else:
            r = close_local(ctx, child(ctx.directory, a.prepared), child(ctx.directory, a.execution))
        print(json.dumps(r, sort_keys=True))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as e:
        print('trial operation stopped: ' + str(e), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
