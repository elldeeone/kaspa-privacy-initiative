#!/usr/bin/env python3
"""Finite real-wallet experiment. No chain RPC, GPU proving or fund broadcast."""
import argparse, concurrent.futures, copy, hashlib, json, os, pathlib, secrets, shutil, subprocess, time, uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = pathlib.Path(__file__).resolve().parent
HOST = ROOT / '.local/ci-target/release/kpi-separated-withdrawal'
TOR = ROOT / '.local/withdrawal-followup/tools/tor/usr/bin/tor'

def write(p, v):
    with p.open('x') as f:
        json.dump(v, f, indent=2)
        f.write('\n')

def read(p):
    return json.loads(p.read_text())

def command(args, **kw):
    return subprocess.run(list(map(str, args)), check=True, **kw)

def image(run):
    context = run / 'image'
    runtime = context / 'root/runtime'
    runtime.mkdir(parents=True)
    for binary in (HOST, TOR):
        output = subprocess.check_output(['ldd', str(binary)], text=True)
        for line in output.splitlines():
            for item in line.split():
                if item.startswith('/'):
                    path = pathlib.Path(item)
                    dest = context / 'root/usr/lib/x86_64-linux-gnu' / path.name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path.resolve(), dest)
    shutil.copy2(HOST, runtime / 'host')
    shutil.copy2(TOR, runtime / 'tor')
    shutil.copy2(PACKAGE / 'role.py', runtime / 'role.py')
    shutil.copy2(PACKAGE / 'observe.py', runtime / 'observe.py')
    shutil.copy2(PACKAGE / 'network-request.py', runtime / 'network_request.py')
    transport = context / 'root' / str(PACKAGE / 'network-request.py').lstrip('/')
    transport.parent.mkdir(parents=True)
    # The actor opens CARGO_MANIFEST_DIR/../network-request.py: the host
    # directory must exist even though the transport lives one level above it.
    (transport.parent / 'host').mkdir()
    shutil.copy2(PACKAGE / 'network-request.py', transport)
    (context / 'Dockerfile').write_text('FROM python:3.14-slim\nCOPY root/ /\nENV PYTHONDONTWRITEBYTECODE=1\n')
    name = 'kpi-separated-withdrawal:' + run.name
    with (run / 'image-build.log').open('x') as log:
        command(['docker', 'build', '--pull=false', '-t', name, context], stdout=log, stderr=subprocess.STDOUT)
    return name

class Wallet:
    def __init__(self, container, direct):
        args = ['docker', 'exec', '-i', '-e', 'RAYON_NUM_THREADS=2', '-e', 'OMP_NUM_THREADS=2']
        if direct:
            args += ['-e', 'KPI_TEST_DIRECT_SERVICE=' + direct]
        self.proc = subprocess.Popen(args + [container, '/runtime/host', 'actor', '/state/wallet', '/public/parameters.bin'],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def call(self, r):
        self.proc.stdin.write(json.dumps(r) + '\n')
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError(self.proc.stderr.read())
        return json.loads(line)['result']

    def close(self):
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.terminate()

def arm(run, mode, img, configuration):
    out = run / mode
    out.mkdir()
    network = 'kpi-separated-' + mode + '-' + run.name[:8]
    command(['docker', 'network', 'create', network], stdout=subprocess.DEVNULL)
    names, wallets, logs, service_process = [], [], [], None
    try:
        for role in ['service', 'wallet-0', 'wallet-1', 'wallet-2', 'wallet-3']:
            volume = out / role
            volume.mkdir(mode=0o700)
            name = network + '-' + role
            names.append(name)
            args = ['docker', 'run', '-d', '--name', name, '--network', network, '--user', '1000:1000',
                    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only',
                    '--tmpfs', '/tmp:rw,nosuid,nodev,mode=1777', '--mount', f'type=bind,src={volume},dst=/state']
            if role != 'service':
                args += ['--mount', f'type=bind,src={configuration["parameters"]},dst=/public/parameters.bin,readonly']
            args += [img, 'python3', '/runtime/role.py', 'service' if role == 'service' else 'wallet']
            command(args, stdout=subprocess.DEVNULL)
        print(mode, 'five isolated roles started; bootstrapping their own connections', flush=True)
        while not all((out / r / 'READY.json').exists() for r in ['service', 'wallet-0', 'wallet-1', 'wallet-2', 'wallet-3']):
            for name in names:
                running = subprocess.check_output(['docker', 'inspect', '--format', '{{.State.Running}}', name], text=True).strip()
                if running != 'true':
                    raise RuntimeError('role stopped: ' + name)
            time.sleep(1)
        isolation = []
        # Actual denied reads/PID checks from the service, not host assertions.
        probe = "import os,json,pathlib;print(json.dumps({'walletHostPathVisible':pathlib.Path(" + repr(str(out / 'wallet-0/wallet/backup.json')) + ").exists(),'dockerSocketVisible':pathlib.Path('/var/run/docker.sock').exists(),'hostHomeVisible':pathlib.Path('/home/luke/.ssh').exists(),'pidNamespace':os.readlink('/proc/self/ns/pid'),'netNamespace':os.readlink('/proc/self/ns/net'),'uid':os.getuid()}))"
        for name in names:
            isolation.append(json.loads(subprocess.check_output(['docker', 'exec', name, 'python3', '-c', probe], text=True)))
        assert len({r['pidNamespace'] for r in isolation}) == len(names)
        assert len({r['netNamespace'] for r in isolation}) == len(names)
        assert all(not r['walletHostPathVisible'] and not r['dockerSocketVisible'] and not r['hostHomeVisible'] and r['uid'] == 1000 for r in isolation)
        write(out / 'ISOLATION.json', isolation)
        direct = names[0] if mode == 'direct' else None
        wallets = [Wallet(n, direct) for n in names[1:]]
        addresses = [w.call({'method': 'public'}) for w in wallets]
        write(out / 'addresses.json', addresses)
        command([HOST, 'init', out / 'addresses.json', out / 'state-0.json'])
        current = out / 'state-0.json'
        operations = []
        todo = [(0, {'method': 'credit'}),
                (0, {'method': 'transfer', 'inputValue': 4_000_000_000, 'amount': 2_000_000_000, 'recipient': addresses[1]}),
                (1, {'method': 'transfer', 'inputValue': 2_000_000_000, 'amount': 1_000_000_000, 'recipient': addresses[2]}),
                (0, {'method': 'transfer', 'inputValue': 2_000_000_000, 'amount': 1_000_000_000, 'recipient': addresses[3]})]
        for i, (who, r) in enumerate(todo):
            response = wallets[who].call(dict(r, state=read(current)['state']))
            opfile = out / f'payment-{i}.json'
            write(opfile, response['operations'])
            operations.extend(response['operations'])
            next_state = out / f'state-{i+1}.json'
            command([HOST, 'apply', current, opfile, next_state])
            current = next_state
        print(mode, 'actual private payments verified', flush=True)
        service = out / 'service'
        command([HOST, 'round', current, service / 'round'])
        cfg = read(service / 'round/config.json')
        configs = [copy.deepcopy(cfg) for _ in range(3)]
        if mode == 'tagged':
            for c in configs:
                c['round'] = list(secrets.token_bytes(32))
            write(service / 'configs.json', configs)
        service_log = (out / 'service-stderr.log').open('x')
        logs.append(service_log)
        cmd = ['docker', 'exec', names[0], '/runtime/host']
        cmd += (['tagged-serve', '/state/configs.json'] if mode == 'tagged' else ['serve', '/state/round/config.json'])
        cmd += ['/state/round/private/issuer.der', '/state/operator.jsonl', '19090']
        service_process = subprocess.Popen(cmd, stdout=service_log, stderr=subprocess.STDOUT)
        while 'COORDINATOR_READY' not in (out / 'service-stderr.log').read_text():
            if service_process.poll() is not None:
                raise RuntimeError('issuer stopped')
            time.sleep(0.1)
        onion = (service / 'tor/onion/hostname').read_text().strip()
        known_claims = {}
        for who in [2, 0, 1]:
            r = wallets[who].call({'method': 'registration-issue', 'config': configs[who], 'state': read(current)['state'], 'onion': onion, 'socks': 19050})
            known_claims[str(who)] = bytes(r['nullifier']).hex()
        write(out / 'known-claims.json', known_claims)
        # Simultaneous start, independently delayed within each wallet. No
        # per-wallet start timestamps or controller IPC enter the service view.
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            jobs = [pool.submit(wallets[who].call, {'method': 'registration-redeem', 'config': configs[who], 'onion': onion, 'socks': 19050}) for who in range(3)]
            for job in jobs:
                assert job.result()['redeemed']
        command([HOST, 'intent', current, service / 'operator.jsonl', out / 'intent.json'])
        intent = read(out / 'intent.json')
        approvals = []
        for who in range(3):
            approvals.extend(wallets[who].call({'method': 'approve', 'intent': intent, 'state': read(current)['state']})['operations'])
        approvals.sort(key=lambda o: o['statement']['nullifier'])
        write(out / 'approvals.json', approvals)
        command([HOST, 'check', current, out / 'intent.json', out / 'approvals.json', configuration['settlement'], out / 'KERNEL.json'])
        # Export service-visible data only; observer has no host network or
        # private volumes. Freeze predictions BEFORE collecting client truth.
        view = out / 'observer-view'
        view.mkdir()
        for src, name in [(service / 'operator.jsonl', 'operator.jsonl'), (service / 'direct-network.jsonl', 'direct-network.jsonl'), (service / 'configs.json', 'configs.json')]:
            if src.exists():
                shutil.copy2(src, view / name)
        shutil.copy2(out / 'intent.json', view / 'intent.json')
        shutil.copy2(out / 'approvals.json', view / 'approvals.json')
        shutil.copy2(current, view / 'state.json')
        predicted = out / 'prediction'
        predicted.mkdir()
        command(['docker', 'run', '--rm', '--network', 'none', '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only',
                 '--mount', f'type=bind,src={view},dst=/view,readonly', '--mount', f'type=bind,src={predicted},dst=/prediction',
                 img, 'python3', '/runtime/observe.py', '/view', '/prediction/PREDICTION.json'])
        sealed = hashlib.sha256((predicted / 'PREDICTION.json').read_bytes()).hexdigest()
        write(out / 'PREDICTION-SEAL.json', {'sha256': sealed, 'sealedUnix': time.time(), 'truthCollected': False})
        # Truth is collected AFTER the seal, from each owner-local registration.
        truth = {}
        for who in range(3):
            client = read(out / f'wallet-{who}/wallet/registration.json')
            claim = bytes(client['issue']['operation']['statement']['nullifier']).hex()
            key = bytes.fromhex(client['message'])[-32:].hex()
            assert known_claims[str(who)] == claim
            truth[claim] = key
        write(out / 'TRUTH-PRIVATE.json', truth)
        prediction = read(predicted / 'PREDICTION.json')
        assert truth in prediction['compatibleMappings']
        correct = sum(truth[c] == k for c, k in prediction['exactServiceFacts'].items())
        timing = sum(truth[c] == k for c, k in prediction['issueRedemptionRankGuess'].items())
        known = list(sorted(truth))
        counts = []
        for n in (1, 2, 3):
            facts = {c: truth[c] for c in known[:n]}
            counts.append(sum(all(cand[c] == k for c, k in facts.items()) for cand in prediction['compatibleMappings']))
        result = {'mode': mode, 'kernel': read(out / 'KERNEL.json'), 'exactCorrectOwnerKeyLinks': correct,
                  'compatibleMappings': prediction['compatibleMappingCount'], 'rankGuessCorrectLinks': timing,
                  'truthRetained': True, 'predictionSealedBeforeTruth': True, 'predictionSha256': sealed,
                  'oneOwnerKnownMappings': counts[0], 'twoOwnersKnownMappings': counts[1], 'allOwnersKnownMappings': counts[2],
                  'independentPhysicalMachines': False, 'chainBroadcast': False, 'consensusChanges': False}
        write(out / 'RESULT.json', result)
        print(mode, json.dumps(result), flush=True)
        return result
    finally:
        for w in wallets:
            w.close()
        for name in names:
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if service_process:
            service_process.wait(timeout=20)
        for f in logs:
            f.close()
        subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('new_private_run', type=pathlib.Path)
    a = p.parse_args()
    run = a.new_private_run.resolve()
    run.mkdir(mode=0o700, parents=True)
    configuration = read(ROOT / '.local/cached-approval-verification/COMBINED.json')
    inputs = [p for p in PACKAGE.rglob('*') if p.is_file() and 'target' not in p.parts and '__pycache__' not in p.parts]
    inputs += [ROOT / 'research/separated-withdrawal-2026-11-07/SELECTION.md', HOST]
    write(run / 'SOURCE-FREEZE.json', {'files': [{'path': str(p.relative_to(ROOT)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in inputs],
                                      'selectedBeforeFreshObservations': True})
    img = image(run)
    write(run / 'IMAGE.json', {'tag': img, 'id': subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', img], text=True).strip()})
    results = [arm(run, mode, img, configuration) for mode in ('direct', 'honest', 'tagged')]
    assert results[0]['exactCorrectOwnerKeyLinks'] == 3
    assert results[1]['compatibleMappings'] == 6
    failed = results[2]['exactCorrectOwnerKeyLinks'] == 3 and results[2]['kernel']['payoutSompi'] == 3_000_000_000
    write(run / 'RESULT.json', {'arms': results, 'privacyGatePassed': not failed, 'costWorkStarted': False,
                              'conclusion': 'configuration agreement is not enforced by current wallet authorization' if failed else 'review bounded privacy evidence before costs'})

if __name__ == '__main__':
    main()
