#!/usr/bin/env python3
"""Prepare only public synthetic cases; no wallet or private witness is read."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
BASE = ROOT / '.local/private-batch-exit-component-probe-01'
OUT = ROOT / '.local/private-batch-exit-component-controls-01'
PROOFS = Path('/run/user/1000/kpb-native-exit-component-proofs-20261028-04')
CLASS = 'UNFUNDED_EXIT_COMPONENT_ONLY_UNSELECTED_PAYMENT_METADATA'
read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
OUT.mkdir(mode=0o700)
public = OUT / 'public'
public.mkdir(mode=0o700)
(OUT / 'out').mkdir(mode=0o700)
records = {}


def save(name, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    with (public / name).open('xb') as output:
        output.write(raw)
    return {'path': '/public/' + name, 'sha256': hashlib.sha256(raw).hexdigest()}


def admit(name, path, sha=None, executable=False):
    raw = read(path, sha) if sha else read(path)
    with (public / name).open('xb') as output:
        output.write(raw)
    (public / name).chmod(0o500 if executable else 0o400)
    record = {'path': '/public/' + name, 'sha256': hashlib.sha256(raw).hexdigest()}
    records[name] = record
    return raw


admit('exit-component-probe', BASE / 'exit-component-probe',
      '88e12978651e456d7a192b8681d56b3c9f7978cddf180f0bf298d88852ccb3fc', True)
admit('native-validator', BASE / 'native-validator',
      '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061', True)
params = json.loads(admit('PARAMETERS.json', BASE / 'PARAMETERS.json',
      'c3d8866c55180991091b4f4b3f6c55ffbe29a6764924414d22488f27b22c169b'))
emission = json.loads(admit('EMITTED-POLICY.json', BASE / 'EMITTED-POLICY.json',
      'bf72f64b0fef0c306f9abd0a0eb3cc50bd98e505801d930b78ec2191b52d9cec'))
admit('AUTH-EXIT-MANIFEST.json', BASE / 'AUTH-EXIT-MANIFEST.json',
      'bc41c97e06f07a06ee9ab2af59ef1ba8c5190a126dfb0eb120d586667aaddd8f')
for name in ('run_native_controls.py', 'run_exit_component_controls.py'):
    admit(name, ROOT / 'poc/local-private-payment/private-batch-public/native' / name)
admit('PREPARE-CONTROLS.py', Path(__file__))
inputs = {}
for branch, name, sha in (
    ('terminal', 'terminal-200M-PROOF-INPUT.json', '5e9a2336904d86eb0a06ffa234a1dd159ab04e977546f2f275fea27eed3f3f42'),
    ('continuing', 'continuing-260M-PROOF-INPUT.json', '6a5296b85fd0459ca7ce103a20041a2b88365cc751fe0cad6ce89f29b1ae89d9')):
    inputs[branch] = json.loads(admit(name, PROOFS / name, sha))


def codec(operation, case=None, state=None):
    request = {'operation': operation, 'parameters': params}
    request.update({'case': case} if case is not None else {'state_hex112': state})
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
        '--clearenv', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--ro-bind', '/etc/alternatives', '/etc/alternatives', '--proc', '/proc',
        '--dev', '/dev', '--tmpfs', '/tmp', '--ro-bind', str(public / 'exit-component-probe'),
        '/public/exit-component-probe', '/public/exit-component-probe']
    result = subprocess.run(command, input=json.dumps(request).encode(), capture_output=True, check=True)
    return json.loads(result.stdout)


def witness(proof, emitted=emission):
    raw = bytearray.fromhex(emitted['zero_proof_witness_hex'])
    assert raw[:2] == b'\x4c\x80' and len(proof) == 128
    raw[2:130] = proof
    return raw.hex()


def prepare(value):
    projection = bytes.fromhex(value['projection_hex'])
    body = bytes.fromhex(value['body_hex1604'])
    assert projection[-1604:] == body and value['old_state_hex112'] == emission['state_hex112']
    assert value['actual_proof_public_verification'] is True and value['fresh_owner_authorization'] is True
    prefix = projection[:-1604]
    outputs, at = [], 105
    for _ in range(int.from_bytes(prefix[103:105], 'little')):
        amount = int.from_bytes(prefix[at:at+8], 'little')
        width = int.from_bytes(prefix[at+8:at+10], 'little')
        outputs.append({'value': amount, 'scriptPublicKey': prefix[at+10:at+10+width].hex(), 'covenant': None})
        assert prefix[at+10+width] == 0
        at += 11 + width
    assert at + 40 == len(prefix)
    case = {'transaction': {'version': 1, 'id': '00'*32, 'inputs': [{
        'previousOutpoint': {'transactionId': prefix[12:44].hex(), 'index': int.from_bytes(prefix[44:48], 'little')},
        'signatureScript': witness(bytes.fromhex(value['proof_hex128'])),
        'sequence': 2**64-1, 'computeBudget': 1800}], 'outputs': outputs,
        'lockTime': 0, 'subnetworkId': '00'*20, 'gas': 0, 'payload': body.hex(), 'mass': 0},
        'entries': [{'amount': int.from_bytes(prefix[56:64], 'little'), 'scriptPublicKey': prefix[66:103].hex(),
        'blockDaaScore': 0, 'isCoinbase': False, 'covenantId': None}]}
    result = codec('normalize', case)
    assert result['financial_projection_hex'] == value['projection_hex']
    assert result['exit_statement_hex152'] == value['statement_hex152']
    assert result['metrics']['actual_fee_sompi'] == value['fee_sompi']
    assert result['metrics']['actual_fee_sompi'] >= result['metrics']['mining_mass'] * 100
    return result['case']


baselines = {branch: prepare(value) for branch, value in inputs.items()}
cases, semantics = [], {}


def add(identity, case, expected, meaning):
    cases.append({'id': identity, 'mode': 'exit', 'expected': expected,
                  'case': save(identity + '.json', case)})
    semantics[identity] = meaning


for branch, baseline in baselines.items():
    add(branch + '-positive', baseline, 'accept', 'Genuine AuthExit proof against exact actual native projection, supplied unfunded context only.')
    for name in ('payout', 'destination', 'fee-body', 'wrong-head', 'wrong-domain', 'wrong-pool',
                 'corrupt-proof', 'cross-context-valid-proof', 'spent-state-nullifier-replay'):
        case = copy.deepcopy(baseline)
        tx = case['transaction']
        payout = tx['outputs'][-1]
        meaning = 'Actual ScriptEngine rejection of ' + name + ' with cached ID/storage mass alone canonicalized.'
        if name == 'payout':
            payout['value'] -= 1
        elif name == 'destination':
            raw = bytearray.fromhex(payout['scriptPublicKey']); raw[3] ^= 1; payout['scriptPublicKey'] = raw.hex()
        elif name == 'fee-body':
            raw = bytearray.fromhex(tx['payload']); raw[360:368] = (inputs[branch]['fee_sompi']+1).to_bytes(8,'little');tx['payload'] = raw.hex()
        elif name == 'wrong-head':
            raw = bytearray.fromhex(tx['inputs'][0]['previousOutpoint']['transactionId']);raw[0] ^= 1;tx['inputs'][0]['previousOutpoint']['transactionId'] = raw.hex()
        elif name in ('wrong-domain', 'wrong-pool'):
            raw = bytearray.fromhex(tx['payload']);raw[104 if name == 'wrong-domain' else 40] ^= 1;tx['payload'] = raw.hex()
        elif name == 'corrupt-proof':
            raw = bytearray.fromhex(tx['inputs'][0]['signatureScript']);raw[2] ^= 1;tx['inputs'][0]['signatureScript'] = raw.hex()
        elif name == 'cross-context-valid-proof':
            other = inputs['continuing' if branch == 'terminal' else 'terminal']
            tx['inputs'][0]['signatureScript'] = witness(bytes.fromhex(other['proof_hex128']))
        else:
            post = codec('emit', state=inputs[branch]['new_state_hex112'])
            case['entries'][0]['scriptPublicKey'] = post['script_public_key']
            tx['inputs'][0]['signatureScript'] = witness(bytes.fromhex(inputs[branch]['proof_hex128']), post)
            meaning = 'Stale/spent-state NF context: actual entry/redeem is post-exit NFroot/count while old body/proof remains; not an isolated in-circuit nonmembership test.'
        add(branch + '-' + name, case, 'reject', meaning)

case = copy.deepcopy(baselines['continuing'])
raw = bytearray.fromhex(case['transaction']['outputs'][0]['scriptPublicKey']);raw[4] ^= 1
case['transaction']['outputs'][0]['scriptPublicKey'] = raw.hex()
add('continuing-successor-policy-substitution', case, 'reject', 'Actual continuation P2SH differs from exact expected successor policy/state.')
case = copy.deepcopy(baselines['continuing'])
case['transaction']['outputs'][-1]['value'] += case['transaction']['outputs'][0]['value']
case['transaction']['outputs'].pop(0)
add('continuing-missing-reserve-output', case, 'reject', 'Remove expected continuation while preserving aggregate output value/fee.')
case = copy.deepcopy(baselines['terminal'])
post = codec('emit', state=inputs['terminal']['new_state_hex112'])
case['transaction']['outputs'][-1]['value'] -= 60000000
case['transaction']['outputs'].insert(0, {'value': 60000000, 'scriptPublicKey': post['script_public_key'], 'covenant': None})
add('terminal-unexpected-reserve-output', case, 'reject', 'Add unexpected continuation while preserving aggregate output value/fee.')
vm = {'schema': 'private-batch-native-vm-controls/v1', 'scope': 'exit',
      'engine': records['native-validator'], 'codec': records['exit-component-probe'],
      'parameters': records['PARAMETERS.json'], 'cases': cases}
plan = {'schema': 'private-batch-unfunded-exit-component-controls/v1', 'classification': CLASS,
        'payment_profile_selected': False, 'auth_exit_parameter_manifest': records['AUTH-EXIT-MANIFEST.json'],
        'expected_auth_exit_source_sha256': 'ccd4e28a728cbf8ffd6db0dd0fa81a6200c0c6e4ecb20242435f00e5b6aae19e',
        'expected_auth_exit_matrix_sha256': '9fbedc0628a6afb592f03a0ceda9825924f7d8bd76fe49785b6252237affc149',
        'reference_fee_rate_sompi_per_mass': 100, 'native_vm_plan': vm}
selected = save('PLAN.json', plan)
receipt = save('PREPARATION.json', {'schema': 'public-unfunded-exit-controls-preparation/v1',
        'classification': CLASS, 'plan': selected, 'source_and_inputs': records,
        'case_semantics': semantics, 'case_count': len(cases), 'payment_profile_selected': False,
        'VM_execution': False, 'funding_or_broadcast': False})
print(json.dumps({'plan': selected, 'preparation': receipt, 'case_count': len(cases)}))
