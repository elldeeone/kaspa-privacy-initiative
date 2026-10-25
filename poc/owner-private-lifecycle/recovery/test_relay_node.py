"""Exact relay Node worker with synthetic SDK/transport in network-off bwrap.

These controls test send sequencing/durable failures, not native cryptography.
The registry and strict JSON parser are the actual selected public sources.
"""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NODE = Path('/var/tmp/kpi-owner-private-lifecycle-01/assets/recovery-static-https-01/'
            'strict-unpack-stage-01/output/software/runtime/node')
SOURCE = ast.parse((HERE / 'relay_closed.py').read_bytes())
SPEC = importlib.util.spec_from_file_location('selected_relay_closed', HERE / 'relay_closed.py')
relay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relay)
WORKER = next(ast.literal_eval(item.value) for item in SOURCE.body
              if isinstance(item, ast.Assign) and any(isinstance(target, ast.Name)
              and target.id == 'NODE' for target in item.targets))
WIRE = '''import fs from 'node:fs';import crypto from 'node:crypto';
export const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
export const stringify=x=>JSON.stringify(x);
export const need=(x,c,m)=>{if(!x)throw Error(c+':'+m);};
export function event(v){let x=[];try{x=JSON.parse(fs.readFileSync('/out/events.json'));}catch{}x.push(v);fs.writeFileSync('/out/events.json',JSON.stringify(x));}
export function loadSdk(){return{RpcClient:class{async connect(){event('connect');}async disconnect(){event('disconnect');}}};}
'''
SUBMIT = '''import fs from 'node:fs';import{event}from'./wire.mjs';
export function makeTransaction(k,b,c){event('make');return{free(){event('free');}};}
let queries=0;
export async function queryInputs(){queries++;event('query'+queries);const c=JSON.parse(fs.readFileSync('/out/MOCK.json'));if(c.fail_second&&queries===2)throw Object.assign(Error('synthetic changed input'),{category:'STALE_INPUT'});return'123';}
export async function transmitOnce(){event('send');return JSON.parse(fs.readFileSync('/out/MOCK.json')).ack;}
'''


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


class Controls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='kpx8-public-relay-node-controls-')
        self.base = Path(self.temporary.name)
        self.software = self.base / 'software'
        self.registry = self.base / 'synthetic-registry'
        self.registry.mkdir(mode=0o700)
        chain = self.software / 'poc/owner-private-lifecycle/chain'
        recovery = self.software / 'poc/owner-private-lifecycle/recovery'
        chain.mkdir(parents=True)
        recovery.mkdir()
        (self.software / 'registry').mkdir(mode=0o700)
        (chain / 'wire.mjs').write_text(WIRE)
        (chain / 'submit.mjs').write_text(SUBMIT)
        (chain / 'selection.mjs').write_text("export{strictJson}from'./json.mjs';\n")
        parser = (ROOT / 'poc/owner-private-lifecycle/chain/json.mjs').read_bytes()
        self.assertEqual(hashlib.sha256(parser).hexdigest(),
                         '59e7b579ddd3a62e5af404b38051376044e3ae1e26c25bdb6e6c6cfd969da1f7')
        (chain / 'json.mjs').write_bytes(parser)
        source = (HERE / 'relay_registry.mjs').read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(),
                         '2e393021757e00b6c6a267e58a2ba6936fa0d2052846435d6a26272692f666e5')
        (recovery / 'relay_registry.mjs').write_bytes(source)
        self.handover = {
            'schema': 'kpx8-replacement-relay-handover/v1',
            'domain_hex32': 'be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480',
            'financial_profile_sha256': '69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f',
            'trial_id': '00000000-0000-4000-8000-000000000001',
            **{name: 'aa' * 32 for name in ('selection_sha256', 'descriptor_sha256',
               'history_sha256', 'checkpoint_sha256', 'current_entry_sha256')},
            'accepted_pool_prefix_txids': [format(i, '064x') for i in (4, 5, 6)],
            'used_submissions': [{'stage': stage, 'transaction_id': format(i, '064x'),
                                  'status': 'CONFIRMED'} for i, stage in enumerate((
                'consolidate-0', 'consolidate-1', 'consolidate-2', 'genesis', 'round-01', 'round-02'), 1)],
            'all_prior_pool_submissions_resolved': True,
            'original_coordinator_prover_and_writers_stopped': True}
        self.node_sha = hashlib.sha256(NODE.read_bytes()).hexdigest()
        self.counter = 0

    def tearDown(self):
        self.temporary.cleanup()

    def run_worker(self, *, operation='submit', stage='exit-new', tx='77' * 32,
                   point='88' * 32 + '00000000', ack=True, fail_second=False):
        self.counter += 1
        job = self.base / ('job-' + str(self.counter))
        job.mkdir()
        out = job / 'out'
        out.mkdir()
        inputs = job / 'inputs'
        inputs.mkdir()
        bootstrap = job / 'bootstrap'
        bootstrap.mkdir()
        (bootstrap / 'relay.mjs').write_text(WORKER)
        candidate = {'schema': 'kpx8-replacement-exit-candidate/v1', 'transaction': {'id': tx},
            'contexts': [], 'case_sha256': '99' * 32, 'trial_id': self.handover['trial_id'],
            'stage': stage, 'previous_outpoint_hex36': point, 'node_pin': self.node_sha,
            'actual_native_Full_and_input_engines_passed': True, 'full_accepted_prefix_replayed': True}
        raw = encoded(candidate)
        (out / 'SDK-CANDIDATE.json').write_bytes(raw)
        handover = encoded(self.handover)
        (inputs / 'handover.json').write_bytes(handover)
        (out / 'NODE-OPTIONS.json').write_bytes(encoded({'operation': operation,
            'candidate_sha256': hashlib.sha256(raw).hexdigest(),
            'handover_sha256': hashlib.sha256(handover).hexdigest(), 'rpc': 'wss://example.invalid/'}))
        (out / 'MOCK.json').write_bytes(encoded({'ack': ack, 'fail_second': fail_second}))
        command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session']
        for system in ('/usr', '/lib', '/lib64'):
            if Path(system).exists():
                command += ['--ro-bind', system, system]
        command += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--ro-bind', str(self.software), '/work', '--bind', str(self.registry), '/work/registry',
            '--ro-bind', str(bootstrap), '/bootstrap', '--ro-bind', str(inputs), '/inputs',
            '--bind', str(out), '/out', '--bind', str(out), '/scratch', '--ro-bind', str(NODE), '/node', '/node', '/bootstrap/relay.mjs']
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return json.loads((out / 'RELAY-RESULT.json').read_bytes()), json.loads((out / 'events.json').read_bytes())

    def test_check_has_no_query_reservation_or_send(self):
        result, events = self.run_worker(operation='check')
        self.assertEqual(result['status'], 'PREFLIGHT_ONLY_NO_SUBMISSION')
        self.assertEqual(events, ['make', 'free'])
        self.assertEqual(list(self.registry.iterdir()), [])

    def test_ack_exact_two_queries_and_one_send(self):
        result, events = self.run_worker()
        self.assertEqual(result['status'], 'SUBMITTED_ACKNOWLEDGED_QUERY_ONLY')
        self.assertEqual(events, ['make', 'connect', 'query1', 'query2', 'send', 'free', 'disconnect'])
        self.assertFalse(result['automatic_resubmission_permitted'])

    def test_unknown_and_restart_never_send_again(self):
        result, events = self.run_worker(ack=False)
        self.assertEqual(result['status'], 'RPC_UNKNOWN_QUERY_ONLY')
        self.assertEqual(events.count('send'), 1)
        result, events = self.run_worker(stage='another-stage')
        self.assertEqual(result['status'], 'INCOMPLETE_QUERY_ONLY')
        self.assertNotIn('send', events)

    def test_second_query_change_preserves_reservation_without_send(self):
        result, events = self.run_worker(fail_second=True)
        self.assertTrue(result['durable_intent_reserved'])
        self.assertFalse(result['submission_attempted'])
        self.assertNotIn('send', events)
        result, events = self.run_worker(stage='another-stage', tx='66' * 32)
        self.assertEqual(result['status'], 'INCOMPLETE_QUERY_ONLY')
        self.assertNotIn('send', events)

    def test_public_outcome_rejects_extra_mapping_and_untyped_fields(self):
        result, _ = self.run_worker()
        self.assertEqual(relay.public_result(encoded(result), 'exit-new', '99' * 32, '77' * 32), result)
        for key, value in (('participant_id', 'aa' * 32), ('durable_intent_reserved', 1),
                           ('automatic_resubmission_permitted', True)):
            changed = dict(result)
            changed[key] = value
            with self.assertRaises(relay.base.Refused):
                relay.public_result(encoded(changed), 'exit-new', '99' * 32, '77' * 32)
        changed = dict(result, status='INCOMPLETE_QUERY_ONLY', category='untrusted private/path text')
        with self.assertRaises(relay.base.Refused):
            relay.public_result(encoded(changed), 'exit-new', '99' * 32, '77' * 32)

    def test_original_stage_rejected_before_any_send(self):
        result, events = self.run_worker(stage='round-01')
        self.assertEqual(result['status'], 'INCOMPLETE_QUERY_ONLY')
        self.assertNotIn('query2', events)
        self.assertNotIn('send', events)


if __name__ == '__main__':
    unittest.main()
