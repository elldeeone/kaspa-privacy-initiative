"""Public controls for the one explicit, proven never-attempted submission."""
import copy
import json
from pathlib import Path
import runpy
import subprocess
import unittest
from unittest.mock import patch

import campaign
import first_submit


class FirstSubmitControls(unittest.TestCase):
    def test_service_metadata_query_has_explicit_public_user_bus_without_changing_submission_env(self):
        result = subprocess.CompletedProcess([], 0, stdout='MainPID=0\nActiveState=inactive\n')
        with patch.object(first_submit.subprocess, 'run', return_value=result) as invoke:
            first_submit.stopped()
        self.assertEqual(invoke.call_args.kwargs['env'], dict(first_submit.CLEAN,
            XDG_RUNTIME_DIR='/run/user/' + str(first_submit.os.getuid())))
        self.assertNotIn('XDG_RUNTIME_DIR', first_submit.CLEAN)

    def test_exact_no_attempt_refusal_rejects_unknown_or_consumed_outcomes(self):
        value = {'schema': 'kpxa-single-native-submission/v1', 'trial_id': first_submit.TRIAL,
            'stage': first_submit.STAGE, 'transaction_id': first_submit.TXID,
            'status': 'INCOMPLETE_QUERY_ONLY', 'durable_intent_reserved': False,
            'submission_attempted': False, 'automatic_resubmission_permitted': False,
            'confirmation_claimed': False, 'stage_already_used': False, 'category': 'INTENT'}
        first_submit.no_attempt(value)
        for key, replacement in [('submission_attempted', True), ('durable_intent_reserved', True),
            ('stage_already_used', True), ('category', 'PUBLIC_RPC_OR_INTENT_UNAVAILABLE'),
            ('status', 'RPC_UNKNOWN_QUERY_ONLY'), ('submission_attempted', 0), ('stage', 'action-0002')]:
            with self.assertRaises(ValueError):
                first_submit.no_attempt(dict(value, **{key: replacement}))

    def test_original_candidate_binds_exact_final_CASE(self):
        value = {'schema': 'kpxa-public-submit-candidate/v1', 'trial_id': first_submit.TRIAL,
            'stage': first_submit.STAGE, 'mode': 'lifecycle', 'case_sha256': first_submit.CASE['sha256'],
            'transaction': {'id': first_submit.TXID}, 'actual_native_Full_passed': True,
            'broadcast_performed': False}
        first_submit.same_candidate(value)
        for key, replacement in [('case_sha256', '00' * 32), ('trial_id', 'other'),
                                 ('actual_native_Full_passed', False), ('broadcast_performed', True)]:
            with self.assertRaises(ValueError):
                first_submit.same_candidate(dict(value, **{key: replacement}))

    def test_both_exact_global_intents_are_metadata_only_and_either_presence_refuses(self):
        with patch.object(first_submit, 'checked', lambda p: p), \
             patch.object(Path, 'lstat', side_effect=FileNotFoundError), \
             patch('builtins.open', side_effect=AssertionError('content-read')):
            targets = first_submit.absent_intents()
        self.assertEqual(targets, [str(campaign.PRIVATE / 'submission-intents' / first_submit.TRIAL /
            'stage-action-0001.intent.json'), str(campaign.PRIVATE / 'submission-transactions' /
            ('tx-' + first_submit.TXID + '.intent.json'))])
        for outcomes in ([object()], [FileNotFoundError(), object()]):
            with patch.object(first_submit, 'checked', lambda p: p), patch.object(Path, 'lstat', side_effect=outcomes):
                with self.assertRaisesRegex(ValueError, 'global-intent-already-exists'):
                    first_submit.absent_intents()

    def test_frozen_submitter_rejects_bad_namespace_before_writes_and_reserves_exact_two_O_EXCL(self):
        h = runpy.run_path(campaign.HELPER)
        source = h['read'](str(campaign.BASE / 'chain/submit.mjs'), first_submit.SUBMIT_SHA).decode()
        function = source[source.index('export function reserveIntent('):source.index('export async function transmitOnce(')]
        function = function.replace('export function reserveIntent(', 'function reserveIntent(', 1)
        # Execute the unchanged selected function with all filesystem effects
        # mocked; no private files/directories are read or written by this test.
        script = """
const path=require('node:path'), assert=require('node:assert/strict');
const PRIVATE=INPUT.private, writes=[], opens=[];
const fs={constants:{O_RDONLY:1,O_WRONLY:2,O_CREAT:4,O_EXCL:8,O_NOFOLLOW:16},
 mkdirSync(){},openSync(p,flags){opens.push([p,flags]);return opens.length;},
 fsyncSync(){},closeSync(){},writeFileSync(fd,raw){writes.push([opens[fd-1][0],raw]);}};
const checkedPath=p=>p,stringify=JSON.stringify;
const need=(ok,category)=>{if(!ok)throw Error(category);};
FUNCTION
const record={trial_id:INPUT.trial,transaction_id:INPUT.tx};
assert.throws(()=>reserveIntent(PRIVATE+'/fixture/submission-journal','action-0001',record),/INTENT/);
assert.equal(opens.length,0);assert.equal(writes.length,0);
const result=reserveIntent(PRIVATE+'/fixture/controller/submission-journal','action-0001',record);
assert.deepEqual(result,INPUT.targets);assert.equal(writes.length,2);
for(const [target] of writes)assert.equal(opens.find(([p])=>p===target)[1],2|4|8|16);
console.log('frozen reserveIntent: bad path zero writes; correct path two exact O_EXCL reservations');
""".replace('FUNCTION', function).replace('INPUT', json.dumps({'private': str(campaign.PRIVATE),
            'trial': first_submit.TRIAL, 'tx': first_submit.TXID, 'targets': [str(campaign.PRIVATE /
            'submission-intents' / first_submit.TRIAL / 'stage-action-0001.intent.json'),
            str(campaign.PRIVATE / 'submission-transactions' / ('tx-' + first_submit.TXID + '.intent.json'))]}))
        node = '/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node'
        result = subprocess.run([node, '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
