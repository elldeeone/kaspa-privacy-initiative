"""Known-public controls. No real RPC, private inputs, intents or signals."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import first_submit8 as helper


class FirstSubmit8Controls(unittest.TestCase):
    def no_attempt(self):
        return {'schema':'kpxa-single-native-submission/v1','trial_id':helper.TRIAL,'stage':helper.STAGE,
            'transaction_id':helper.TXID,'status':'INCOMPLETE_QUERY_ONLY','durable_intent_reserved':False,
            'submission_attempted':False,'automatic_resubmission_permitted':False,'confirmation_claimed':False,
            'stage_already_used':False,'category':'PUBLIC_RPC_OR_INTENT_UNAVAILABLE'}

    def test_only_exact_pinned_no_attempt_is_admitted(self):
        helper.no_attempt(self.no_attempt())
        for key,value in [('stage','action-0009'),('transaction_id','00'*32),
            ('submission_attempted',True),('durable_intent_reserved',0),('category','INTENT')]:
            bad=self.no_attempt();bad[key]=value
            with self.assertRaises(ValueError):helper.no_attempt(bad)

    def test_original_candidate_and_native_must_bind_exact_whole_case(self):
        c={'schema':'kpxa-public-submit-candidate/v1','trial_id':helper.TRIAL,'stage':helper.STAGE,
            'mode':'lifecycle','case_sha256':helper.CASE['sha256'],'transaction':{'id':helper.TXID},
            'actual_native_Full_passed':True,'broadcast_performed':False}
        n={'native_Full_accepted':True,'all_input_scripts_accepted':True,'mode':'direct-exit',
            'transaction_id':helper.TXID,'validated_case_sha256':helper.CASE['sha256']}
        case={'transaction':{'id':helper.TXID}}
        helper.same_financial_evidence(c,n,case)
        for group,key,value in [('candidate','case_sha256','00'*32),('candidate','actual_native_Full_passed',False),
            ('candidate','broadcast_performed',True),('native','all_input_scripts_accepted',False),
            ('native','validated_case_sha256','11'*32),('native','mode','mixed-attach')]:
            a,b=copy.deepcopy(c),copy.deepcopy(n)
            (a if group=='candidate' else b)[key]=value
            with self.assertRaises(ValueError):helper.same_financial_evidence(a,b,case)

    def test_root_held_identity_requires_pid_start_invocation_and_kernel_T(self):
        u={'MainPID':str(helper.PID),'ActiveState':'active','InvocationID':helper.INVOCATION,
            'ExecMainStartTimestampMonotonic':helper.UNIT_START}
        helper.held_identity(u,'T',helper.KERNEL_START)
        for key,value in [('MainPID','1'),('ActiveState','inactive'),('InvocationID','old'),
            ('ExecMainStartTimestampMonotonic','0')]:
            with self.assertRaises(ValueError):helper.held_identity(dict(u,**{key:value}),'T',helper.KERNEL_START)
        for state,ticks in [('S',helper.KERNEL_START),('T','0')]:
            with self.assertRaises(ValueError):helper.held_identity(u,state,ticks)

    def test_global_intent_targets_exact_and_either_existing_blocks_before_read(self):
        targets=helper.intent_targets()
        self.assertEqual(targets[0],helper.PRIVATE/'submission-intents'/helper.TRIAL/'stage-action-0008.intent.json')
        self.assertEqual(targets[1],helper.PRIVATE/'submission-transactions'/('tx-'+helper.TXID+'.intent.json'))
        with patch.object(helper,'checked',side_effect=lambda p:p), \
             patch.object(Path,'lstat',side_effect=FileNotFoundError), \
             patch.object(Path,'open',side_effect=AssertionError('private-content-read')):
            helper.absent_intents()
        for results in ([object()],[FileNotFoundError(),object()]):
            with patch.object(helper,'checked',side_effect=lambda p:p), \
                 patch.object(Path,'lstat',side_effect=results), \
                 patch.object(Path,'open',side_effect=AssertionError('private-content-read')):
                with self.assertRaises(ValueError):helper.absent_intents()

    def test_args_select_current_head7_and_explicit_electron_without_fallback(self):
        def r(n):return {'path':'/known-public/'+n,'sha256':'11'*32}
        activation={k:r(k) for k in ('selection','descriptor','assets','parameters','codec')}
        selection={'node':r('node'),'activation':r('ACTIVATION.json'),
            'cache_policy':{'runtime_source':r('runtime'),'admission':r('admission')}}
        head={'selectors':{'fetch.json':r('HEAD7/fetch.json'),'CACHE.json':r('HEAD7/CACHE.json')}}
        with patch.object(helper,'public_read',side_effect=lambda row:json.dumps(activation).encode()):
            argv=helper.arguments(selection,head,Path('/known-public/out'),execute=True)
        self.assertEqual(argv[:2],[selection['node']['path'],helper.SUBMIT['path']])
        for flag,value in [('--stage','action-0008'),('--case-sha256',helper.CASE['sha256']),
            ('--rpc',helper.ENDPOINT),('--fetch',head['selectors']['fetch.json']['path']),
            ('--baseline-fetch',head['selectors']['fetch.json']['path']),('--pool-selection-sha256',helper.POOL['sha256'])]:
            self.assertEqual(argv[argv.index(flag)+1],value)
        self.assertEqual(argv.count('--execute'),1)
        self.assertIn('/controller/',argv[argv.index('--journal')+1])
        self.assertNotIn('--fallback',argv)

    def test_one_child_only_and_separate_operator_lock_preserves_caller_lock(self):
        events=[]
        with tempfile.TemporaryDirectory(prefix='known-public-submit8-control-') as directory:
            control=Path(directory);out=control/'attempt'
            with (
                patch.object(helper,'CONTROL',control), patch.object(helper,'evidence',return_value=({},{})),
                patch.object(helper,'held_gate',side_effect=lambda:events.append('held')),
                patch.object(helper,'absent_intents',side_effect=lambda:events.append('absent')),
                patch.object(helper,'arguments',return_value=['KNOWN-PUBLIC-CHILD']),
                patch.object(helper.subprocess,'run',side_effect=lambda *a,**k:events.append('one-child') or SimpleNamespace(returncode=2)) as child,
                patch.object(helper.os,'kill',side_effect=AssertionError('signal-forbidden')),
            ):
                value=helper.run(out,execute=True)
            self.assertEqual(value['returncode'],2)
            self.assertEqual(child.call_count,1)
            self.assertEqual(events,['held','absent','held','absent','one-child'])
            self.assertTrue((control/'FIRST-SUBMIT8-OPERATOR-LOCK').exists())
            self.assertFalse((control/'CALLER-LOCK').exists())
            self.assertFalse(value['automatic_retry_or_resubmission_permitted'])

    def test_failed_hold_never_reaches_child_or_mutates_state(self):
        with patch.object(helper,'evidence',return_value=({},{})), \
             patch.object(helper,'held_gate',side_effect=ValueError('not-held')), \
             patch.object(helper.subprocess,'run',side_effect=AssertionError('child-forbidden')):
            with self.assertRaises(ValueError):helper.run(Path('/known-public/unused'),execute=True)


if __name__=='__main__':unittest.main()
