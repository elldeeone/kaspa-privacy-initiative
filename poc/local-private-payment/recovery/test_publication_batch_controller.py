"""Controller seam controls on a public model, with all writes/workers mocked.

No Original stat/read, namespace, network, actual producer or Original worker.
The prepared launcher has its own separately retained real PUBLIC controls.
"""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import publication_batch_audit as a
import publication_batch_controller as c
from test_publication_batch_audit import fixture, PREPARED


def value(f):
    return {'index':{'path':'/known-public/INDEX.json','sha256':f['index_sha']},
        'batch_plan':{'path':'/known-public/PLAN.json','sha256':f['plan_sha']},
        'launcher':{'path':'/known-public/c465.py','sha256':a.LAUNCHER},
        'prepared_launcher':{'path':'/known-public/prepared.py','sha256':PREPARED},
        'canary_assets':f['canary_assets'],'originals':f['originals'],'run_label':'public-model'}


def primary(f,v):
    return {'schema':'kpxa-publication-primary-audit-checkpoint/v1','execution_plan_value':v,
        'index':f['index'],'plan':f['plan'],'contexts':f['contexts'],'coverage':f['coverage'],
        'batches':f['batches'],'invocations':[i for i in f['invocations'] if i['batch_id']!='DESCRIPTORS'],
        'descriptor_release':{'path':'/known-public/initial-stage.json','sha256':'77'*32}}


def unprepared_stage(f):
    return {k:v for k,v in f['descriptor_stage'].items() if k not in ('release_sha256','preparation')}


class Controls(unittest.TestCase):
    def test_one_prepared_call_retains_exact_original_metadata_without_opening_it(self):
        f=fixture();v=value(f);expected=f['invocations'][0];record=f['batches'][0];calls=[];saved=[]
        def execute(args,cohort,identity):
            calls.append((vars(args),cohort,identity))
            return {'summary':expected['summary'],'workers':expected['worker_receipts'],
                'public_preparation_provenance':record['preparation']['provenance'],'worker_pair_wall_seconds':1.125}
        with patch.object(c.audit,'save',side_effect=lambda p,v:saved.append((p,v))):
            result=c.audit_one(v,f['originals'][0],record['descriptor'],record['descriptor_row'],
                record['releases']['creation'],f['contexts']['creation'],Path('/known-public/out'),
                SimpleNamespace(execute=execute),record['preparation'])
        self.assertEqual(len(calls),1);self.assertEqual(len(saved),2)
        self.assertEqual(calls[0][0]['original_inode'],f['originals'][0]['inode'])
        self.assertEqual(calls[0][1:],('creation','audit-public-model-base-o01'))
        self.assertEqual(result['workers'],expected['workers'])

    def test_substituted_prepared_result_refused_before_saved_success(self):
        f=fixture();v=value(f);record=f['batches'][0];expected=f['invocations'][0]
        result={'summary':expected['summary'],'workers':expected['worker_receipts'],
            'public_preparation_provenance':copy.deepcopy(record['preparation']['provenance']),'worker_pair_wall_seconds':1}
        result['public_preparation_provenance']['prepared_launcher_source_sha256']='99'*32
        with patch.object(c.audit,'save') as save:
            with self.assertRaises(ValueError):c.audit_one(v,f['originals'][0],record['descriptor'],record['descriptor_row'],
                record['releases']['creation'],f['contexts']['creation'],Path('/known-public/out'),
                SimpleNamespace(execute=lambda *_:result),record['preparation'])
            save.assert_not_called()

    def test_resume_checks_full_primary_and_all_supplemental_bytes_before_new_job(self):
        for change in ('none','missing-primary','wrong-plan','wrong-context','wrong-descriptor','missing-mandatory','changed-extra'):
            with self.subTest(change=change):
                f=fixture();v=value(f);p=primary(f,v);stage=unprepared_stage(f)
                if change=='missing-primary':p['invocations'].pop()
                if change=='wrong-plan':p['plan']['operator_decoded_budget_bytes']=101
                if change=='wrong-context':p['contexts']['actual02']['scope_document']['roles']['history']['sha256']='99'*32
                if change=='wrong-descriptor':stage['required_public_metadata']['plan']['sha256']='99'*32
                if change=='missing-mandatory':stage['files'].pop()
                if change=='changed-extra':stage['files'][0]['bytes']+=1
                pr={'path':'/known-public/primary.json','sha256':a.sha(a.encoded(p))}
                sr={'path':'/known-public/stage.json','sha256':a.sha(a.encoded(stage))}
                selected={'schema':'kpxa-publication-descriptor-resume-release/v1',
                    'execution_plan':{'path':'/known-public/EXECUTION.json','sha256':'88'*32},'primary_journal':pr,'descriptor_release':sr}
                rr={'path':'/known-public/RESUME.json','sha256':a.sha(a.encoded(selected))}
                docs={rr['path']:a.encoded(selected),pr['path']:a.encoded(p),sr['path']:a.encoded(stage)}
                for file in stage['files']:docs[file['source']]=b'x'*file['bytes']
                # Actual source authentication is tested in helper/producer. This
                # explicit identity oracle isolates controller order and joins.
                fresh=RuntimeError('REACHED_ONLY_PUBLIC_GATES')
                with patch.object(c,'load_plan',return_value=(v,f['index'],f['plan'],f['contexts'],f['coverage'])), \
                    patch.object(c.audit,'guarded',side_effect=lambda row:docs[row['path']]), \
                    patch.object(c,'fresh_control_output',side_effect=fresh) as create, \
                    patch.object(c,'selected_module') as module:
                    with self.assertRaises((ValueError,RuntimeError)) as failure:c.resume_descriptors(rr,Path('/known-public/fresh'))
                    module.assert_not_called()
                    if change=='none':self.assertIs(failure.exception,fresh);create.assert_called_once()
                    else:create.assert_not_called()

    def test_supplemental_preparation_reuses_primary_without_original_jobs(self):
        f=fixture();v=value(f);p=primary(f,v);extra={'source':'/known-public/DATA-PARTS.json',
            'path':'public-descriptors/DATA-PARTS.json','bytes':17,'sha256':'55'*32}
        selected={'schema':'kpxa-publication-descriptor-preparation/v1',
            'execution_plan':{'path':'/known-public/PLAN.json','sha256':'11'*32},
            'primary_journal':{'path':'/known-public/PRIMARY.json','sha256':'22'*32},'extra_metadata':[extra]}
        docs={'/known-public/SELECTOR.json':a.encoded(selected),v['index']['path']:a.encoded(f['index']),
            v['batch_plan']['path']:a.encoded(f['plan']),extra['source']:b'x'*17}
        docs.update({r['descriptor_row']['path']:a.encoded(r['descriptor']) for r in f['batches']})
        saved=[]
        def save(path,data):
            saved.append(data);return {'path':str(path),'sha256':a.sha(a.encoded(data))}
        with patch.object(c.audit,'guarded',side_effect=lambda row:docs[row['path']]), \
            patch.object(c,'checkpoint_checked',return_value=(v,f['index'],f['plan'],f['contexts'],f['coverage'],p)), \
            patch.object(c,'fresh_control_output',return_value=Path('/known-public/output')), \
            patch.object(c.audit,'save',side_effect=save),patch.object(c,'selected_module') as module:
            result=c.prepare_supplemental({'path':'/known-public/SELECTOR.json','sha256':'33'*32},Path('/known-public/output'))
            module.assert_not_called()
        self.assertIs(result['actual_original_workers_invoked'],False)
        self.assertIs(result['global_audit_complete'],False)
        stage=next(s for s in saved if isinstance(s,dict) and s.get('batch_id')=='DESCRIPTORS')
        self.assertEqual(stage['supplemental_public_metadata'],[extra]);self.assertEqual(len(stage['files']),len(f['batches'])+3)


if __name__=='__main__':unittest.main()
