"""Released public sentinel/interface controls; no chain/native/private runs."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import accepted_public as selected
import installation

TRIAL = '11111111-1111-4111-8111-111111111111'
PROGRAM_SHA = 'd8b5673f95adfb68e8566ff7435dc9bac27ee1a8361388355acbcb667321a1a9'


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()


def fixture(root, operation='finalize'):
    """Eight unsafe PUBLIC text sentinels and nonexecutable dummy metadata."""
    private_roots = (root/'PUBLIC-local', root/'PUBLIC-live')
    originals = []
    for trial_index, directory in enumerate(private_roots):
        for role in 'ABCD':
            path = directory/'owners'/role/'backup.json'; path.parent.mkdir(parents=True)
            path.write_bytes(('PUBLIC_UNSAFE_SENTINEL_NOT_A_FINANCIAL_BACKUP_'+str(trial_index)+role).encode())
            path.chmod(0o600); originals.append(path)
    public = root/'public'; public.mkdir()
    software = public/'software'; software.mkdir()
    rows, members = [], []
    for index, name in enumerate(sorted(installation.mapping('accepted'))):
        raw = ('PUBLIC_UNSAFE_NONEXECUTABLE_CANARY_'+str(index)).encode()
        path = software/name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw); path.chmod(0o400); members.append(path)
        rows.append({'path':name, 'bytes':len(raw), 'sha256':installation.digest(raw),
                     'kind':'public-canary'})
    inventory = software/'SOFTWARE-BUNDLE.json'
    inventory.write_bytes(encoded({'schema':'kpx4-public-software-bundle/v1',
        'classification':'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY','files':rows}))
    bundle = public/'retained'; bundle.mkdir()
    pages = (bundle/'pages/first.json.gz', bundle/'pages/post-delta-last.json.gz')
    for page in pages:
        page.parent.mkdir(parents=True, exist_ok=True)
        page.write_bytes(b'PUBLIC_UNSAFE_NOT_GZIP_NOT_FULL_NOT_CHAIN_EVIDENCE')
    fetch_doc = {'schema':'kpx5-gn2-network-fetch/v1','status':'FETCHED_PENDING_REPLAY',
        'pages':[{'path':'pages/first.json.gz'}],
        'current_view':{'post_query_delta':{'pages':[{'path':'pages/post-delta-last.json.gz'}]}}}
    values = {}
    for name in ('financial','descriptor','case','proof','projection','journal','preparation',
                 'codec','exit_receipts','recovery_receipts'):
        path = public/(name+'.txt');path.write_bytes(('PUBLIC_UNSAFE_NOT_ACTUAL_'+name).encode())
        values[name]=path
    fetch=public/'fetch.json';fetch.write_bytes(encoded(fetch_doc))
    args=SimpleNamespace(op=operation,exclude_private_root=private_roots,
        financial_sha256=selected.PROFILE_SHA,financial_profile=values['financial'],trial_id=TRIAL,
        inventory_sha256=installation.digest(inventory.read_bytes()),program_sha256=PROGRAM_SHA,
        output=root/'must-not-be-created',software_root=software,
        descriptor=values['descriptor'],descriptor_sha256=installation.digest(values['descriptor'].read_bytes()),
        fetch=fetch,fetch_sha256=installation.digest(fetch.read_bytes()),bundle_directory=bundle,
        case=values['case'],case_sha256=installation.digest(values['case'].read_bytes()),
        proof=values['proof'],proof_sha256=installation.digest(values['proof'].read_bytes()),
        projection=values['projection'],projection_sha256=installation.digest(values['projection'].read_bytes()),
        journal=values['journal'],journal_sha256=installation.digest(values['journal'].read_bytes()),
        preparation=values['preparation'],preparation_sha256=installation.digest(values['preparation'].read_bytes()),
        codec=values['codec'],exit_receipts=values['exit_receipts'],
        exit_receipts_sha256=installation.digest(values['exit_receipts'].read_bytes()),
        recovery_receipts=values['recovery_receipts'],
        recovery_receipts_sha256=installation.digest(values['recovery_receipts'].read_bytes()),
        recipient_exit_index=[0,1],execute=False)
    return args, originals, inventory, members, pages


class AcceptedPublicSentinels(unittest.TestCase):
    def guarded_rejection(self,args,expected_reads):
        read=[];original=installation.read_public
        def tracked(path,*a,**kw):
            read.append(Path(path));return original(path,*a,**kw)
        with patch.object(installation,'read_public',side_effect=tracked), \
             patch.object(selected,'read_public',side_effect=tracked), \
             patch.object(selected,'accepted_base',side_effect=AssertionError('accepted-replay-forbidden')) as replay:
            with self.assertRaises(ValueError):selected.stage(args)
            replay.assert_not_called()
        self.assertEqual(read,expected_reads)
        self.assertFalse(args.output.exists())

    def test_last_software_member_aliases_eighth_before_member_read_or_copy(self):
        with tempfile.TemporaryDirectory(prefix='kpx6-PUBLIC-accepted-sentinel-')as tmp:
            args,originals,inventory,members,_=fixture(Path(tmp))
            last=members[-1];last.unlink();last.hardlink_to(originals[-1])
            self.guarded_rejection(args,[inventory])

    def test_fetch_aliases_eighth_before_any_public_bytes(self):
        with tempfile.TemporaryDirectory(prefix='kpx6-PUBLIC-accepted-sentinel-')as tmp:
            args,originals,_,_,_=fixture(Path(tmp))
            args.fetch.unlink();args.fetch.hardlink_to(originals[-1])
            self.guarded_rejection(args,[])

    def test_late_post_delta_page_aliases_eighth_before_member_or_page_read(self):
        with tempfile.TemporaryDirectory(prefix='kpx6-PUBLIC-accepted-sentinel-')as tmp:
            args,originals,inventory,_,pages=fixture(Path(tmp))
            pages[-1].unlink();pages[-1].hardlink_to(originals[-1])
            self.guarded_rejection(args,[inventory,args.fetch])

    def test_external_inventory_pin_mismatch_before_member_bytes(self):
        with tempfile.TemporaryDirectory(prefix='kpx6-PUBLIC-accepted-sentinel-')as tmp:
            args,_,inventory,_,_=fixture(Path(tmp));args.inventory_sha256='00'*32
            self.guarded_rejection(args,[inventory])

    def test_bad_trial_financial_selection_and_recipient_indices_before_ingress(self):
        mutations=[('trial_id',value)for value in ('bad',None,123,
            '11111111-1111-3111-8111-111111111111','ABCDEFAB-1111-4111-8111-111111111111')]
        mutations += [('recipient_exit_index',value)for value in
                      ([],[0],[1,1],[-1,2],[True,2],[0,4],[0,1,2])]
        mutations += [('financial_sha256','00'*32)]
        for field,value in mutations:
            with self.subTest(field=field,value=value), \
                 tempfile.TemporaryDirectory(prefix='kpx6-PUBLIC-accepted-sentinel-')as tmp:
                args,_,_,_,_=fixture(Path(tmp),operation='ledger');setattr(args,field,value)
                self.guarded_rejection(args,[])

    def test_recognition_projection_drops_private_fields_and_rejects_bad_counts(self):
        counts={'recognized_historical_receipt_count':2,'recognized_spent_receipt_count':2,
            'recognized_unspent_claim_count_before':0,
            'historical_native_payout_key_control_match_count':1,'unresolved_owned_NF_payout_records':0}
        private={'historical_native_payout_sompi':987654321,
            'ordinary_funding_change_sompi':987654322,'native_payout_sompi':987654323,
            'payout_script':'PUBLIC_UNSAFE_PRIVATE_SCRIPT_SENTINEL',
            'owned_positions':['PUBLIC_UNSAFE_PRIVATE_POSITION_SENTINEL'],
            'cm_hex32':'PUBLIC_UNSAFE_PRIVATE_CM_SENTINEL','nf_hex32':'PUBLIC_UNSAFE_PRIVATE_NF_SENTINEL',
            'backup_sha256':'PUBLIC_UNSAFE_PRIVATE_BACKUP_HASH_SENTINEL',
            'seed_hex32':'PUBLIC_UNSAFE_PRIVATE_SEED_SENTINEL',
            'funding_secret_hex32':'PUBLIC_UNSAFE_PRIVATE_FUNDING_SENTINEL','actor':'PUBLIC_UNSAFE_PRIVATE_ACTOR'}
        row={'op':'recover',**counts,**private};result=selected.recognition_counts(row)
        expected={'schema','financial_profile_sha256',*counts,
            'per_owner_payout_amount_script_owned_positions_or_backup_hash_exported','PK_or_proving_worker_required'}
        self.assertEqual(set(result),expected)
        self.assertEqual({name:result[name]for name in counts},counts)
        self.assertIs(result['per_owner_payout_amount_script_owned_positions_or_backup_hash_exported'],False)
        self.assertIs(result['PK_or_proving_worker_required'],False)
        raw=encoded(result)
        for name,value in private.items():
            self.assertNotIn(name,result);self.assertNotIn(str(value).encode(),raw)
        for name in counts:
            for bad in (True,False,-1,'1',1.0):
                with self.subTest(name=name,value=bad),self.assertRaises(ValueError):
                    selected.recognition_counts({**row,name:bad})
        for op in ('prepare-full-cashout',None):
            with self.subTest(op=op),self.assertRaises(ValueError):
                selected.recognition_counts({**row,'op':op})


if __name__=='__main__':unittest.main()
