"""Known PUBLIC_UNSAFE controls only; never use a financial owner backup."""
import base64
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import check_export as audit
import run_export_check as launch
from installation import digest, mapping

ROOT = Path(__file__).resolve().parents[2]
TRIAL = '11111111-1111-4111-8111-111111111111'
SEED = bytes(range(224, 256))
FUNDING = bytes([251]) * 32
PROFILE = ROOT / 'poc/four-wallet-profile/financial-profile.json'


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()


def selected_source(name):
    raw=(ROOT/name).read_bytes()
    if name in launch.FIXED and digest(raw)!=launch.FIXED[name]:
        # The coordinator may add a later accepted-chain pin while this audit
        # deliberately tests the reviewed b00 public contract preimage.
        raw=(ROOT/'research/next-session/four-wallet-testnet/lifecycle/controls-02/source'/Path(name).name).read_bytes()
        if digest(raw)!=launch.FIXED[name]:raise ValueError('retained-control-source-pin')
    return raw


def fixture(root, blobs=None):
    profile = root / 'profile.json'; profile.write_bytes(PROFILE.read_bytes())
    domain = json.loads(profile.read_bytes())['child_domain_hex32']
    backups = []
    for index, role in enumerate('ABCD'):
        path = root / 'private' / role / 'backup.json'; path.parent.mkdir(parents=True)
        path.write_bytes(encoded({'schema':'kpx6-four-wallet-backup/v1', 'network_id':'testnet-10',
            'genesis_hash_hex':'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
            'domain_hex32':domain, 'trial_id':TRIAL,
            'seed_hex32':SEED.hex() if index == 0 else (bytes([index])*32).hex(),
            'funding_secret_hex32':FUNDING.hex() if index == 0 else (index+1).to_bytes(32,'big').hex()}))
        path.chmod(0o600); backups.append(path)
    candidate_root = root / 'candidates'; candidate_root.mkdir()
    candidate_rows = []
    for index, blob in enumerate(blobs or [b'PUBLIC CLEAN CANDIDATE']):
        name = str(index)+'.bin'; (candidate_root/name).write_bytes(blob)
        candidate_rows.append({'path':name, 'bytes':len(blob), 'sha256':digest(blob)})
    candidates = root / 'CANDIDATES.json'
    candidates.write_bytes(encoded({'schema':audit.CANDIDATE_SCHEMA,
        'classification':audit.CANDIDATE_CLASS, 'files':candidate_rows}))
    software = root / 'software'; software.mkdir()
    source_rows = []
    for name in sorted(audit.PURE_PATHS):
        raw = selected_source(name); target = software/name
        target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(raw)
        source_rows.append({'path':name,'bytes':len(raw),'sha256':digest(raw),'kind':'runtime-source'})
    inventory = root / 'SOFTWARE.json'
    inventory.write_bytes(encoded({'schema':'kpx4-public-software-bundle/v1',
        'classification':audit.SOFTWARE_CLASS,'files':source_rows}))
    args=SimpleNamespace(backup=backups[0],financial_profile=profile,financial_sha256=digest(profile.read_bytes()),
        software_inventory=inventory,software_sha256=digest(inventory.read_bytes()),software_root=software,
        candidates=candidates,candidates_sha256=digest(candidates.read_bytes()),candidate_root=candidate_root,
        output=root/'RESULTS.json',trial_id=TRIAL)
    return args,backups


def host_fixture(root, blobs=None):
    args, backups=fixture(root,blobs)
    tree=root/'full-software'; tree.mkdir(); rows=[]
    for name in sorted(mapping('local')):
        raw=('PUBLIC_DUMMY_NEVER_EXECUTED_'+name).encode()
        if name.startswith('runtime-source/') and name[len('runtime-source/'):] in launch.FIXED:
            raw=selected_source(name[len('runtime-source/'):])
        target=tree/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        rows.append({'path':name,'bytes':len(raw),'sha256':digest(raw),
                     'kind':'selected-executable' if name.startswith('runtime/') else 'runtime-source'})
    inventory=root/'FULL-SOFTWARE.json';inventory.write_bytes(encoded({'schema':'kpx4-public-software-bundle/v1',
        'classification':audit.SOFTWARE_CLASS,'files':rows}))
    host=SimpleNamespace(controller=root/'controller',backup=backups[0],exclude_private_file=backups,
        exclude_private_dir=[path.parent for path in backups],checker=ROOT/'poc/four-wallet-lifecycle/check_export.py',
        checker_sha256=digest((ROOT/'poc/four-wallet-lifecycle/check_export.py').read_bytes()),
        software_root=tree,inventory=inventory,inventory_sha256=digest(inventory.read_bytes()),
        financial_profile=args.financial_profile,financial_sha256=args.financial_sha256,
        candidates=args.candidates,candidates_sha256=args.candidates_sha256,candidate_root=args.candidate_root,
        trial_id=TRIAL,execute=False,source_kind='local')
    return host,backups


class ExportControls(unittest.TestCase):
    def test_clean_and_all_exact_encodings_with_boundary_overlap(self):
        values=[]
        for key in (SEED,FUNDING):
            values.extend((key,key.hex().encode(),key.hex().upper().encode(),base64.b64encode(key),
                base64.b64encode(key).rstrip(b'='),base64.urlsafe_b64encode(key),
                base64.urlsafe_b64encode(key).rstrip(b'=')))
        for blobs, expected in (([b'PUBLIC CLEAN CANDIDATE'],0),
                                ([b'padding-1234567'+value+b'end' for value in values],len(values))):
            with tempfile.TemporaryDirectory(prefix='kpx6-PUBLIC-export-control-') as tmp:
                args,_=fixture(Path(tmp),blobs)
                with patch.object(audit,'CHUNK_BYTES',16):result=audit.run(args)
                self.assertEqual(result['matched_candidate_file_count'],expected)
                self.assertEqual(result['passed'],expected==0)
                raw=args.output.read_bytes()
                for value in values:self.assertNotIn(value,raw)

    def test_public_identity_failure_precedes_backup_access(self):
        for field in ('financial_sha256','software_sha256','candidates_sha256','trial_id'):
            with tempfile.TemporaryDirectory(prefix='kpx6-PUBLIC-export-control-') as tmp:
                args,_=fixture(Path(tmp));setattr(args,field,'00'*32 if field!='trial_id' else 'wrong')
                with patch.object(audit,'read_backup',side_effect=AssertionError('backup-read-before-auth')) as read:
                    with self.assertRaises(ValueError):audit.run(args)
                    read.assert_not_called()
                self.assertFalse(args.output.exists())

    def test_secret_filename_in_public_manifest_is_counted(self):
        with tempfile.TemporaryDirectory(prefix='kpx6-PUBLIC-export-control-') as tmp:
            args,_=fixture(Path(tmp))
            name=SEED.hex()+'.bin';(args.candidate_root/'0.bin').rename(args.candidate_root/name)
            value=json.loads(args.candidates.read_bytes());value['files'][0]['path']=name
            args.candidates.write_bytes(encoded(value));args.candidates_sha256=digest(args.candidates.read_bytes())
            result=audit.run(args)
            self.assertFalse(result['passed']);self.assertEqual(result['matched_candidate_file_count'],0)
            self.assertEqual(result['matched_public_metadata_file_count'],1)

    def test_late_candidate_alias_and_manifest_malformed_precede_member_reads(self):
        for malformed in ('alias','duplicate','traversal','bool-size','extra-field'):
            with tempfile.TemporaryDirectory(prefix='kpx6-PUBLIC-export-control-') as tmp:
                args,backups=fixture(Path(tmp),[b'first',b'last'])
                value=json.loads(args.candidates.read_bytes())
                if malformed=='alias':
                    path=args.candidate_root/'1.bin';path.unlink();path.hardlink_to(backups[0])
                    value['files'][-1]['bytes']=path.stat().st_size
                elif malformed=='duplicate':value['files'].append(value['files'][0])
                elif malformed=='traversal':value['files'][-1]['path']='../other'
                elif malformed=='bool-size':value['files'][-1]['bytes']=True
                else:value['files'][-1]['owner']='forbidden'
                args.candidates.write_bytes(encoded(value));args.candidates_sha256=digest(args.candidates.read_bytes())
                with patch.object(audit,'stream',side_effect=AssertionError('member-read-before-metadata')) as stream, \
                     patch.object(audit,'read_backup',side_effect=AssertionError('backup-read-before-metadata')) as read:
                    with self.assertRaises(ValueError):audit.run(args)
                    stream.assert_not_called();read.assert_not_called()

    def test_host_fourth_backup_alias_before_selected_member_copy(self):
        with tempfile.TemporaryDirectory(prefix='kpx6-PUBLIC-export-control-') as tmp:
            args,backups=host_fixture(Path(tmp),[b'first',b'last'])
            path=args.candidate_root/'1.bin';path.unlink();path.hardlink_to(backups[-1])
            value=json.loads(args.candidates.read_bytes());value['files'][-1]['bytes']=path.stat().st_size
            args.candidates.write_bytes(encoded(value));args.candidates_sha256=digest(args.candidates.read_bytes())
            with patch.object(launch,'copy_stable',side_effect=AssertionError('member-read-before-fourth-alias')) as copy:
                with self.assertRaises(ValueError):launch.run(args)
                copy.assert_not_called()
            self.assertFalse(args.controller.exists())

    def test_real_offline_namespace_clean_and_deliberate_leak(self):
        for blob,passed in ((b'PUBLIC CLEAN CANDIDATE',True),(b'PUBLIC DELIBERATE '+SEED.hex().encode(),False)):
            with tempfile.TemporaryDirectory(prefix='kpx6-PUBLIC-export-control-') as tmp:
                args,_=host_fixture(Path(tmp),[blob]);args.execute=True
                result=launch.run(args)
                self.assertEqual(result['passed'],passed)
                self.assertEqual(result['matched_candidate_file_count'],0 if passed else 1)
                self.assertFalse((args.controller/'software/runtime/prover').exists())
                for change in ({'extra_secret':SEED.hex()}, {'candidate_bytes':True},
                               {'matched_candidate_file_count':2}, {'passed':not passed}):
                    with self.assertRaises(ValueError):
                        launch.count_only_report({**result,**change},
                            [({'bytes':len(blob)},Path('public-control'))],0 if passed else 2)


if __name__=='__main__':unittest.main()
