"""Finite static publication audit orchestration; private reads only in children.

Adapted from the retained /var/tmp/kpi-owner-private-publication-audit-02.py
controller. The three checker implementations are byte-identical reviewed
sources. Root supplies its guard09 and one exact selected public manifest.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess

REPO = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
PRIVATE = Path('/var/tmp/kpi-owner-private-lifecycle-01/private')
SELECTION = Path('/var/tmp/kpi-owner-private-lifecycle-01/public/publication-static-01/SELECTION.json')
SELECTION_SHA = 'ceae87dd75d64c2d04fececa5e6076e0fe9268c939cdecbd734fd7f072898071'
COUNT, BYTES = 84, 1_496_603_058
PROFILE_SHA = '41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a'
OLD_SEED_WORKER = '1c6c4c007849181b57bf62c5ba552999dd7cda73f081040cc7302a3d71ea8236'
NEW_SEED_WORKER = '64527cadcd85df584fd3c36b945c2c263978cdd6d055376631027d616c8e6711'
FIXED = {
 'poc/four-wallet-lifecycle/installation.py':'5158c1e39038454a6db1d7426acea39672283e9cc19cffdc9832499526b302b9',
 'poc/four-wallet-lifecycle/contracts.py':'b00cf22e66dbda5b3f2083c36529319d32997879b6ef24ab78e96e55ffaf0938',
 'poc/four-wallet-lifecycle/paths.py':'4f1a7444c99a245bfda194602c6f8676d1f35b0a03b0e1ab5accf399de3d35f7',
 'poc/four-wallet-profile/selection.py':'425469f9e5ed012d43132ae17ac965f7c1bc3b0fdacd7a2ecf8a36a881d90553',
 'poc/four-wallet-bootstrap/gn2_common.py':'2f0742ef22eec589978cbc55df20e7acc1c3a95458c46a77b311fc647dcf037b',
 'poc/four-wallet-bootstrap/gn2_backup.py':'8fdf5e01d9b81c99802406276704ddaacd4927d4f48b8432240ec18e6a17efc0',
 'poc/four-wallet-lifecycle/check_export.py':'dd80662b7bd26fc9d32adb18a1661df98ad5b4b1453b7d2a5489d3b83e728da0'}
CLEAN = {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC'}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',',':'))+'\n').encode()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb') as target:
        target.write(raw);target.flush();os.fsync(target.fileno())


def originals():
    old=[(Path('/var/tmp')/root/'owners'/role/'backup.json',trial)
         for root,trial in [('kpi-four-wallet-local-rehearsal-01','fd3bdcb5-c018-418d-ab66-02f8c7f37d2e'),
                            ('kpi-four-wallet-live-01','66c83abb-0745-4709-ab29-dbb28a3de31c')] for role in 'ABCD']
    prior=[Path('/var/tmp/kpi-owner-private-integration-01')/f'party-{i}/owner/OWNER.json' for i in range(3)]
    prior += [Path('/var/tmp/kpi-owner-private-cohort-01')/f'world-{w:02d}/party-{i}/owner/OWNER.json'
              for w in range(1,17) for i in range(3)]
    current=[PRIVATE/label/f'party-{i}/owner/BACKUP.json' for label in ('local-01','live-01') for i in range(3)]
    assert len(old)==8 and len(prior)==51 and len(current)==6
    identities=set()
    for path in [p for p,_ in old]+prior+current:
        info=path.lstat()  # Metadata ONLY. No private leaf hash/content/copy.
        assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600
        assert (info.st_dev,info.st_ino) not in identities
        identities.add((info.st_dev,info.st_ino))
    return old,prior,current


def run(guard, runtime, receipts, controller_source):
    runtime,receipts=Path(runtime),Path(receipts)
    assert runtime==PRIVATE/'static-canary-02' and not runtime.exists()
    assert not receipts.exists() and not receipts.is_relative_to(PRIVATE) and not receipts.is_relative_to(REPO)
    assert type(controller_source) is bytes and controller_source
    # guard09 refreshes whole-private/monotone inode exclusions before reading.
    raw_selection=guard['read'](SELECTION,SELECTION_SHA)
    selected=json.loads(raw_selection)
    assert set(selected)=={'contains_history_or_original_backup','files','producer_static_selection_sha256',
                          'schema','software_archive_members_independently_compared'}
    assert selected['schema']=='owner-private-lifecycle-root-static-publication-selection/v1'
    assert selected['contains_history_or_original_backup'] is False
    assert type(selected['software_archive_members_independently_compared']) is int
    assert selected['software_archive_members_independently_compared']==66
    rows=[];names=set();sources=[]
    for row in selected['files']:
        assert set(row)=={'path','bytes','sha256','source'}
        name=row['path'];path=PurePosixPath(name)
        assert isinstance(name,str) and name and not path.is_absolute() and str(path)==name
        assert '..' not in path.parts and '\\' not in name and '\0' not in name and name not in names
        assert type(row['bytes']) is int and row['bytes']>=0
        assert isinstance(row['sha256'],str) and len(row['sha256'])==64 and bytes.fromhex(row['sha256']).hex()==row['sha256']
        names.add(name);rows.append({k:row[k] for k in ('path','bytes','sha256')});sources.append(Path(row['source']))
    assert len(rows)==COUNT and sum(row['bytes'] for row in rows)==BYTES
    old,prior,current=originals()
    for path in sources:
        _,info=guard['m'].GUARD.metadata(path);assert info.st_nlink==1
    runtime.mkdir(mode=0o700);receipts.mkdir(parents=True,mode=0o700)
    save(runtime/'controller.py',controller_source)
    relative,numeric=runtime/'relative',runtime/'numeric';relative.mkdir();numeric.mkdir()
    # One shared pair of layouts, never per-original copies or hard links.
    for index,(source,row) in enumerate(zip(sources,rows)):
        raw=guard['read'](source,row['sha256']);assert len(raw)==row['bytes']
        save(relative/row['path'],raw);save(numeric/(str(index)+'.bin'),raw)
    manifests={
      'old':encoded({'schema':'kpx6-owner-public-export-candidates/v1',
        'classification':'FINITE_PUBLIC_EXPORT_CANDIDATES_NOT_SECRET_COMPLETENESS_PROOF','files':rows}),
      'prior':encoded({'schema':'kpx7-new-owner-seed-export-allowlist/v1','files':rows}),
      'current':encoded({'schema':'kpx8-new-owner-seed-export-allowlist/v1','files':rows})}
    manifest_pins={kind:hashlib.sha256(raw).hexdigest() for kind,raw in manifests.items()}
    for kind,raw in manifests.items():save(runtime/(kind+'.json'),raw)
    for family,pin,relative_source in (
      ('prior',OLD_SEED_WORKER,'poc/owner-private-payments/wallet/export_seed_worker.py'),
      ('current',NEW_SEED_WORKER,'poc/owner-private-lifecycle/wallet/export_seed_worker.py')):
        save(runtime/(family+'-seed-worker.py'),guard['read'](REPO/relative_source,pin))
    source_rows=[]
    for name,pin in FIXED.items():
        original=REPO/('research/next-session/four-wallet-testnet/lifecycle/source-compat-local-01/contracts.py'
                       if name=='poc/four-wallet-lifecycle/contracts.py' else name)
        raw=guard['read'](original,pin);save(runtime/'software'/name,raw)
        source_rows.append({'path':name,'bytes':len(raw),'sha256':pin,'kind':'runtime-source'})
    software=encoded({'schema':'kpx4-public-software-bundle/v1',
        'classification':'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY',
        'files':sorted(source_rows,key=lambda row:row['path'])})
    software_pin=hashlib.sha256(software).hexdigest();save(runtime/'SOFTWARE.json',software)
    save(runtime/'PROFILE.json',guard['read'](REPO/'poc/four-wallet-profile/financial-profile.json',PROFILE_SHA))
    closure={'schema':'kpx8-static-publication-canary-closure/v1','selected_public_manifest_sha256':SELECTION_SHA,
       'controller_sha256':hashlib.sha256(controller_source).hexdigest(),
       'candidate_file_count':COUNT,'candidate_bytes':BYTES,'manifest_sha256':manifest_pins,
       'compound_checker_sha256':FIXED['poc/four-wallet-lifecycle/check_export.py'],
       'compound_source_closure':source_rows,'compound_profile_sha256':PROFILE_SHA,
       'prior_seed_worker_sha256':OLD_SEED_WORKER,'current_seed_worker_sha256':NEW_SEED_WORKER,
       'max_parallel_workers':4,'original_counts':{'old_compound':8,'prior_seed':51,'current_seed':6}}
    save(receipts/'SOURCE-CLOSURE.json',encoded(closure))
    base=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
      '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
      '--symlink','usr/lib64','/lib64','--ro-bind','/etc/alternatives','/etc/alternatives',
      '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8']
    logs=runtime/'logs';logs.mkdir(mode=0o700)
    def one(job):
        kind,index,owner,trial=job;out=receipts/(kind+f'-{index:02d}');out.mkdir(mode=0o700)
        if kind in ('prior','current'):
            mount='/OWNER.json' if kind=='prior' else '/BACKUP.json'
            command=base+['--ro-bind',str(runtime/(kind+'-seed-worker.py')),'/check.py',
                '--ro-bind',str(numeric),'/candidates','--ro-bind',str(runtime/(kind+'.json')),'/ALLOWLIST.json',
                '--ro-bind',str(owner),mount,'--bind',str(out),'/out','/usr/bin/python3','-B','/check.py',
                '--owner',mount,'--allowlist','/ALLOWLIST.json','--allowlist-sha256',manifest_pins[kind],
                '--candidates','/candidates','--output','/out/RESULTS.json']
        else:
            command=base+['--ro-bind',str(runtime/'software'),'/work','--ro-bind',str(relative),'/candidates',
                '--ro-bind',str(runtime/'SOFTWARE.json'),'/software.json','--ro-bind',str(runtime/'PROFILE.json'),'/profile.json',
                '--ro-bind',str(runtime/'old.json'),'/candidates.json','--ro-bind',str(owner),'/private/backup.json',
                '--bind',str(out),'/out','--chdir','/work/poc/four-wallet-lifecycle','/usr/bin/python3','-B',
                '/work/poc/four-wallet-lifecycle/check_export.py','--backup','/private/backup.json',
                '--financial-profile','/profile.json','--financial-sha256',PROFILE_SHA,
                '--software-inventory','/software.json','--software-sha256',software_pin,'--software-root','/work',
                '--candidates','/candidates.json','--candidates-sha256',manifest_pins[kind],
                '--candidate-root','/candidates','--trial-id',trial,'--output','/out/RESULTS.json']
        result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,env=CLEAN)
        save(logs/(kind+f'-{index:02d}.stdout'),result.stdout);save(logs/(kind+f'-{index:02d}.stderr'),result.stderr)
        assert result.returncode==0,'closed-original-audit-incomplete'
        raw_result=guard['read'](out/'RESULTS.json');value=json.loads(raw_result)
        if kind in ('prior','current'):
            assert set(value)=={'schema','status','candidate_count','candidate_bytes','matched_candidate_count','scope'}
            assert value['schema']==('kpx7' if kind=='prior' else 'kpx8')+'-new-owner-seed-export-result/v1'
            assert value['status']=='PASS' and type(value['matched_candidate_count']) is int and value['matched_candidate_count']==0
            assert value['candidate_count']==COUNT+1 and value['candidate_bytes']==BYTES+len(manifests[kind])
            assert value['scope']=='LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF'
        else:
            assert value['schema']=='kpx6-owner-public-export-check/v1' and value['passed'] is True
            assert value['matched_candidate_file_count']==value['matched_public_metadata_file_count']==0
            assert value['candidate_file_count']==COUNT and value['candidate_bytes']==BYTES
            assert value['scope']=='OWN_TWO_ORIGINAL_KEYS_EXACT_RAW_HEX_BASE64_ENCODINGS_ONLY'
            assert value['secret_values_hashes_or_match_locations_exported'] is False
            assert value['general_transformed_secret_absence_proven'] is False
        return kind
    jobs=[('old',i,path,trial) for i,(path,trial) in enumerate(old)]
    jobs += [('prior',i,path,None) for i,path in enumerate(prior)]
    jobs += [('current',i,path,None) for i,path in enumerate(current)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(one,jobs))
    assert len(results)==65
    summary={'schema':'kpx8-static-publication-canary-summary/v1','candidate_file_count':COUNT,'candidate_bytes':BYTES,
        'selected_public_manifest_sha256':SELECTION_SHA,'candidate_manifest_sha256':manifest_pins,
        'old_original_compound_checks_passed':results.count('old'),'prior_original_seed_checks_passed':results.count('prior'),
        'current_original_seed_checks_passed':results.count('current'),'all_65_checks_passed':True,'matched_candidates':0,
        'controller_original_private_reads_or_hashes':False,'private_reads_only_inside_single_original_leaf_namespaces':True,
        'secret_values_owner_hashes_or_match_locations_exported':False,
        'scope':'FINITE_SELECTED_LITERAL_CANARIES_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF'}
    save(receipts/'SUMMARY.json',encoded(summary))
    return summary
