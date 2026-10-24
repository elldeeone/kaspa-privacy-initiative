#!/usr/bin/env python3
"""Authenticate a restored public runtime, then run one closed owner operation.

The child invokes worker.py directly. It has no supervisor HostPolicy, foreign
backups, original paths, network, GPU or shared prover. The trusted supervisor
inspects private metadata only; one original own backup is mounted for restore.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess

import closure
from run_restore import CLEAN, PublicPolicy, attrs, checked


PROFILE_SHA = '69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f'
CRYPTO_SHA = '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'
REFERENCE_SHA = '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'
WALLET = 'poc/owner-private-lifecycle/wallet/'
SOURCES = tuple(WALLET + name + '.py' for name in ('paths','support','history','trees','worker')) + (
    'poc/future-recipient/v2/recipient.py',
    'poc/owner-private-lifecycle/integration/construction/codec.py',
    'poc/owner-private-lifecycle/verification/wire.py')
OPERATIONS = ('restore','scan','exit-ready','exit')
EXPORTS = {
    'kpx8-owner-restored/v1': {'schema','domain_hex32','participant_id_hex32','seed_only','private_maps_imported'},
    'kpx8-owner-scan-complete/v1': {'schema','domain_hex32','participant_id_hex32','history_sha256','seed_only',
        'scan_completed','private_claims_exported','terminal_reconciled','native_payout_keys_rederived'},
    'kpx8-owner-exit-ready/v1': {'schema','domain_hex32','participant_id_hex32','history_sha256','nf_hex32',
        'gross_claim_sompi','payout_spk_hex36','financial_authorization'},
    'kpx8-owner-no-unspent-claim/v1': {'schema','participant_id_hex32','history_sha256','empty'},
    'kpx8-owner-exit-authorization/v1': {'schema','history_sha256','projection_sha256','effects_digest_hex32',
        'nf_hex32','statement_hex152','proof_hex128'},
}
OP_SCHEMAS = {'restore': {'kpx8-owner-restored/v1'}, 'scan': {'kpx8-owner-scan-complete/v1'},
    'exit-ready': {'kpx8-owner-exit-ready/v1','kpx8-owner-no-unspent-claim/v1'},
    'exit': {'kpx8-owner-exit-authorization/v1'}}


def retained_private_roots():
    """Metadata-only host exclusions; absent old fixtures are not required."""
    roots=[Path('/var/tmp/kpi-owner-private-lifecycle-01/private')]
    for trial in ('kpi-four-wallet-local-rehearsal-01','kpi-four-wallet-live-01'):
        roots.extend(Path('/var/tmp')/trial/'owners'/role for role in 'ABCD')
    for name in ('party-0','party-1','party-2','controller-private'):
        roots.append(Path('/var/tmp/kpi-owner-private-integration-01')/name)
    diagnostic=Path('/var/tmp/kpi-owner-private-diagnostics-01')
    if diagnostic.is_dir():
        roots.extend(p for p in diagnostic.iterdir()
                     if p.name not in ('public','PUBLIC-SELECTOR.json') and p.is_dir())
    for number in range(1,17):
        world=Path('/var/tmp/kpi-owner-private-cohort-01')/f'world-{number:02d}'
        roots.extend(world/name for name in ('party-0','party-1','party-2','controller-private'))
    roots.extend(Path('/var/tmp')/name for name in ('kpi-owner-private-cohort-controller-01',
        'kpi-owner-private-publication-runtime-01','kpi-owner-private-publication-runtime-02'))
    return tuple(p for p in roots if p.exists())


def stream(policy, path, expected, expected_bytes=None):
    """Metadata/inode exclusion and stable whole-file hash before any seed mount."""
    policy.refresh();path=policy.public_path(path);before=path.lstat()
    closure.need(stat.S_ISREG(before.st_mode) and before.st_nlink==1
                 and (before.st_dev,before.st_ino) not in policy.identities,'cold-public-private-alias')
    closure.need(expected_bytes is None or before.st_size==expected_bytes,'cold-public-object-length')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        closure.need(attrs(os.fstat(fd))==attrs(before)
                     and (before.st_dev,before.st_ino) not in policy.identities,'cold-public-open-race')
        hasher=hashlib.sha256();size=0
        with os.fdopen(os.dup(fd),'rb') as source:
            while raw:=source.read(1024*1024):hasher.update(raw);size+=len(raw)
        closure.need(attrs(os.fstat(fd))==attrs(before) and attrs(path.lstat())==attrs(before)
                     and size==before.st_size and hasher.hexdigest()==expected,'cold-whole-public-object-pin')
    finally:os.close(fd)
    return path,before


def fresh(path, roots, *, private):
    path=checked(path)
    closure.need(not path.exists() and not path.is_relative_to(closure.ROOT)
                 and any(path.is_relative_to(root) for root in roots)==private,'cold-fresh-directory-boundary')
    path.mkdir(parents=True,mode=0o700)
    return path


def write(path,raw,mode=0o400):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as target:target.write(raw);target.flush();os.fsync(target.fileno())


def parse_public(raw):
    return closure.storage_module().parse(raw)


def selection(a,policy):
    root=policy.public_path(a.software_root)
    inventory=parse_public(policy.read(a.software_inventory,a.software_inventory_sha256))
    closure.need(type(inventory) is dict and set(inventory)=={'schema','classification','files'}
                 and inventory['schema']=='kpx4-public-software-bundle/v1'
                 and inventory['classification']=='PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY'
                 and type(inventory['files']) is list,'cold-selected-software-inventory')
    members={};identities=[]
    for row in inventory['files']:
        closure.need(type(row) is dict and set(row)=={'kind','path','bytes','sha256'},'cold-inventory-member')
        name=row['path'];path=PurePosixPath(name)
        closure.need(type(name) is str and name==path.as_posix() and not path.is_absolute()
                     and '\\' not in name and all(p not in ('.','..') for p in path.parts)
                     and name not in members and type(row['bytes']) is int and row['bytes']>0
                     and type(row['sha256']) is str and closure.HEX32.fullmatch(row['sha256']),
                     'cold-canonical-inventory-member')
        members[name]=row
    closure.need(set(SOURCES)<=set(members),'complete-closed-worker-source-closure')
    for name,row in members.items():identities.append(stream(policy,root/name,row['sha256'],row['bytes']))
    closure.need(members['poc/future-recipient/v2/recipient.py']['sha256']==REFERENCE_SHA,
                 'cold-fixed-recipient-reference')
    profile=parse_public(policy.read(root/'poc/owner-private-lifecycle/financial-profile.json',PROFILE_SHA))
    assets=parse_public(policy.read(a.assets,a.assets_sha256))
    closure.need(type(assets) is dict and set(assets)=={'schema','domain_hex32','component_profile',
        'component_profile_sha256','relation','crypto','spend','output','exit','codec_sha256','wire_sha256',
        'program_source_sha256'} and assets['schema']=='kpx8-wallet-assets/v1'
        and assets['domain_hex32']==closure.LIFECYCLE_DOMAIN
        and assets['component_profile_sha256']==profile['component_profile_sha256'],
        'cold-selected-financial-assets')
    component=(assets['component_profile'],assets['component_profile_sha256'])
    identities.append(stream(policy,*component))
    for role,pin in [('relation',profile['selected_public_binaries_and_native_policy']['relation']['sha256']),
                     ('crypto',CRYPTO_SHA)]:
        row=assets[role]
        closure.need(type(row) is dict and set(row)=={'path','sha256'} and row['sha256']==pin,
                     'cold-selected-executable-role')
        identities.append(stream(policy,row['path'],pin))
    for role in ('spend','output','exit'):
        row=assets[role];selected=profile['roles'][role]
        closure.need(type(row) is dict and set(row)=={'manifest','manifest_sha256','pk','pk_sha256'}
                     and row['manifest_sha256']==selected['manifest_sha256']
                     and row['pk_sha256']==selected['pk_sha256'],'cold-selected-parameter-role')
        identities.append(stream(policy,row['manifest'],row['manifest_sha256']))
        # All three complete keys are authenticated before the original own
        # backup is mounted, even though only Exit PK enters an exit child.
        identities.append(stream(policy,row['pk'],row['pk_sha256'],selected['pk_bytes']))
    closure.need(members[SOURCES[-2]]['sha256']==assets['codec_sha256']
                 and members[SOURCES[-1]]['sha256']==assets['wire_sha256'],'cold-public-codec-selection')
    return root,members,assets,identities


PROBE='''from pathlib import Path
import json,os,sys
v=json.loads(Path('/cold/options.json').read_bytes())
absent={str(i):not Path(p).exists() for i,p in enumerate(v['absent'])}
assert all(absent.values()), 'original-path-visible-to-cold-owner'
assert not list(Path('/dev').glob('nvidia*'))
Path('/out/ISOLATION.json').write_text(json.dumps({'schema':'kpx8-cold-owner-isolation/v1',
 'all_original_paths_absent':all(absent.values()),'network_unshared':True,
 'GPU_mounted':False,'foreign_wallet_or_old_trial_fixtures_mounted':False,
 'only_own_original_backup_mounted':v['restore'],'restored_worker_direct_entry':True},sort_keys=True)+'\\n')
os.execv('/usr/bin/python3',['/usr/bin/python3','-B',*sys.argv[1:]])
'''


def run(a):
    policy=PublicPolicy(a.exclude_private_directory)
    closure.need(all(any(p.is_relative_to(root) for root in policy.roots)
                     for p in retained_private_roots()),'cold-all-retained-private-parents-required')
    owner,mpc=checked(a.owner_directory),checked(a.mpc_directory)
    closure.need(owner!=mpc and not owner.is_relative_to(mpc) and not mpc.is_relative_to(owner)
                 and all(any(p.is_relative_to(d) for d in policy.roots) for p in (owner,mpc)),
                 'cold-own-private-directories')
    backup=None
    if a.operation=='restore':
        closure.need(a.backup is not None,'cold-own-original-backup-required')
        backup=checked(a.backup);info=backup.lstat()
        closure.need(any(backup.is_relative_to(d) for d in policy.roots)
                     and not any(backup.is_relative_to(p) for p in (owner,mpc))
                     and stat.S_ISREG(info.st_mode) and info.st_nlink==1
                     and stat.S_IMODE(info.st_mode)==0o600,'cold-own-backup-metadata-only')
    else:
        closure.need(owner.is_dir() and mpc.is_dir() and a.backup is None,
                     'cold-restored-private-runtime-required')
    # Own private coverage is checked using metadata before even an inventory
    # or helper content-open. A new host need not retain any old trial fixture.
    policy.read(closure.STORAGE_SOURCE,closure.STORAGE_SHA256)
    root,members,assets,identities=selection(a,policy)
    selected_inputs=[]
    if a.operation!='restore':
        for name in ('history','context'):
            path=getattr(a,name);pin=getattr(a,name+'_sha256')
            closure.need(path is not None and pin is not None,'cold-selected-public-history-context')
            selected_inputs.append((name,policy.read(path,pin)))
        if a.operation=='exit':
            closure.need(a.projection is not None and a.projection_sha256 is not None,
                         'cold-selected-exit-projection')
            selected_inputs.append(('projection',policy.read(a.projection,a.projection_sha256)))
    private=fresh(a.private_run_directory,policy.roots,private=True)
    closure.need(not private.is_relative_to(owner) and not private.is_relative_to(mpc),
                 'cold-controller-separated-from-own-runtime')
    output=fresh(a.output,policy.roots,private=False)
    if a.operation=='restore':
        fresh(owner,policy.roots,private=True);fresh(mpc,policy.roots,private=True)
    command=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
        '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
        '--symlink','usr/lib64','/lib64','--ro-bind','/etc/alternatives','/etc/alternatives',
        '--proc','/proc','--dev','/dev','--tmpfs','/tmp']
    for name in SOURCES:
        raw=policy.read(root/name,members[name]['sha256']);staged=private/'software'/name
        write(staged,raw);command+=['--ro-bind',str(staged),'/work/'+name]
    for role in ('relation','crypto'):
        raw=policy.read(assets[role]['path'],assets[role]['sha256'])
        closure.need(raw[:4]==b'\x7fELF','cold-selected-executable-ELF')
        executable=private/'runtime'/role
        write(executable,raw,0o500)
        command+=['--ro-bind',str(executable),'/runtime/'+role]
    command+=['--ro-bind',assets['component_profile'],'/parameters/component-profile.json']
    assets['component_profile']='/parameters/component-profile.json'
    for role in ('relation','crypto'):assets[role]['path']='/runtime/'+role
    for role in ('spend','output','exit'):
        command+=['--ro-bind',assets[role]['manifest'],'/parameters/'+role+'.json']
        if a.operation=='exit' and role=='exit':
            command+=['--ro-bind',assets[role]['pk'],'/parameters/exit.pk']
        assets[role]['manifest']='/parameters/'+role+'.json';assets[role]['pk']='/parameters/'+role+'.pk'
    raw_assets=closure.encoded(assets);write(private/'assets.json',raw_assets)
    command+=['--ro-bind',str(private/'assets.json'),'/assets.json']
    for name,raw in selected_inputs:
        write(private/'inputs'/name,raw);command+=['--ro-bind',str(private/'inputs'/name),'/'+name]
    absent=['/home/luke',str(closure.ROOT),*[str(d) for d in policy.roots],
        '/home/luke/.cache/kpi-sdk','/home/luke/.cargo']
    write(private/'probe.py',PROBE.encode());write(private/'options.json',closure.encoded({
        'absent':absent,'restore':a.operation=='restore'}))
    command+=['--ro-bind',str(private/'probe.py'),'/cold/probe.py',
        '--ro-bind',str(private/'options.json'),'/cold/options.json',
        '--bind',str(owner),'/private','--bind',str(mpc),'/mpc','--bind',str(output),'/out']
    if backup is not None:command+=['--ro-bind',str(backup),'/backup.json']
    command+=['--chdir','/work/poc/owner-private-lifecycle/wallet','--setenv','PATH','/usr/bin:/bin',
        '--setenv','LANG','C.UTF-8','--setenv','TZ','UTC','/usr/bin/python3','-B','/cold/probe.py',
        '/work/'+WALLET+'worker.py',a.operation,'--owner','/private','--mpc','/mpc','--output','/out']
    if a.operation=='restore':command+=['--backup','/backup.json']
    else:
        command+=['--assets','/assets.json','--assets-sha256',closure.digest(raw_assets),
            '--history','/history','--history-sha256',a.history_sha256,
            '--context','/context','--context-sha256',a.context_sha256]
        if a.operation=='exit-ready':command+=['--note-kind',a.note_kind]
        if a.operation=='exit':command+=['--projection','/projection','--projection-sha256',a.projection_sha256]
    for path,before in identities:
        closure.need(attrs(path.lstat())==attrs(before),'cold-public-runtime-changed-before-launch')
    write(private/'PRIVATE-PLAN.json',closure.encoded({'command':command,'publish_or_hash':False}))
    process=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,env=CLEAN)
    write(private/'PRIVATE-STDOUT.log',process.stdout);write(private/'PRIVATE-STDERR.log',process.stderr)
    closure.need(process.returncode==0,'cold-owner-operation-refused-private-log-retained')
    value=parse_public(policy.read(output/'PUBLIC.json'))
    schema=value.get('schema') if type(value) is dict else None
    closure.need(schema in OP_SCHEMAS[a.operation] and set(value)==EXPORTS[schema],
                 'cold-fixed-public-export')
    isolation=parse_public(policy.read(output/'ISOLATION.json'))
    closure.need(isolation['all_original_paths_absent'] is True
                 and isolation['foreign_wallet_or_old_trial_fixtures_mounted'] is False,
                 'cold-observed-private-path-isolation')
    return {'operation':a.operation,'completed':True,'restored_worker_direct_entry':True,
            'software_inventory_sha256':a.software_inventory_sha256,
            'financial_profile_sha256':PROFILE_SHA,'private_contents_read_by_supervisor':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=OPERATIONS)
    for name in ('software-root','software-inventory','assets','owner-directory','mpc-directory',
                 'private-run-directory','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('software-inventory-sha256','assets-sha256'):p.add_argument('--'+name,required=True)
    p.add_argument('--exclude-private-directory',type=Path,action='append',required=True)
    for name in ('history','context','projection','backup'):p.add_argument('--'+name,type=Path)
    for name in ('history-sha256','context-sha256','projection-sha256'):p.add_argument('--'+name)
    p.add_argument('--note-kind',choices=('initial','received','change','any','received-or-change'),default='any')
    try:print(json.dumps(run(p.parse_args()),sort_keys=True))
    except Exception:p.exit(2,'cold owner refused; private material not disclosed\n')


if __name__=='__main__':main()
