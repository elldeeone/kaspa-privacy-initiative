#!/usr/bin/env python3
"""Restore root-selected current-W PUBLIC software over anonymous verified TLS."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import sys

from prepare import PROFILE
from software_bundle import parse, need
from unpack_bundle import unpack

HERE = Path(__file__).resolve().parent
HOSTS = ('github.com','release-assets.githubusercontent.com')
TRANSPORT_PINS = {
    'public_fetch.py':'37f1a3aa6a7b0c9e4f5363ffb15f2deebde087295c49b60d1cd9b2b9f6eb32ae',
    'trusted_util.py':'78633b9e62a57796d609b600139cea77f4e1866ec362aa5bdd2588516baad9a6',
    'vendor/capsule.py':'ba6fba072eb00e54297e47473c61ce7ef2230356183c9dfd60d0a8741cc492d2',
    'vendor/chunk_public.py':'c713a4871079acd040f5c434ceed47c4d6f71885c8e5256199a86488a5f724aa',
}

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def restore(args):
    for name,expected in TRANSPORT_PINS.items():
        path=HERE/'transport'/name
        need(not any(p.is_symlink()for p in(path,*path.parents)) and sha(path)==expected,
             'fixed-trusted-transport-source')
    output=args.output.absolute();need(not output.exists(),'fresh-HTTPS-output')
    need(not any(p.is_symlink()for p in output.parents),'output-parent-symlink')
    output.mkdir(parents=True,mode=0o700); assets=output/'assets';assets.mkdir()
    receipts=[]
    def get(url,size,digest,target):
        command=[sys.executable,'-B',str(HERE/'transport/public_fetch.py'),
                 '--url',url,'--expected-bytes',str(size),'--expected-sha256',digest,
                 '--output',str(target),*sum((['--allowed-host',h]for h in HOSTS),[])]
        result=subprocess.run(command,capture_output=True,text=True,
                              env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        need(result.returncode==0,'selected-current-W-HTTPS-object-incomplete')
        receipt=parse(result.stdout);receipts.append(receipt);return receipt
    index_path=assets/'ROOT-SELECTED-INDEX.json'
    get(args.index_url,args.index_bytes,args.index_sha256,index_path)
    index=parse(index_path.read_bytes())
    need(index['schema']=='kpx5-current-W-runtime-distribution/v1'
         and index['classification']=='UNFUNDED_CURRENT_W_PUBLIC_SOFTWARE_DO_NOT_FUND'
         and index['profile']==PROFILE
         and index['wallet_source_freeze_sha256']=='f4f9b187e838be5a5d99a2f40bec7639451a34e3988b8b9766349fa6b1486b7f'
         and index['old_B05_or_D35_financial_selection_inherited'] is False
         and index['outer_proving_or_compression_assets_required_to_exit'] is False,
         'externally-selected-current-W-profile')
    kinds={'current_W_software_archive','current_W_member_inventory','current_W_typed_inventory'}
    need(type(index['assets'])is list and len(index['assets'])==3,'exact-software-assets')
    selected={}
    for row in index['assets']:
        need(type(row)is dict and set(row)=={'kind','basename','bytes','sha256'}
             and row['kind']in kinds and row['kind']not in selected
             and type(row['basename'])is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,199}',row['basename'])
             and type(row['bytes'])is int and row['bytes']>0
             and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
             'safe-unique-typed-asset')
        selected[row['kind']]=row
    archive=index['archive'];need(archive['selected_profile']==PROFILE,'archive-profile-join')
    for kind,field in [('current_W_software_archive','archive_sha256'),
                       ('current_W_member_inventory','member_inventory_sha256'),
                       ('current_W_typed_inventory','typed_software_inventory_sha256')]:
        need(selected[kind]['sha256']==archive[field],'index-selected-asset-join')
    need(selected['current_W_software_archive']['bytes']==archive['archive_bytes'],
         'archive-length-join')
    paths={}
    for kind,row in selected.items():
        path=assets/row['basename']
        get(args.release_base.rstrip('/')+'/'+row['basename'],row['bytes'],row['sha256'],path)
        paths[kind]=path
    restored=output/'restored'
    receipt=unpack(paths['current_W_software_archive'],paths['current_W_member_inventory'],
        archive['archive_sha256'],archive['archive_bytes'],archive['member_inventory_sha256'],
        archive['typed_software_inventory_sha256'],restored)
    need((restored/'SOFTWARE-BUNDLE.json').read_bytes()==paths['current_W_typed_inventory'].read_bytes(),
         'downloaded-inventory-exact-extracted-inventory')
    selection=parse((restored/'EXTERNAL-SELECTION.json').read_bytes())
    need(selection['profile']==PROFILE and selection['typed_software_inventory_sha256']
         ==archive['typed_software_inventory_sha256']
         and selection['wallet_source_freeze_sha256']==index['wallet_source_freeze_sha256']
         and selection['old_B05_or_D35_financial_selection_inherited'] is False,
         'new-current-W-software-authority-join')
    result={'schema':'kpx5-current-W-software-HTTPS-restore/v1',
        'externally_selected_index_sha256':args.index_sha256,
        'software_inventory_sha256':archive['typed_software_inventory_sha256'],
        'archive_sha256':archive['archive_sha256'],'unpack':receipt,
        'HTTPS_objects':receipts,'restored_root':str(restored),
        'restored_source_or_executable_imported_or_executed':False,
        'private_backup_seed_witness_or_PK_read':False,
        'old_financial_selection_used':False,'chain_currentness_or_backing_qualified':False}
    (output/'RESULT.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True))
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index-url',required=True)
    parser.add_argument('--index-sha256',required=True)
    parser.add_argument('--index-bytes',type=int,required=True)
    parser.add_argument('--release-base',required=True)
    parser.add_argument('--output',type=Path,required=True)
    restore(parser.parse_args())
