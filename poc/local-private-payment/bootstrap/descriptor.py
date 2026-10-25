#!/usr/bin/env python3
"""Bind locally validated newgenesis CASE to a recorded pre-mining birth anchor."""
import argparse
from pathlib import Path
from gn3 import validate_genesis
from gn3_common import GENESIS,digest,encoded,hx,need,parse,write_new
from gn3_selection import decode
from paths import HostPolicy


def run(a):
    guard=HostPolicy();selection=decode(guard.read(a.selection,a.selection_sha256),a.selection_sha256)
    case=parse(guard.read(a.case,a.case_sha256));initial=validate_genesis(case,selection,a.trial_id,signed=True)
    anchor=parse(guard.read(a.anchor,a.anchor_sha256))
    need(anchor['schema']=='kpxa-gn3-birth-anchor/v1' and anchor['network_id']=='testnet-10'
         and anchor['genesis_hash_hex']==GENESIS and anchor['financial_profile_sha256']==selection.profile_sha256
         and anchor['selection_file_sha256']==a.selection_sha256,'same-selected-pre-mining-anchor')
    hx(anchor['birth_start_hash'],32)
    value={'schema':'kpxa-gn3-network-descriptor/v1','network_id':'testnet-10','genesis_hash_hex':GENESIS,
        'financial_profile_sha256':selection.profile_sha256,'trial_id':a.trial_id,
        'founding_outpoint':initial['founding_outpoint'],'birth_start_hash':anchor['birth_start_hash'],
        'initial_redeem_hex':initial['redeem_hex'],'initial_redeem_sha256':digest(hx(initial['redeem_hex']))}
    raw=encoded(value)+b'\n';write_new(a.output,raw,0o400)
    return {'output':str(a.output),'sha256':digest(raw),'accepted_backing_or_currentness_claimed':False,'broadcast_performed':False}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('selection','case','anchor','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('selection-sha256','case-sha256','anchor-sha256','trial-id'):p.add_argument('--'+name,required=True)
    try:print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,KeyError,TypeError):p.exit(1,'newgenesis network descriptor incomplete\n')
