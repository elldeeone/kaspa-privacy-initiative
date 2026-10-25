#!/usr/bin/env python3
"""Convert3 exact ordinary-readback boundary strings once to integer sompi CASE sources."""
import argparse
from pathlib import Path
from gn3_common import GENESIS,amount,digest,encoded,fields,hx,need,parse,uint,uuid_text,write_new
from paths import HostPolicy


def boundary(value):
    need(type(value) is str and value.isascii() and value.isdecimal()
         and (value=='0' or not value.startswith('0')),'canonical-decimal-boundary')
    return uint(int(value))


def run(a):
    uuid_text(a.trial_id);guard=HostPolicy();need(len(a.observations)==len(a.observation_sha256)==3,'three-exact-ordinary-observations')
    rows=[]
    for path,sha in zip(a.observations,a.observation_sha256):
        value=parse(guard.read(path,sha))
        need(value['schema']=='kpxa-ordinary-output-readback/v1'
            and value['status']=='EXACT_ORDINARY_OUTPUT_OBSERVED_DAA_DEPTH20'
            and value['network_id']=='testnet-10' and value['genesis_hash_hex']==GENESIS
            and value['trial_id']==a.trial_id,'exact-actual-own-testnet-observation')
        output=value['output'];fields(output,{'outpoint','amount_sompi','script_public_key','block_daa_score','is_coinbase','covenant_id'},'exact-native-source-context')
        amount_sompi=boundary(output['amount_sompi']);amount(amount_sompi,True)
        need(amount_sompi>=2_100_000_000 and output['is_coinbase'] is False and output['covenant_id'] is None,'ordinary-source21KAS-headroom')
        script=hx(output['script_public_key'],36);need(script[:3]==b'\0\0\x20' and script[-1:]==b'\xac','ordinary-P2PK-source')
        point=output['outpoint'];fields(point,{'transactionId','index'},'ordinary-outpoint');hx(point['transactionId'],32);uint(point['index'],32)
        rows.append({'outpoint':point,'entry':{'amount':amount_sompi,'scriptPublicKey':script.hex(),
            'blockDaaScore':boundary(output['block_daa_score']),'isCoinbase':False,'covenantId':None}})
    need(len({(r['outpoint']['transactionId'],r['outpoint']['index']) for r in rows})==3
         and len({r['entry']['scriptPublicKey'] for r in rows})==3,'distinct3ordinary-sources')
    raw=encoded(rows)+b'\n';write_new(a.output,raw,0o400)
    return {'output':str(a.output),'sha256':digest(raw),'integer_sompi_sources':3,'signing_or_broadcast_performed':False}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--observations',type=Path,nargs=3,required=True);p.add_argument('--observation-sha256',nargs=3,required=True);p.add_argument('--trial-id',required=True);p.add_argument('--output',type=Path,required=True)
    try:print(encoded(run(p.parse_args())).decode())
    except (ValueError,OSError,KeyError,TypeError):p.exit(1,'exact ordinary source conversion incomplete\n')
