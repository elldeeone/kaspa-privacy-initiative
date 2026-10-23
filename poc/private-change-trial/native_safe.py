"""Lossless native serde -> pinned SDK body. No keys, network or mutation."""
import json
from pathlib import Path
import re
import sys


def hx(value, size=None):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-f]{2})*', value):
        raise ValueError('canonical hex')
    if size is not None and len(value) != size * 2:
        raise ValueError('hex width')
    return value


def script(value):
    hx(value)
    if len(value) < 4 or value[:4] != '0000':
        raise ValueError('only script public key version0 executes this policy')
    return value


def u(value,bits=64):
    if isinstance(value,bool) or not isinstance(value,(int,str)):
        raise ValueError("integer type")
    if isinstance(value,str) and not re.fullmatch(r"0|[1-9][0-9]*",value):
        raise ValueError("noncanonical integer")
    value=int(value)
    if not 0<=value<2**bits:raise ValueError("integer range")
    return str(value) if bits==64 else value


def body(t):
    if set(t)!={'version','inputs','outputs','lockTime','subnetworkId','gas','payload','mass','id'}:
        raise ValueError("unsupported native transaction fields")
    if t['version']!=1:raise ValueError("new finite trace requires native version1")
    inputs=[]
    for i in t['inputs']:
        if set(i)!={'previousOutpoint','signatureScript','sequence','computeBudget'}:
            raise ValueError("unsupported native input fields")
        p=i['previousOutpoint']
        if set(p)!={'transactionId','index'}:raise ValueError("outpoint fields")
        inputs.append({'previousOutpoint':{'transactionId':hx(p['transactionId'],32),'index':u(p['index'],32)},
            'signatureScript':hx(i['signatureScript']),'sequence':u(i['sequence']),
            'computeBudget':u(i['computeBudget'],16)})
    outputs=[]
    for o in t['outputs']:
        if set(o)!={'value','scriptPublicKey','covenant'} or o['covenant'] is not None:
            raise ValueError("unsupported output/covenant fields")
        outputs.append({'value':u(o['value']),'scriptPublicKey':script(o['scriptPublicKey']),'covenant':None})
    return {'version':1,'id':hx(t['id'],32),'inputs':inputs,'outputs':outputs,
        'lockTime':u(t['lockTime']),'subnetworkId':hx(t['subnetworkId'],20),'gas':u(t['gas']),
        'payload':hx(t['payload']),'storageMass':u(t['mass'])}


def context(entries):
    result = []
    for e in entries:
        if set(e) != {'amount_sompi', 'script_public_key', 'block_daa_score', 'is_coinbase', 'covenant_id'}:
            raise ValueError('native context fields')
        if e['covenant_id'] is not None:
            raise ValueError('native context covenant')
        if type(e['is_coinbase']) is not bool:
            raise ValueError('native context coinbase')
        result.append({'amount_sompi': u(e['amount_sompi']),
                       'script_public_key': script(e['script_public_key']),
                       'block_daa_score': u(e['block_daa_score']),
                       'is_coinbase': e['is_coinbase'], 'covenant_id': None})
    return result


if __name__=='__main__':
    is_context = sys.argv[1] == '--context'
    file = sys.argv[2] if is_context else sys.argv[1]
    print(json.dumps((context if is_context else body)(json.loads(Path(file).read_text())),separators=(',',':')))
