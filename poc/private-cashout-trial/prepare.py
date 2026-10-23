#!/usr/bin/env python3
"""Private local four-body preparation. No RPC, setup or broadcast interface."""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
from pathlib import Path
import secrets
import subprocess

import action as a
import trial as t

NATIVE = t.RELEASE / 'native-action'
NATIVE_SHA = 'f6139cea85a30f092447efe199796f62c540b0399d63e949845423678d4bdc44'
GENERIC = t.RELEASE / 'native-validator'
GENERIC_SHA = '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'


def save(path, value):
    t.private_write(path, t.encoded(value))


def read(path):
    path=Path(path).absolute()
    t.no_symlinks(path)
    return t.parse_json(path.read_bytes())


def mkdir(path):
    if not path.exists():
        mkdir(path.parent)
        t.private_dir(path)


def fresh(path, parent):
    path = t.outside_git(path)
    t.require(parent in path.parents and not path.exists(), 'fresh-private-output-inside-trial')
    mkdir(path)
    return path


def context_entry(amount, spk, daa='0'):
    t.require(type(amount) is int and 0<amount<=a.MAX and type(spk) is str
        and re.fullmatch('0000(?:[0-9a-f]{2})+',spk) is not None,'public-UTXO-amount-SPK')
    t.require(type(daa) is int or type(daa) is str and re.fullmatch('0|[1-9][0-9]*',daa),
              'public-UTXO-DAA')
    t.require(0<=int(daa)<=0xffffffffffffffff,'public-UTXO-DAA-range')
    return {'amount_sompi': str(amount), 'script_public_key': spk,
        'block_daa_score': str(daa), 'is_coinbase': False, 'covenant_id': None}


def sdk_body(native):
    return {'version': native['version'], 'id': native['id'],
        'inputs': [{**row, 'sequence': str(row['sequence'])} for row in native['inputs']],
        'outputs': [{**row, 'value': str(row['value']), 'covenant': None} for row in native['outputs']],
        'lockTime': str(native['lockTime']), 'subnetworkId': native['subnetworkId'],
        'gas': str(native['gas']), 'payload': native['payload'],
        'storageMass': str(native['mass'])}


def native_body(sdk):
    return {'version': sdk['version'], 'id': sdk['id'],
        'inputs': [{**row, 'sequence': int(row['sequence'])} for row in sdk['inputs']],
        'outputs': [{**row, 'value': int(row['value'])} for row in sdk['outputs']],
        'lockTime': int(sdk['lockTime']), 'subnetworkId': sdk['subnetworkId'],
        'gas': int(sdk['gas']), 'payload': sdk['payload'], 'mass': int(sdk['storageMass'])}


def sdk_call(body, contexts, funding_secret=None):
    request = {'schema': 'kpx3-offline-sdk-body/v1', 'network_id': 'testnet-10',
        'genesis_hash_hex': t.GENESIS, 'mode': 'sign-founding' if funding_secret else 'roundtrip',
        'transaction': sdk_body(body), 'contexts': contexts}
    if funding_secret:
        request['funding_secret_hex32'] = funding_secret
    process=t.node_run([str(Path(__file__).with_name('sdk.mjs'))],input_text=json.dumps(request))
    t.require(process.returncode == 0, 'offline-SDK-body-failed')
    result = t.parse_json(process.stdout)
    t.require(result['lossless_safe_roundtrip'] is True, 'SDK-safe-roundtrip')
    return native_body(result['transaction'])


class Context:
    def __init__(self, directory):
        self.directory, self.profile = t.load_profile(directory)
        self.module, self.crypto, _ = t.runtime(t.DEFAULT_BRIDGE, t.DEFAULT_SDK)
        self.domain = bytes.fromhex(self.profile['domain_hex32'])
        self.seeds = {name: bytes.fromhex(self.profile['secrets'][name+'_seed_hex32'])
                      for name in ('alice','bob','charlie')}
        self.wallets = {name: self.module.Receiver(seed, self.domain, self.crypto)
                        for name,seed in self.seeds.items()}

    def close(self):
        self.crypto.close()

    def recipe(self):
        return {'rho': [secrets.token_bytes(32).hex() for _ in range(5)],
            'dummy_inputs': [[secrets.token_bytes(32).hex(),secrets.token_bytes(32).hex()] for _ in range(6)],
            'dummy_ciphers': [a.sealed_dummy(self.crypto,secrets.token_bytes(32),
                secrets.token_bytes(216)).hex() for _ in range(2)]}

    def payment(self, fee, recipe, previous):
        rho = [bytes.fromhex(value) for value in recipe['rho']]
        amount = 2*a.FLOOR + fee
        raw,record = a.receipt(self.module,self.wallets['alice'],amount,0,rho[0])
        before = self.module.Snapshot([record],[self.module.NFEntry(a.ZERO,a.ZERO,0)])
        order=recipe['recipient_order']
        t.require(type(order) is list and sorted(order)==['bob','charlie'],'private-recipient-permutation')
        outputs = [a.receipt(self.module,self.wallets[name],a.FLOOR,pos,rho[pos])
                   for pos,name in enumerate(order,1)]
        after,fixture,public = a.action(self.module,self.domain,before,
            [(0,self.wallets['alice']),None],outputs,previous,amount,fee,0,bytes(36),
            [tuple(bytes.fromhex(value) for value in row) for row in recipe['dummy_inputs'][:2]])
        return raw,record,before,after,fixture,public

    def own_claim(self, owner, current):
        recovered=self.module.recover(self.wallets[owner],current.pin(self.domain),current)
        claims=[row for row in recovered.owned if row.owner_action_available]
        t.require(len(claims)==1 and claims[0].receipt.value_sompi==a.FLOOR
            and claims[0].receipt.index==0 and not claims[0].privacy_contaminated,
            'one-independent-recognized-claim')
        return claims[0]


def shape(directory):
    ctx = Context(directory)
    try:
        output = fresh(ctx.directory/'local-shape',ctx.directory)
        recipe = ctx.recipe()
        recipe['recipient_order']=['bob','charlie']  # New setup shapes only; actual recipes shuffle.
        _,_,_,_,fixture,_ = ctx.payment(20_000_000,recipe,bytes(36))
        save(output/'recipe.json',recipe)
        save(output/'witness.json',fixture)
        save(output/'SHAPE.json',{'schema':'kpx3-private-local-shape/v1',
            'trial_id':ctx.profile['trial_id'],'domain_hex32':ctx.domain.hex(),
            'setup_or_proof_performed':False,'native_VM_performed':False})
        return {'phase':'private-shape-created','trial_id':ctx.profile['trial_id'],
                'setup_or_proof_performed':False}
    finally:ctx.close()


def transaction(previous, outputs, payload, signature, budget):
    return {'version':1,'id':bytes(32).hex(),'inputs':[{'previousOutpoint':previous,
        'signatureScript':signature.hex(),'sequence':0xffffffffffffffff,'computeBudget':budget}],
        'outputs':[{'value':value,'scriptPublicKey':spk,'covenant':None} for value,spk in outputs],
        'lockTime':0,'subnetworkId':bytes(20).hex(),'gas':0,'payload':payload.hex(),'mass':0}


def normalize(runtime, body, contexts, output):
    for row in contexts:
        t.require(set(row)=={'amount_sompi','script_public_key','block_daa_score','is_coinbase','covenant_id'}
            and row['is_coinbase'] is False and row['covenant_id'] is None
            and row==context_entry(int(row['amount_sompi']),row['script_public_key'],row['block_daa_score']),
            'exact-noncoinbase-uncovenanted-context')
    entries = [{'amount':int(row['amount_sompi']),'scriptPublicKey':row['script_public_key'],
                'blockDaaScore':int(row['block_daa_score']),'isCoinbase':False,'covenantId':None}
               for row in contexts]
    source = output.with_suffix('.input.json')
    save(source,{'transaction':body,'entries':entries})
    process = runtime.run(['control-normalize-freeze',str(source),str(output)])
    t.require(process.returncode == 0,'generic-noVM-normalization')
    result,metrics = read(output/'transaction.json'),read(output/'metrics.json')
    save(output/'strict-context.json',contexts)
    return result,metrics


def genesis(runtime, ctx, vk, raw, record):
    request={'schema':'kpx3-public-native-action/v1','mode':'genesis','network_id':'testnet-10',
        'genesis_hash_hex':t.GENESIS,'domain_hex32':ctx.domain.hex(),'vk_hex328':vk.hex(),
        'note_hex168':raw.hex(),'cipher_hex264':record.ciphertext.hex()}
    process=runtime.run([],input_text=json.dumps(request))
    t.require(process.returncode==0,'approved-public-genesis-constructor')
    result=t.parse_json(process.stdout)
    before=ctx.module.Snapshot([record],[ctx.module.NFEntry(a.ZERO,a.ZERO,0)])
    expected_payload=(b'KPX2GN01'+ctx.domain+raw+a.h(b'KPX1NOT\0',ctx.domain,raw)
                      +record.ciphertext+a.h(record.ciphertext))
    t.require(result['state_hex112']==a.state(ctx.domain,before).hex()
        and len(bytes.fromhex(result['redeem_hex']))==24417
        and bytes.fromhex(result['redeem_hex'])[2:114]==a.state(ctx.domain,before)
        and result['script_public_key_hex']==pool_spk(bytes.fromhex(result['redeem_hex']))
        and result['payload_hex536']==expected_payload.hex()
        and int(result['reserve_sompi'])==int.from_bytes(raw[64:72],'little'),
        'genesis-state-program-payload-value')
    return result


def private_transaction(public, redeem, previous, current_spk):
    auth=bytes.fromhex(public['auth_hex528']);remaining=int.from_bytes(auth[476:484],'little')
    t.require(len(redeem)==24417 and current_spk==pool_spk(redeem)
        and auth[76:188]==redeem[2:114]
        and auth[40:76]==bytes.fromhex(previous['transactionId'])+a.u32(previous['index']),
        'private-current-program-state-outpoint')
    payout=int.from_bytes(auth[484:492],'little');outputs=[]
    if remaining:
        successor=redeem[:2]+auth[364:476]+redeem[114:]
        spk=pool_spk(successor)
        outputs.append((remaining,spk))
    if payout:outputs.append((payout,auth[492:528].hex()))
    frame=b'\x41'+bytes(65)+b'\x4c\x80'+bytes(128)+b'\x4d'+len(redeem).to_bytes(2,'little')+redeem
    payload=auth+bytes.fromhex(public['cipher_hex528'])+bytes.fromhex(public['public_witness_hex3344'])
    return transaction(previous,outputs,payload,frame,1600)


def hashlib_blake(raw):
    # Native P2SH uses Kaspa's established unkeyed BLAKE2b-256 constructor.
    import hashlib
    return hashlib.blake2b(raw,digest_size=32).digest()


def pool_spk(redeem):
    return (b'\0\0\xaa\x20'+hashlib_blake(redeem)+b'\x87').hex()


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['shape'])
    parser.add_argument('trial',type=Path)
    args=parser.parse_args()
    print(json.dumps(shape(args.trial),sort_keys=True))


if __name__=='__main__':main()
