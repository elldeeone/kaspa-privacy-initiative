#!/usr/bin/env python3
"""Bounded ownership inference from complete public counterfactual-world data.

Assumes the reused proof system, encryption and RSA blindness. Does not measure
network anonymity or derive independence from three local synthetic wallets.
"""
import hashlib
import itertools
import json
from collections import Counter
from pathlib import Path

TAG=b'KPI-output-registration-v1\0'
MODE=b'RFC9474-RSABSSA-SHA384-PSS-Randomized'
DOMAIN=b'KPI-unfunded-batched-payment-effects-v1\0'

def require(ok,message):
    if not ok:raise ValueError(message)

def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def hx(v):return bytes(v).hex()
def fields(v,allowed,label):require(set(v)==set(allowed.split()),'unreviewed '+label+' fields')
def read(p):
    def pairs(items):
        d={}
        for k,v in items:
            require(k not in d,'duplicate JSON key');d[k]=v
        return d
    return json.loads(Path(p).read_text(),object_pairs_hook=pairs)

def operation(op):
    fields(op,'statement deliveries proof','operation')
    s=op['statement'];fields(s,'version kind domain verifier anchor nullifier outputs delivery deposit deposit_owner deposit_value exit_destination exit_value fee_recipient fee','statement')
    require(len(op['proof'])==128,'full wallet proof encoding')
    require(len(op['deliveries'])==2,'two delivery slots')
    for d in op['deliveries']:fields(d,'commitment ciphertext','delivery')
    return s

def state(v):
    fields(v,'root pool wallet_vk fee_refund_spk ledger','state')
    l=v['ledger'];fields(l,'verifier tree anchors nullifiers deposits exits paid_native_outputs deliveries reserve private_liability batch','ledger')
    fields(l['tree'],'leaves','tree')
    for d in l['deposits'].values():fields(d,'amount owner status','deposit')
    for d in l['exits'].values():fields(d,'amount destination paid','exit')
    for d in l['deliveries']:fields(d,'commitment ciphertext','public delivery')
    require(not l['exits'] and not l['paid_native_outputs'],'normalized paid records')
    pending=sum(d['amount'] for d in l['deposits'].values() if d['status']==0)
    require(pending+l['private_liability']==l['reserve'],'principal conservation')

def effects_context(e,root):
    fields(e,'previous index input_value outputs','effects')
    raw=DOMAIN+bytes.fromhex(root)+bytes(e['previous'])+e['index'].to_bytes(8,'little')+e['input_value'].to_bytes(8,'little')+len(e['outputs']).to_bytes(8,'little')
    for o in e['outputs']:
        fields(o,'value spk','effect output')
        raw+=o['value'].to_bytes(8,'little')+len(o['spk']).to_bytes(8,'little')+bytes(o['spk'])
    return sha(raw)

def validate_view(view):
    fields(view,'schema world initialState steps rawBincodeIsCompletePublicState sourceWorldSha256','view')
    require(view['schema']=='batched-payment-public-view-v1' and view['rawBincodeIsCompletePublicState'] is True,'public view schema');state(view['initialState'])
    w=view['world'];fields(w,'batched joint usefulPaymentSompi nativeTransactionCount totalNativeFeeSompi networkFeePercent outerProofSeconds walletSetupSeconds walletPaymentProofSeconds finalPrincipalSompi finalPrivateLiabilitySompi finalUnpaidExits transactions nativeFullValidation offlineRelayChecks chainAcceptance providerInvoiceUsd hardwareCostValuation','world')
    require(w['nativeFullValidation'] and not w['chainAcceptance'],'offline scope')
    require(w['nativeTransactionCount']==len(w['transactions'])==len(view['steps'])+1,'complete native path')
    native_fields='gas id inputs lockTime mass outputs payload subnetworkId version'
    inputs='computeBudget previousOutpoint sequence signatureScript'
    expected_old=view['initialState']['root'];expected_point=None
    exits=[]
    for i,r in enumerate(w['transactions']):
        fields(r,'kind transaction report' if i==0 else 'kind transaction report inputBincodeHex postStateBincodeHex payoutPrincipalSompi refundedFeeSompi','native record')
        base_report='computeMass feeMass feeSompi fitsBlock minimumDefaultRelayFeeSompi nativeFullValidation offlineDefaultRelayChecks serializedBytes storageMass transientMass'
        fields(r['report'],base_report if i==0 else base_report+' walletPreparationSeconds genuineNewWalletProofs proving','cost/proof report')
        if i:
            pr=r['report']['proving'];fields(pr,'claimDigest completeReceiptVerified compressedReceiptBytes compressionSeconds developmentMode image journalBytes mode nativeProofBytes operations publicProverInputsOnly sourceInputSha256 stats succinctSeconds totalProofSeconds','proving report')
            fields(pr['stats'],'paging_cycles reserved_cycles segments total_cycles user_cycles','proof stats')
            require(pr['developmentMode'] is False and pr['completeReceiptVerified'] is True and pr['publicProverInputsOnly'] is True,'genuine complete proof scope')
        tx=r['transaction'];fields(tx,native_fields,'native transaction')
        require(tx['version']==1 and tx['gas']==tx['lockTime']==0 and tx['subnetworkId']=='00'*20,'native header')
        require(len(tx['inputs'])==1,'one bank input')
        for inp in tx['inputs']:
            fields(inp,inputs,'native input');fields(inp['previousOutpoint'],'index transactionId','outpoint');require(inp['sequence']==0,'sequence')
        for o in tx['outputs']:
            fields(o,'covenant scriptPublicKey value','native output');require(o['covenant'] is None,'covenant metadata')
        if i==0:
            require(r['kind']=='deposit','deposit first');expected_point={'transactionId':tx['id'],'index':0};continue
        st=view['steps'][i-1];fields(st,'beforeState packet effects context afterState journalHex inputBincodeHex postStateBincodeHex','public step')
        state(st['beforeState']);state(st['afterState'])
        require(st['inputBincodeHex']==r['inputBincodeHex'] and st['postStateBincodeHex']==r['postStateBincodeHex'],'complete public source bytes')
        require(st['beforeState']['root']==expected_old and tx['inputs'][0]['previousOutpoint']==expected_point,'complete state/outpoint lineage')
        require(tx['inputs'][0]['computeBudget']==1600,'fixed native budget')
        e=st['effects'];require(hx(e['previous'])==expected_point['transactionId'] and e['index']==expected_point['index'],'actual previous input')
        require([(o['value'],hx(o['spk'])) for o in e['outputs']]==[(o['value'],o['scriptPublicKey']) for o in tx['outputs']],'all actual outputs including fee refund')
        require(effects_context(e,expected_old)==st['context'],'whole effects context')
        fields(st['packet'],'mode operations','public packet')
        p=st['packet'];auth=[operation(o) for o in p['operations']]
        if p['mode']==1:
            require(all(s['kind'] in (1,2) and s['exit_destination']==[0]*32 for s in auth),'actual private credit/transfers')
        else:
            require(p['mode'] in (2,4),'selected withdrawal modes')
            require(all(s['kind']==3 for s in auth),'full actual EXIT statements')
            exits += [(s,tx,st) for s in auth]
            if p['mode']==2:require(all(hx(s['exit_destination'])==st['context'] for s in auth),'whole-set binding')
        require(set(map(hx,st['beforeState']['ledger']['nullifiers']))<=set(map(hx,st['afterState']['ledger']['nullifiers'])),'economic nullifiers retained')
        expected_old=st['afterState']['root'];expected_point={'transactionId':tx['id'],'index':0}
    require(w['finalPrincipalSompi']==w['finalPrivateLiabilitySompi']==w['finalUnpaidExits']==0,'complete drainage')
    return exits

def predict(observation):
    fields(observation,'schema registration publicView sideInformation','observation')
    require(observation['schema']=='batched-payment-ownership-v1','schema')
    reg=observation['registration'];fields(reg,'schema observer mode issuerDer issuerFingerprint round denominationSompi owners events explicitOwnerLinks network','registration')
    require(reg['schema']=='common-set-observation-v1','registration schema')
    require(reg['mode'].encode()==MODE and sha(MODE+bytes.fromhex(reg['issuerDer']))==reg['issuerFingerprint'],'issuer/mode')
    owners=reg['owners'];require(len(owners)==len(set(owners))==3,'three known eligible owners')
    issues=[e for e in reg['events'] if e['kind']=='issue'];redeems=[e for e in reg['events'] if e['kind']=='redeem']
    require([e['kind'] for e in reg['events']]==['issue']*3+['redeem']*3,'issuance barrier')
    require({e['owner'] for e in issues}==set(owners),'known input owners')
    nf_owners={e['claim']:e['owner'] for e in issues}
    for e in issues:
        require(set(e)<=set('kind owner claim context walletOperation blindMessage blindSignature leakedRandomizer'.split()),'unreviewed issue field')
        s=operation(e['walletOperation']);require(hx(s['nullifier'])==e['claim'] and hx(s['exit_destination'])==e['context'],'real eligibility NF/context')
    keys=sorted(e['recipientKey'] for e in redeems)
    require(len(set(keys))==3,'three payout keys')
    for e in redeems:
        require(set(e)<=set('kind message signature randomizer recipientKey valueSompi owner'.split()),'unreviewed redeem field')
        expected=TAG+bytes.fromhex(reg['round'])+bytes.fromhex(reg['issuerFingerprint'])+reg['denominationSompi'].to_bytes(8,'little')+bytes.fromhex(e['recipientKey'])
        require(bytes.fromhex(e['message'])==expected and e['valueSompi']==reg['denominationSompi'],'actual blinded output context')
    exits=validate_view(observation['publicView'])
    require({hx(s['nullifier']) for s,_,_ in exits}==set(nf_owners),'same economic claims')
    links=[]
    payout_scripts={'000020'+k+'ac':k for k in keys}
    for s,tx,st in exits:
        require(s['exit_value']==reg['denominationSompi'],'equal denomination')
        if st['packet']['mode']==4:
            matches=[k for k in keys if sha(b'\0'+bytes.fromhex(k))==hx(s['exit_destination'])]
            require(len(matches)==1,'original public destination commitment')
            links.append((nf_owners[hx(s['nullifier'])],matches[0],'public named EXIT destination'))
        else:
            actual=[(o['scriptPublicKey'],o['value']) for o in tx['outputs'] if o['scriptPublicKey'] in payout_scripts]
            require(Counter(actual)==Counter((p,reg['denominationSompi']) for p in payout_scripts),'actual equal native payouts')
    for e in redeems:
        if 'owner' in e:links.append((e['owner'],e['recipientKey'],'revealed redemption origin'))
    for e in issues:
        if 'leakedRandomizer' in e:
            matches=[r['recipientKey'] for r in redeems if r['randomizer']==e['leakedRandomizer']]
            require(len(matches)==1,'randomizer disclosure');links.append((e['owner'],matches[0],'identified issuance randomizer'))
    for link in reg['explicitOwnerLinks']+observation['sideInformation']:
        fields(link,'owner recipientKey','side information');links.append((link['owner'],link['recipientKey'],'participant or previously published fact'))
    require(all(o in owners and k in keys for o,k,_ in links),'known side information')
    assignments=[]
    for perm in itertools.permutations(keys):
        candidate=dict(zip(owners,perm))
        if all(candidate[o]==k for o,k,_ in links):assignments.append(candidate)
    require(assignments,'contradictory observed histories')
    return {'schema':'batched-payment-prediction-v1','observationSha256':sha(canonical(observation)),'assignmentCount':len(assignments),'completeOwnershipAssignments':assignments,'uniquelyAttributedOutputs':sum(len({o for a in assignments for o,k in a.items() if k==key})==1 for key in keys),'linkSources':sorted({why for _,_,why in links}),'networkAnonymityMeasured':False,'cryptographicPropertiesAssumed':True,'includesEveryNativeRefund':True,'identifiedWithdrawnSompiByOwner':{e['owner']:operation(e['walletOperation'])['exit_value'] for e in issues},'withdrawalAmountsHidden':False}
