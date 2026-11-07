#!/usr/bin/env python3
"""Additive post-registration API refusals; no wallet secrets or bank mutation."""
import argparse,copy,hashlib,importlib.util,json,pathlib,secrets,time
ROOT=pathlib.Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('network',ROOT/'poc/withdrawal-followup/network.py');network=importlib.util.module_from_spec(s);s.loader.exec_module(network)
def main():
 a=argparse.ArgumentParser();a.add_argument('combined_run',type=pathlib.Path);run=a.parse_args().combined_run
 transport=json.loads((run/'transport.json').read_text());registration=run/'flow/registration';config=json.loads((registration/'config.json').read_text());rows=[json.loads(l) for l in (registration/'operator.jsonl').read_text().splitlines()]
 issues=[r['request'] for r in rows if r['request']['kind']=='issue' and 'error' not in r['response']];redemptions=[r['request'] for r in rows if r['request']['kind']=='redeem' and 'error' not in r['response']];assert len(issues)==len(redemptions)==3
 cases=[('unexpected human identity',{'kind':'issue','blindMessage':'','operation':{},'owner':'synthetic-control-only'},'unexpected issue field'),('unknown request kind',{'kind':'synthetic-control'},'request kind'),('replayed eligibility',issues[0],'duplicate eligibility')]
 bad=copy.deepcopy(issues[0]);op=bad['operation'];op['statement']['nullifier'][0]^=1;nf=bytes(op['statement']['nullifier']);op['statement']['exit_destination']=list(hashlib.sha256(b'KPI-anonymous-eligibility-v1\0'+bytes(config['round'])+bytes(config['issuer'])+nf+bytes.fromhex(bad['blindMessage'])).digest());op['proof'][0]^=1;cases.append(('altered new-claim wallet proof',bad,None))
 bad=copy.deepcopy(redemptions[0]);msg=bytearray.fromhex(bad['message']);msg[-32:]=bytes.fromhex(redemptions[1]['message'])[-32:];bad['message']=msg.hex();cases.append(('changed valid recipient key',bad,None))
 for name,index in [('wrong round',len(b'KPI-anonymous-eligibility-v1\0')),('wrong denomination',-40)]:
  bad=copy.deepcopy(redemptions[0]);msg=bytearray.fromhex(bad['message']);msg[index]^=1;bad['message']=msg.hex();cases.append((name,bad,'round/issuer/denomination framing'))
 bad=copy.deepcopy(redemptions[0]);sig=bytearray.fromhex(bad['signature']);sig[0]^=1;bad['signature']=sig.hex();cases.append(('corrupted blind signature',bad,None));cases.append(('replayed registered output',redemptions[0],'duplicate output'))
 selected={'scope':'additive auxiliary controls after all three valid registrations, during ongoing offline comparison; no valid extra registration or bank update','selectedAtUnix':time.time(),'cases':[v[0] for v in cases]}
 (registration/'ADDITIVE-CONTROL-SELECTION.json').write_text(json.dumps(selected,indent=2)+'\n')
 results=[]
 for name,request,expected in cases:
  response=network.request(transport['onion'],80,request,socks=transport['socks'],isolation=secrets.token_hex(24).encode());error=response.get('error');assert error,(name,response)
  if expected:assert expected in error,(name,error)
  if name=='altered new-claim wallet proof':assert error not in ('duplicate eligibility','eligibility context/value'),error
  if name=='changed valid recipient key':assert error!='duplicate output',error
  results.append({'case':name,'error':error})
 with (registration/'ADDITIVE-CONTROLS.json').open('x') as f:json.dump({'actualOnionTransport':True,'controls':results},f,indent=2);f.write('\n')
 print(len(results),'post-registration refusals passed; positive cohort unchanged',flush=True)
if __name__=='__main__':main()
