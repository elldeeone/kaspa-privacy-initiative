#!/usr/bin/env python3
"""Real onion transport to our own unfunded coordinator; fresh processes only."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]
BIN=ROOT/'.local/ci-target/release/kpi-withdrawal-followup'
TOR=ROOT/'.local/withdrawal-followup/tools/tor/usr/bin/tor'

def write(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2);f.write('\n')
def read(p):return json.loads(p.read_text())
def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def exact(s,n):
    b=b''
    while len(b)<n:
        part=s.recv(n-len(b))
        if not part:raise ConnectionError('truncated response')
        b+=part
    return b
def request(host,p,value,socks=None,source=None):
    with socket.socket() as s:
        s.settimeout(180)
        if source:s.bind((source,0))
        if socks:
            s.connect(('127.0.0.1',socks))
            s.sendall(b'\x05\x01\x02')
            assert exact(s,2)==b'\x05\x02','SOCKS auth required'
            username=b'<torS0X>0';password=secrets.token_hex(24).encode()
            s.sendall(b'\x01'+bytes([len(username)])+username+bytes([len(password)])+password)
            assert exact(s,2)==b'\x01\x00','SOCKS auth rejected'
            name=host.encode('ascii')
            s.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+struct.pack('!H',p))
            reply=exact(s,4);assert reply[:2]==b'\x05\x00',f'SOCKS refused {reply.hex()}'
            n={1:4,4:16}.get(reply[3]);n=n if n is not None else exact(s,1)[0]
            exact(s,n+2)
        else:s.connect((host,p))
        raw=json.dumps(value,separators=(',',':')).encode()
        s.sendall(struct.pack('!I',len(raw))+raw)
        return json.loads(exact(s,struct.unpack('!I',exact(s,4))[0]))

def main():
    a=argparse.ArgumentParser();a.add_argument('core',type=Path);args=a.parse_args()
    parent=ROOT/'.local/withdrawal-followup';parent.mkdir(exist_ok=True)
    run=parent/('network-'+str(uuid.uuid4()));run.mkdir(mode=0o700)
    write(run/'SELECTION.json',{'sourceCommit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'scope':'separate local clients, actual onion service and full coordinator logs; no global traffic anonymity claim','frozenAtUnix':time.time(),'torVersion':subprocess.check_output([str(TOR),'--version'],text=True).splitlines()[0],'torSha256':hashlib.file_digest(TOR.open('rb'),'sha256').hexdigest()})
    print(run,flush=True)
    processes=[];files=[];service_port=port();socks_port=port()
    try:
        for role in ('service','client'):
            data=run/(role+'-tor');data.mkdir(mode=0o700)
            config=data/'torrc'
            options=f'DataDirectory {data}\nLog notice stdout\nClientOnly 1\n'
            if role=='service':options+=f'SocksPort 0\nHiddenServiceDir {data}/onion\nHiddenServicePort 80 127.0.0.1:{service_port}\n'
            else:options+=f'SocksPort 127.0.0.1:{socks_port} IsolateSOCKSAuth\nSafeSocks 1\n'
            config.write_text(options)
            log=(run/(role+'-tor.log')).open('x');files.append(log)
            processes.append(subprocess.Popen([str(TOR),'-f',str(config)],stdout=log,stderr=subprocess.STDOUT))
        fixture=run/'fixture'
        subprocess.run([str(BIN),'privacy',str(args.core.resolve()),str(fixture)],check=True)
        deadline=time.monotonic()+900
        while not all('Bootstrapped 100%' in (run/(role+'-tor.log')).read_text() for role in ('service','client')):
            if any(p.poll() is not None for p in processes):raise RuntimeError('Tor process stopped')
            if time.monotonic()>deadline:raise TimeoutError('Tor bootstrap exceeded 900 seconds; no direct fallback')
            time.sleep(1)
        onion=(run/'service-tor/onion/hostname').read_text().strip()
        write(run/'ONION.json',{'hostname':onion,'actualServiceTargetPort':service_port,'clientSocksPort':socks_port,'bootstrapComplete':True})
        clients=[read(fixture/f'private/client-{i}.json') for i in range(3)]
        # Direct and onion counterfactuals have separate issuer replay state.
        for mode in ('direct','onion'):
            out=run/mode;out.mkdir();log=(out/'coordinator-stderr.log').open('x');files.append(log)
            server=subprocess.Popen([str(BIN),'serve',str(fixture/'config.json'),str(fixture/'private/issuer.der'),str(out/'operator.jsonl'),str(service_port)],stdout=log,stderr=log);processes.append(server)
            deadline=time.monotonic()+60
            while 'COORDINATOR_READY' not in (out/'coordinator-stderr.log').read_text():
                if server.poll() is not None:raise RuntimeError('coordinator failed')
                if time.monotonic()>deadline:raise TimeoutError('coordinator did not start')
                time.sleep(.1)
            def send(value,i):
                # Every request uses a new socket and a fresh SOCKS isolation token.
                return request(onion if mode=='onion' else '127.0.0.1',80 if mode=='onion' else service_port,value,socks_port if mode=='onion' else None,None if mode=='onion' else f'127.0.0.{i+2}')
            controls=[]
            bad=copy.deepcopy(clients[0]['issue']);bad['owner']='owner-1'
            controls.append({'case':'human_identity_field','response':send(bad,0)})
            bad=copy.deepcopy(clients[0]['issue']);bad['operation']['proof'][0]^=1
            controls.append({'case':'changed_wallet_proof','response':send(bad,0)})
            for i in (2,0,1):
                response=send(clients[i]['issue'],i);assert 'error' not in response,response
                write(out/f'issue-response-{i}.json',response)
                subprocess.run([str(BIN),'finalize',str(fixture/'config.json'),str(fixture/f'private/client-{i}.json'),str(out/f'issue-response-{i}.json'),str(out/f'redeem-{i}.json')],check=True)
                duplicate=send(clients[i]['issue'],i);assert duplicate.get('error')=='duplicate eligibility'
                controls.append({'case':'duplicate_eligibility','response':duplicate})
                if i==2:
                    early=send(read(out/f'redeem-{i}.json'),i);assert early.get('error')=='issuance barrier'
                    controls.append({'case':'early_redemption','response':early})
            # Barrier prevents immediately following an issue with its redemption.
            for i in (1,2,0):
                value=read(out/f'redeem-{i}.json')
                changed=copy.deepcopy(value);changed['message']=changed['message'][:-2]+'ff'
                controls.append({'case':'changed_recipient','response':send(changed,i)})
                response=send(value,i);assert 'error' not in response,response
                controls.append({'case':'duplicate_redemption','response':send(value,i)})
            assert all('error' in c['response'] for c in controls),controls
            write(out/'CONTROLS.json',controls)
            server.terminate();server.wait(timeout=20)
        write(run/'COMPLETE.json',{'completed':True,'applicationRequestOwners':0,'genuineWalletEligibilities':3,'actualBlindIssuanceAndUnblinding':True,'counterfactuals':['direct distinct loopback sources','onion transport fresh SOCKS auth per request'],'limits':'same host and one Tor client; service-side origin observation only; timing, known nullifiers, Sybil cohorts and global network remain attacks'})
        print('NETWORK_COMPLETE '+str(run),flush=True)
    except Exception as e:
        write(run/'FAILURE.json',{'error':str(e),'directFallbackUsed':False});raise
    finally:
        for process in processes:
            if process.poll() is None:process.terminate()
        for process in processes:
            try:process.wait(timeout=20)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        for f in files:f.close()

if __name__=='__main__':main()
