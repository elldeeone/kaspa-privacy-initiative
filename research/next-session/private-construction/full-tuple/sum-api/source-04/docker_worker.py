#!/usr/bin/env python3
"""Trusted ADR0062 controller; only owned containers, no daemon socket in parties."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

import worker

IMAGE = 'sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea'
Q = worker.Q
ENV = None


def need(value, reason): worker.need(value, reason)


def cli(*args, check=True):
    p = subprocess.run(['/usr/bin/docker', *args], capture_output=True, env=ENV)
    if check: need(p.returncode == 0, 'owned-Docker-operation-failed')
    return p


def info(name):
    p = cli('inspect', '--format', '{{json .}}', name)
    value = json.loads(p.stdout)
    need(value['Config']['Image'] == IMAGE and value['Config']['Labels'].get('kpi.sum.owned') == 'ADR0062',
         'owned-selected-container-identity')
    return value


def resources(name):
    value = info(name); state = value['State']; pid = state['Pid']; counters = None
    if pid:
        try:
            relative = next(s.split(':', 2)[2] for s in Path(f'/proc/{pid}/cgroup').read_text().splitlines()
                            if s.startswith('0::'))
            need(value['Id'] in relative, 'owned-container-cgroup')
            directory = Path('/sys/fs/cgroup') / relative.lstrip('/')
            counters = {n:(directory/n).read_text().strip() for n in
                ('cpu.stat','memory.peak','memory.swap.peak','memory.events') if (directory/n).exists()}
        except (OSError, StopIteration): pass
    return {'container_id':value['Id'],'container_name':name,'running':state['Running'],
        'PID':pid,'exit_code':state['ExitCode'],'cgroup_counters_observed':counters,
        'configured_limits':{k:value['HostConfig'][k] for k in
            ('NanoCpus','Memory','MemorySwap','PidsLimit')},
        'timestamp_monotonic':time.monotonic()}


def base(name, *, network, anchor=False):
    # 3*.9 + .1 engine/anchor CPU + <=1 controller CPU = <=3.8.
    # 3*1GiB +32MiB anchor + <=512MiB controller = <=3616MiB.
    memory, cpu = ('32m','0.1') if anchor else ('1g','0.9')
    return ['/usr/bin/docker','run','--pull=never','--name',name,
        '--label','kpi.sum.owned=ADR0062','--read-only','--cap-drop=ALL',
        '--security-opt=no-new-privileges:true','--user',f'{os.getuid()}:{os.getgid()}',
        '--cpus',cpu,'--memory',memory,'--memory-swap',memory,'--pids-limit','256',
        '--network',network,'--tmpfs','/tmp:rw,nosuid,nodev,size=64m,mode=1777',
        '--mount','type=bind,src=/usr,dst=/usr,readonly']


def finish(names, case):
    before = []
    for name in names:
        p = cli('inspect','--format','{{.Id}}',name,check=False)
        if p.returncode == 0:
            before.append(resources(name)); cli('rm','--force',name)
    absent = []
    for name in names:
        p=cli('inspect','--format','{{.Id}}',name,check=False)
        need(p.returncode != 0,'owned-container-not-removed'); absent.append(name)
    worker.save(case/'CLEANUP.json',{'owned_containers_before_removal':before,
        'owned_containers_verified_absent':absent,'images_or_unrelated_containers_changed':False})


def start_anchor(name, case, *, echo=False):
    state=case/'anchor-state';state.mkdir()
    if echo:
        code="import socket;from pathlib import Path;s=socket.socket();s.bind(('127.0.0.1',17349));s.listen();Path('/anchor/ready').write_text('READY');\nwhile True:\n c,a=s.accept();assert c.recv(4)==b'PING';c.sendall(b'PONG');c.close()"
        payload=['/usr/bin/python3','-B','-c',code]
    else: payload=['/usr/bin/sleep','infinity']
    command=base(name,network='none',anchor=True)+['--detach',
        '--mount',f'type=bind,src={state},dst=/anchor','--entrypoint','/usr/bin/env',
        IMAGE,'-i','PATH=/usr/bin:/bin','LANG=C.UTF-8','TZ=UTC',*payload]
    p=subprocess.run(command,capture_output=True,env=ENV)
    need(p.returncode==0,'owned-network-none-anchor-start')
    started=time.monotonic()
    while echo and not(state/'ready').exists():
        need(info(name)['State']['Running'],'calibration-anchor-exited')
        need(time.monotonic()-started<120,'calibration-anchor-operational-wait-incomplete')
        time.sleep(.05)
    return p.stdout.decode().strip()


def command(name,anchor,private,programs,*,party,kind,calibration=False):
    prefix=base(name,network='container:'+anchor)+['--interactive',
        '--mount',f'type=bind,src={private},dst=/work/Player-Data',
        '--mount',f'type=bind,src={private / ("P"+str(party)+".key")},dst=/work/Player-Data/P{party}.key,readonly',
        '--mount',f'type=bind,src={private / ("Input-P"+str(party)+"-0")},dst=/work/Player-Data/Input-P{party}-0,readonly',
        '--mount',f'type=bind,src={programs},dst=/work/Programs,readonly',
        '--workdir','/work']
    if calibration:
        code="from pathlib import Path;import socket,json;d=Path('/work/Player-Data');s=socket.create_connection(('127.0.0.1',17349),timeout=10);s.sendall(b'PING');assert s.recv(4)==b'PONG';s.close();print(json.dumps({'own_input_count':len(list(d.glob('Input-P*-0'))),'own_TLS_private_count':len(list(d.glob('P*.key'))),'only_loopback':all(x.split(':')[0].strip()=='lo' for x in Path('/proc/net/dev').read_text().splitlines()[2:]),'no_host_home':not Path('/home/luke').exists(),'no_daemon_socket':not Path('/var/run/docker.sock').exists(),'no_global_output':not Path('/out').exists(),'actual_isolated_shared_TCP':True}))"
        payload=['/usr/bin/python3','-B','-c',code]
    elif kind=='lost-before-input' and party==2:
        # No engine/input entry in this declared lost party.
        payload=['/usr/bin/sleep','infinity']
    else:
        prefix+=['--mount',f'type=bind,src={worker.ROOT / "mascot-party.x"},dst=/engine,readonly']
        payload=['/engine','-N','3','-I','-p',str(party),'-h','127.0.0.1','-pn','17349',
            '--prime',str(Q+2 if kind=='wrong-runtime-prime' else Q),'kpi_delta']
    return prefix+['--entrypoint','/usr/bin/env',IMAGE,'-i','PATH=/usr/bin:/bin',
        'LANG=C.UTF-8','TZ=UTC',*payload]


def stop(name):
    state=info(name)['State']
    if state['Running']:cli('kill','--signal=KILL',name)
    cli('wait',name)
    need(not info(name)['State']['Running'],'declared-lost-container-reaped')


def run_case(args, ordinal, kind, values, expected, *, calibration=False):
    identity=str(uuid.uuid4());case=worker.OUT/f'{ordinal:02d}-{kind}-{identity}';case.mkdir(mode=0o700)
    names=[f'kpi-sum-{identity}-anchor',*(f'kpi-sum-{identity}-p{i}'for i in range(3))]
    private=worker.certificates(case);programs=[];gates=[];processes=[];streams=[];samples=[]
    started=time.monotonic();markers=[False]*3;released=False;reason=None;loss_at=None
    natural_statuses=None;unexpected_survivor_sum=False;observation_end=None
    try:
        start_anchor(names[0],case,echo=calibration)
        for party,directory in enumerate(private):
            value=worker.canonical(values[party].to_bytes(32,'little'))
            (directory/f'Input-P{party}-0').write_text(str(value)+'\n')
            (directory/f'Input-P{party}-0').chmod(0o400)
            program=case/f'programs-{party}';program.mkdir()
            if not calibration:
                compiled=json.loads((Path(args.compiled_root)/'COMPILED.json').read_bytes())
                for row in compiled['files']:
                    relative=Path(row['path'])
                    need(not relative.is_absolute()and '..'not in relative.parts
                         and relative.parts[0]in('Schedules','Bytecode'),'finite-compiled-member')
                    source=Path(args.compiled_root)/'compiler/Programs'/relative
                    need(not source.is_symlink()and source.stat().st_nlink==1
                         and source.stat().st_size==row['bytes'],'fresh-staged-finite-compiled-file')
                    raw=source.read_bytes()
                    need(worker.hashlib.sha256(raw).hexdigest()==row['sha256'],'finite-compiled-member-digest')
                    destination=program/relative;destination.parent.mkdir(parents=True,exist_ok=True)
                    destination.write_bytes(raw);destination.chmod(0o400)
                (program/'Public-Input').mkdir()
                fifo=program/'Public-Input/kpi_delta';os.mkfifo(fifo,0o600)
                gates.append(os.open(fifo,os.O_RDWR|os.O_NONBLOCK))
            programs.append(program)
            stdin=(directory/f'Input-P{party}-0').open('rb')
            stdout=(case/f'party-{party}.stdout').open('xb');stderr=(case/f'party-{party}.stderr').open('xb')
            streams.extend((stdin,stdout,stderr))
            processes.append(subprocess.Popen(command(names[party+1],names[0],directory,program,
                party=party,kind=kind,calibration=calibration),stdin=stdin,stdout=stdout,stderr=stderr,env=ENV))
        while True:
            available=[]
            for name in names:
                p=cli('inspect','--format','{{.Id}}',name,check=False)
                if p.returncode==0:available.append(name)
            if len(available)==4 and kind=='lost-before-input' and reason is None:
                stop(names[3]);reason='declared-party-loss-before-engine-entry';loss_at=time.monotonic()
            for party in range(3):
                markers[party]=b'KPX6_INPUTS_COMPLETE' in(case/f'party-{party}.stdout').read_bytes()
            if all(markers) and not released:
                samples.extend(resources(name)for name in names)
                if kind=='lost-after-input':
                    stop(names[3]);reason='declared-party-loss-after-all-input-markers';loss_at=time.monotonic()
                for party,gate in enumerate(gates):
                    if not(kind=='lost-after-input' and party==2):os.write(gate,b'1\n')
                released=True
            statuses=[p.poll()for p in processes]
            if all(s is not None for s in statuses):break
            if kind in('lost-before-input','lost-after-input') and loss_at is not None:
                if any(b'KPX6_SUM 'in(case/f'party-{i}.stdout').read_bytes()for i in(0,1)):
                    unexpected_survivor_sum=True;reason='FAIL-surviving-parties-exported-sum';break
                if time.monotonic()-loss_at>=60:
                    reason='CONTROLLER_CANCEL_AFTER_60S_OPERATIONAL_INCOMPLETE_NOT_ENGINE_ABORT';break
                time.sleep(.05);continue
            if kind not in('wrong-runtime-prime',) and any(s is not None and s!=0 for s in statuses):
                reason='unexpected-party-exit';break
            if time.monotonic()-started>900:reason='operational-wait-INCOMPLETE';break
            time.sleep(.05)
        natural_statuses=[p.poll()for p in processes];observation_end=time.monotonic()
        samples.extend(resources(name)for name in available)
    finally:
        for name in names[1:]:
            p=cli('inspect','--format','{{.Id}}',name,check=False)
            if p.returncode==0 and info(name)['State']['Running']:stop(name)
        for p in processes:
            if p.poll()is None:p.wait(timeout=30)
        statuses=[p.returncode for p in processes]
        for stream in streams:stream.close()
        for gate in gates:os.close(gate)
        finish(names,case)
    sums=[re.findall(rb'KPX6_SUM ([0-9]+)',(case/f'party-{i}.stdout').read_bytes())for i in range(3)]
    if calibration:
        receipts=[json.loads((case/f'party-{i}.stdout').read_bytes())for i in range(3)]
        need(statuses==[0,0,0] and all(r=={'own_input_count':1,'own_TLS_private_count':1,
            'only_loopback':True,'no_host_home':True,'no_daemon_socket':True,'no_global_output':True,
            'actual_isolated_shared_TCP':True}for r in receipts),'actual-three-container-FS-TCP-calibration')
        report={'schema':'kpx6-installed-tools-Docker-calibration/v1','passed':True,
            'parties':receipts,'selected_image':IMAGE,'downloaded_compiler_engine_consumer_executed':False}
    else:
        complete=kind=='normal' and statuses==[0,0,0] and sums==[[str(expected).encode()]]*3
        if kind=='normal':need(complete,'actual-engine-normal-result-required-see-retained-logs')
        else:
            if any(sums)or unexpected_survivor_sum:
                worker.save(case/'FAILED.json',{'status':'FAIL','reason':'survivor-or-refused-case-exported-sum',
                    'kind':kind,'actual_sum_outputs':[[v.decode()for v in row]for row in sums],
                    'natural_statuses_before_controller_cleanup':natural_statuses,
                    'containers_removed':True})
                raise ValueError('incomplete-or-refused-case-must-not-export-sum-see-retained-FAIL')
        if kind=='lost-after-input':need(all(markers)and released,'definite-input-markers-before-loss')
        if kind=='wrong-runtime-prime':
            need(all(s!=0 for s in statuses)and all(b'Different prime for compilation and computation.'in
                (case/f'party-{i}.stderr').read_bytes()for i in range(3)),'actual-engine-prime-mismatch-refusal')
        report={'schema':'kpx6-existing-engine-sum-case/v1','identity':identity,'kind':kind,
            'status':'COMPLETE'if complete else'INCOMPLETE','expected_decimal':str(expected),
            'sum_decimal':str(int(sums[0][0]))if complete else None,'party_returncodes':statuses,
            'all_three_input_instruction_markers_observed':all(markers),'public_gate_released':released,
            'runtime_prime_decimal':str(Q+2 if kind=='wrong-runtime-prime'else Q),
            'natural_statuses_before_controller_cleanup':natural_statuses,
            'survivor_observation_seconds_after_declared_loss':observation_end-loss_at if loss_at else None,
            'operational_reason':reason,'actual_malicious_wire_injection':False,
            'financial_authorization_or_KAS_interface':False}
    report.update(wall_seconds=time.monotonic()-started,owned_container_samples=samples,
        counters_are_actual_observations_not_guaranteed_complete_lifetime_totals=True,
        all_owned_containers_removed=True)
    worker.save(case/'RESULTS.json',report);return report


def main():
    global ENV
    parser=argparse.ArgumentParser();parser.add_argument('op',choices=('calibrate-docker','run-docker'))
    parser.add_argument('--output',required=True);parser.add_argument('--compiled-root')
    args=parser.parse_args();worker.OUT=Path(args.output);worker.ROOT=Path(__file__).resolve().parent
    home=worker.OUT/'controller-home';home.mkdir();config=worker.OUT/'docker-config';config.mkdir()
    ENV=dict(worker.CLEAN,HOME=str(home),DOCKER_CONFIG=str(config),DOCKER_HOST='unix:///var/run/docker.sock')
    image=json.loads(cli('image','inspect',IMAGE,'--format','{{json .Id}}').stdout)
    need(image==IMAGE,'exact-local-image-no-pull')
    if args.op=='calibrate-docker':
        report=run_case(args,0,'calibration',(5,11,17),33,calibration=True)
        worker.save(worker.OUT/'CALIBRATION.json',report)
    else:
        compiled=json.loads((Path(args.compiled_root)/'COMPILED.json').read_bytes())
        need(compiled['prime_decimal']==str(Q),'actual-compiled-exact-prime')
        results=[]
        for i,values in enumerate(((Q-1,Q-2,6),(0,0,0),(Q-1,1,0),(5,11,17))):
            results.append(run_case(args,i,'normal',values,sum(values)%Q))
        for i,kind in enumerate(('lost-before-input','lost-after-input','wrong-runtime-prime'),start=4):
            results.append(run_case(args,i,kind,(Q-1,Q-2,6),3))
        worker.save(worker.OUT/'RESULTS.json',{'schema':'kpx6-existing-engine-sum-results/v1',
            'compiled':compiled,'cases':results,'correct_complete_count':4,
            'declared_party_loss_incomplete_count':2,'actual_engine_wrong_prime_refusal_count':1,
            'privacy_qualified':False,'adaptive_corruption_or_malicious_share_injection_tested':False})


if __name__=='__main__':main()
