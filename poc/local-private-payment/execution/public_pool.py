#!/usr/bin/env python3
"""Persistent immutable PUBLIC bytes; fixed offline roles, no signing or RPC.

Host helper09 admits each new path/pin. Only selected public bytes enter new
networkless namespaces. Controller state, listener and journals remain outside.
This is trusted local software, not external attestation or chain authority.
"""
import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import signal
import socket
import stat
import struct
import subprocess
import time

SCHEMA = 'kpxa-public-offline-pool-selection/v1'
SCOPE = 'local-offline-public-replay-and-preflight-only'
BASE = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/local-private-payment')
ENTRIES = {'replay': (str(BASE/'chain/replay_cached.py'), 'd39b264788c8b649d0037a3bae45b7101358478c2a3675817c653ded58f18b1a'),
           'preflight': (str(BASE/'chain/preflight_cached.py'), '5e1201aa51f56f7178336435947eb0d886561408d26caf49acb9718e324d7285')}
RUNTIME = '30da3b8e5573248f20753173654723cf683e3e44066ee1b6e6b0f64bbf2e1be1'
ADMISSION = 'fd47c3f8c6ae75d03be3eb335782bd68ac88e53ddbc7f6650929d6470d3db514'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def pairs(items):
        result = {}
        for key,value in items:
            need(key not in result,'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))


def canonical(value):
    need(type(value) is str and value.startswith('/') and not value.startswith('//')
         and str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts
         and '\0' not in value and '\\' not in value,'canonical absolute public path required')
    return Path(value)


def pin(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None,'canonical SHA256 required')


def write_new(path,raw):
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb') as out:
        out.write(raw);out.flush();os.fsync(out.fileno())


class SnapshotStore:
    """Serial public jobs; source admission never grants ledger authority."""
    def __init__(self,core,admit_module,private_directories,supervisor_bytes,static_files):
        self.core,self.admit_module = core,admit_module
        self.private = tuple(Path(x) for x in private_directories)
        self.static = [dict(row) for row in static_files]
        self.known,self.contents,self.targets = {},{},{}
        self.supervisor = core['sealed'](supervisor_bytes,'public-pool-supervisor')
        self.closed,self.busy = False,False
        try:
            rows,_ = self._plan(self.static,['/usr/bin/python3.14'])
            for _,_,fd in rows:
                os.close(fd)
        except BaseException:
            self.close();raise

    def _validate(self,files,argv):
        targets,sources = {},{}
        for row in files:
            need(set(row) == {'source','target','sha256','mode'},'closed immutable source row')
            target = self.core['target'](row['target'])
            need(target not in targets,'duplicate immutable target')
            source = canonical(row['source']);pin(row['sha256'])
            need(type(row['mode']) is int and row['mode'] in (0o400,0o500),'immutable input mode')
            need(not any(source == p or p in source.parents or Path(target) == p or p in Path(target).parents
                         for p in self.private),'protected source or target refused')
            identity = row['sha256']
            need(str(source) not in sources or sources[str(source)] == identity,'conflicting source identity')
            need(str(source) not in self.known or self.known[str(source)][0] == identity,'known source identity changed')
            need(target not in self.targets or self.targets[target] == row,'known target identity or mode changed')
            sources[str(source)] = identity;targets[target] = row
        need(not any(PurePosixPath(a) in PurePosixPath(b).parents for a in targets for b in targets),'input file parent conflict')
        need(all(targets.get(path,{}).get('sha256') == sha for path,sha in self.core['HELPER_PINS'].items()),'unchanged helper closure')
        need(type(argv) is list and argv and all(type(x) is str and '\0' not in x for x in argv),'explicit public command')
        need(argv[0] in targets and targets[argv[0]]['mode'] == 0o500,'selected executable required')
        return sources

    def _plan(self,files,argv):
        sources = self._validate(files,argv)
        new = [{'source':path,'sha256':identity} for path,identity in sources.items() if path not in self.known]
        began = time.perf_counter()
        raw = self.admit_module['read_many'](new,workers=4)
        pending,identities,rows = {},{},[]
        try:
            for path,identity in sources.items():
                if path in self.known:
                    identities[path] = self.known[path];continue
                body = raw[(path,identity)]
                need(digest(body) == identity,'new public bytes differ')
                key = (identity,len(body))
                if key not in self.contents and key not in pending:
                    pending[key] = self.core['sealed'](body,'admitted-public-content')
                identities[path] = (identity,len(body),key)
            def cached(path,sha):
                identity = identities[str(path)]
                need(identity[0] == sha,'cached selection differs')
                fd = self.contents.get(identity[2],pending.get(identity[2]))
                body = os.pread(fd,identity[1],0)
                need(len(body) == identity[1] and digest(body) == sha,'sealed public bytes differ')
                return body
            manifest = {'schema':'kpxa-public-snapshot-prototype/v1','scope':self.core['SCOPE'],
                        'files':files,'argv':argv,'exports':[],'network':'none'}
            rows = self.core['admit'](manifest,cached,self.private)
            self.contents.update(pending);pending = {}
            self.known.update(identities)
            self.targets.update({r['target']:dict(r) for r in files})
            return rows,{'admitted_new_sources':len(new),'reused_sources':len(sources)-len(new),
                         'admission_seconds':time.perf_counter()-began}
        except BaseException:
            for _,_,fd in rows:
                os.close(fd)
            raise
        finally:
            for fd in pending.values():
                os.close(fd)

    def execute(self,argv,files,output):
        need(not self.closed and not self.busy,'serial live snapshot store required')
        self.busy = True
        rows,fds,empty = [],[],[]
        try:
            output = canonical(str(output))
            need(output.name == 'result' and output.parent != Path('/'),'pool-only parent/result required')
            need(not output.parent.exists() and not output.parent.is_symlink(),'fresh pool-only output parent required')
            need(not any(output == p or p in output.parents for p in self.private),'protected output refused')
            for parent in output.parents:
                need(not parent.is_symlink(),'public output ancestor symlink')
            selected = {r['target']:r for r in self.static}
            seen = set()
            for row in files:
                need(set(row) == {'source','sha256','mode'},'closed dynamic public row')
                need(row['source'] not in seen,'duplicate dynamic source')
                seen.add(row['source'])
                full = {**row,'target':row['source']}
                need(full['target'] not in selected or selected[full['target']] == full,'static target replacement refused')
                selected[full['target']] = full
            plan = list(selected.values())
            need(not any(Path(r['target']) == output.parent or output.parent in Path(r['target']).parents for r in plan),
                 'writable output parent overlaps immutable input')
            rows,stats = self._plan(plan,argv)
            fds = [fd for _,_,fd in rows]
            request = {'schema':'kpxa-public-pool-execution/v1','scope':self.core['SCOPE'],
                       'argv':argv,'output_root':str(output),'synthetic_stubs':list(self.core['STUBS'])}
            request_fd = self.core['sealed'](encoded(request),'public-pool-request')
            fds.append(request_fd)
            os.lseek(self.supervisor,0,os.SEEK_SET)
            command,empty = self.core['command'](rows,request_fd,self.supervisor,output_root=str(output))
            began = time.perf_counter()
            child = subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,close_fds=True,
                pass_fds=tuple(fds+[self.supervisor]+empty),env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC'})
            need(child.returncode == 0,'public namespace supervisor refused execution')
            result = parse(child.stdout)
            need(result['schema'] == 'kpxa-public-pool-execution-result/v1' and result['scope'] == self.core['SCOPE']
                 and result['network'] == 'none' and result['private_mounts_or_owner_authority'] is False
                 and result['inherited_nonstdio_fds'] == [] and type(result['returncode']) is int,'typed isolated result')
            if result['returncode'] == 0:
                need(base64.b64decode(result['stderr_base64'],validate=True) == b'','successful offline role emitted stderr')
                self.core['write_exports'](result,output)
            else:
                need(result['exports'] == [],'failed role cannot export successful evidence')
            result.update(stats)
            result['wall_seconds'] = time.perf_counter()-began
            return result
        finally:
            self.busy = False
            for fd in fds+empty:
                os.close(fd)

    def close(self):
        if not self.closed:
            self.closed = True
            for fd in self.contents.values():
                os.close(fd)
            os.close(self.supervisor)


PAIRS = {'selection','selection-sha256','descriptor','descriptor-sha256','fetch','fetch-sha256',
    'assets','assets-sha256','parameters','parameters-sha256','codec','codec-sha256','bundle-directory','output',
    'runtime-source','runtime-source-sha256','cache-admission','cache-admission-sha256',
    'baseline-fetch','baseline-fetch-sha256','baseline-bundle-directory','baseline-cache','baseline-cache-sha256',
    'crypto','node','native-validator','sdk-directory'}
FIXED = {'selection','selection-sha256','descriptor','descriptor-sha256','assets','assets-sha256',
    'parameters','parameters-sha256','codec','codec-sha256','runtime-source','runtime-source-sha256',
    'cache-admission','cache-admission-sha256'}
OPTIONAL_FIXED = {'crypto','node','native-validator','sdk-directory'}
FILE_OPTIONS = {'selection','descriptor','fetch','assets','parameters','codec','runtime-source','cache-admission',
                'baseline-fetch','baseline-cache','case'}


def load_selection(row,read):
    canonical(row['path']);pin(row['sha256'])
    value = parse(read(row['path'],row['sha256']))
    need(value['schema'] == SCHEMA and value['scope'] == SCOPE,'explicit offline pool selection')
    need(value['parent_runtime']['sha256'] == RUNTIME and value['parent_admission']['sha256'] == ADMISSION,
         'unchanged financial runtime and admission required')
    need(set(value['roles']) == set(ENTRIES),'only fixed offline financial roles')
    for role,(path,sha) in ENTRIES.items():
        need(value['roles'][role]['entry'] == {'path':path,'sha256':sha},'unchanged old role entry required')
    selected_inputs = {member['target']:member for member in value['static_files']}
    for path,sha in ENTRIES.values():
        need(selected_inputs.get(path,{}).get('sha256') == sha,'old role source is immutable selected input')
    for parent in ('parent_runtime','parent_admission'):
        member = value[parent]
        need(selected_inputs.get(member['path'],{}).get('sha256') == member['sha256'],'old authority selection is immutable input')
    members = {}
    for member in value['source_members']:
        canonical(member['path']);pin(member['sha256'])
        need(member['path'] not in members,'unique outer wrapper source')
        members[member['path']] = member['sha256']
        read(member['path'],member['sha256'])
    for name in ('server','client','core','supervisor','admit'):
        selected = value[name]
        need(members.get(selected['path']) == selected['sha256'],'every executed wrapper selected')
    need(value['server']['path'] == str(Path(__file__).absolute()),'selected actual server entry')
    return value


def role_argv(selection,role,argv,files,output):
    need(role in ENTRIES and type(argv) is list and all(type(x) is str and '\0' not in x for x in argv),'closed old role flags')
    values,index = {},0
    allowed = PAIRS | ({'case','case-sha256','trial-id','stage','mode'} if role == 'preflight' else set())
    while index < len(argv):
        option = argv[index]
        need(option.startswith('--') and option[2:] not in values,'distinct old role options')
        key = option[2:]
        if key == 'trusted-local-cache':
            values[key] = True;index += 1;continue
        need(key in allowed and index+1 < len(argv) and not argv[index+1].startswith('--'),'closed old role option/value')
        values[key] = argv[index+1];index += 2
    fixed = selection['roles'][role]['fixed_arguments']
    need(FIXED <= set(fixed) and not (set(fixed)-FIXED-OPTIONAL_FIXED-{'mode','trial-id'}),'closed fixed arguments')
    need(all(values.get(k) == v for k,v in fixed.items()),'same fixed financial selection required')
    need(not any(k in values and k not in fixed for k in OPTIONAL_FIXED),'runtime override refused')
    required = FIXED | {'fetch','fetch-sha256','bundle-directory','output','baseline-fetch','baseline-fetch-sha256','baseline-bundle-directory'}
    if role == 'preflight':
        required |= {'case','case-sha256','trial-id','stage','mode'}
        need(values.get('mode') == 'lifecycle','pool preflight is lifecycle only')
    need(required <= set(values) and values['output'] == str(output),'complete exact old role arguments')
    need(('baseline-cache' in values) == ('baseline-cache-sha256' in values),'complete optional cache selector')
    for key,value in values.items():
        if key.endswith('-sha256'):
            pin(value)
    identities = {r['target']:(r['source'],r['sha256']) for r in selection['static_files']}
    identities.update({r['source']:(r['source'],r['sha256']) for r in files})
    for key in FILE_OPTIONS & set(values):
        canonical(values[key])
        need(identities.get(values[key]) == (values[key],values[key+'-sha256']),'role selector must be admitted')
    canonical(values['bundle-directory']);canonical(values['baseline-bundle-directory'])
    return ['/usr/bin/python3','-B',ENTRIES[role][0],*argv]


def receive(stream):
    def exact(count):
        parts = []
        while count:
            body = stream.recv(count)
            need(body,'incomplete local pool frame')
            parts.append(body);count -= len(body)
        return b''.join(parts)
    width = struct.unpack('<Q',exact(8))[0]
    need(0 < width < 1 << 63,'local pool frame width')
    return parse(exact(width))


def send(stream,value):
    body = encoded(value)
    stream.sendall(struct.pack('<Q',len(body))+body)


def serve(a):
    if a.parent_pid is not None:
        need(a.parent_pid > 1 and os.getppid() == a.parent_pid,'selected caller parent required')
        libc = ctypes.CDLL(None,use_errno=True)
        need(libc.prctl(1,signal.SIGTERM,0,0,0) == 0,'caller-death binding required')
        need(os.getppid() == a.parent_pid,'caller vanished during startup')
    helper = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
    read = helper['read']
    row = {'path':str(a.pool_selection),'sha256':a.pool_selection_sha256}
    selection = load_selection(row,read)
    def module(name):
        selected = selection[name]
        namespace = {'__name__':'public_pool_'+name,'__file__':selected['path']}
        exec(compile(read(selected['path'],selected['sha256']),selected['path'],'exec'),namespace)
        return namespace
    core,admit = module('core'),module('admit')
    store = SnapshotStore(core,admit,helper['m'].GUARD.directories,
        read(selection['supervisor']['path'],selection['supervisor']['sha256']),selection['static_files'])
    address = canonical(selection['socket'])
    listener = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    bound = False
    try:
        need(not address.exists() and not address.is_symlink(),'fresh local pool socket required')
        for parent in address.parents:
            need(not parent.is_symlink(),'local pool socket ancestor symlink')
        need(address.parent.is_dir() and address.parent.stat().st_uid == os.getuid()
             and stat.S_IMODE(address.parent.stat().st_mode) == 0o700,'caller-owned private IPC directory required')
        listener.bind(str(address));bound = True
        os.chmod(address,0o600);listener.listen()
        while True:
            connection,_ = listener.accept()
            with connection:
                try:
                    message = receive(connection)
                    need(set(message) == {'schema','pool_selection','role','request','output'}
                         and message['schema'] == 'kpxa-public-offline-pool-call/v1' and message['pool_selection'] == row,
                         'selected local pool call required')
                    request_row = message['request']
                    need(set(request_row) == {'path','sha256'},'closed public request selector')
                    canonical(request_row['path']);pin(request_row['sha256'])
                    # Each new public request receives the same unchanged guard
                    # with current private metadata, never a cleared old guard.
                    # The actual immutable Original leaves remain preserved.
                    request_read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
                    request = parse(request_read(request_row['path'],request_row['sha256']))
                    need(set(request) == {'schema','role','argv','files'} and request['schema'] == 'kpxa-public-offline-role-job/v1'
                         and request['role'] == message['role'],'closed offline role job')
                    output = canonical(message['output'])
                    need(canonical(selection['public_output_prefix']) in output.parents,'selected public output namespace')
                    argv = role_argv(selection,request['role'],request['argv'],request['files'],output)
                    result = store.execute(argv,request['files'],output)
                    if result['returncode'] == 0:
                        provenance = {'schema':'kpxa-public-offline-pool-provenance/v1','pool_selection':row,
                            'role':request['role'],'request':request_row,'output':str(output),
                            'stdout_sha256':digest(base64.b64decode(result['stdout_base64'],validate=True)),
                            'role_entry':selection['roles'][request['role']]['entry'],'argv_sha256':digest(encoded(request['argv'])),
                            'exported_files':[{k:r[k] for k in ('path','sha256','bytes')} for r in result['exports']],
                            'network':'none',**{k:result[k] for k in ('admitted_new_sources','reused_sources','admission_seconds','namespace_seconds')}}
                        write_new(output/'POOL-PROVENANCE.json',encoded(provenance)+b'\n')
                    send(connection,{'schema':'kpxa-public-offline-pool-reply/v1','pool_selection':row,
                         'role':request['role'],'request':request_row,'output':str(output),
                         **{k:result[k] for k in ('returncode','stdout_base64','stderr_base64')}})
                except (ValueError,OSError,KeyError,TypeError):
                    try:
                        send(connection,{'schema':'kpxa-public-offline-pool-error/v1','error':'public offline role incomplete'})
                    except OSError:
                        pass
    finally:
        listener.close();store.close()
        if bound and address.is_socket():
            address.unlink()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pool-selection',type=Path,required=True)
    parser.add_argument('--pool-selection-sha256',required=True)
    parser.add_argument('--parent-pid',type=int)
    serve(parser.parse_args())
