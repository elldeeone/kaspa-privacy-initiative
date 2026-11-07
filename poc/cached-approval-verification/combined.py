#!/usr/bin/env python3
"""Own Tor processes and the finite combined-flow controller. No broadcasts."""
import argparse,importlib.util,json,os,pathlib,subprocess,time,threading
ROOT=pathlib.Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('network',ROOT/'poc/withdrawal-followup/network.py');network=importlib.util.module_from_spec(s);s.loader.exec_module(network)
def main():
 a=argparse.ArgumentParser();a.add_argument('configuration',type=pathlib.Path);c=json.loads(a.parse_args().configuration.read_text());run=pathlib.Path(c['run'])
 service,socks=network.port(),network.port();processes=[];files=[];stop=threading.Event();started=time.monotonic()
 def monitor():
  with (run/'resource-samples.jsonl').open('x') as f:
   while not stop.is_set():
    sample={'elapsedSeconds':time.monotonic()-started,'scope':'whole GPU device, not exclusive host energy'}
    try:sample['gpu']=subprocess.check_output(['nvidia-smi','--query-gpu=power.draw,memory.used,utilization.gpu','--format=csv,noheader,nounits'],text=True).strip()
    except Exception as e:sample['error']=str(e)
    f.write(json.dumps(sample)+'\n');f.flush();stop.wait(2)
 thread=threading.Thread(target=monitor);thread.start()
 try:
  for role in ('service','client'):
   data=run/(role+'-tor');data.mkdir(mode=0o700);rc=data/'torrc';options=f'DataDirectory {data}\nLog notice stdout\nClientOnly 1\n'
   options+=(f'SocksPort 0\nHiddenServiceDir {data}/onion\nHiddenServicePort 80 127.0.0.1:{service}\n' if role=='service' else f'SocksPort 127.0.0.1:{socks} IsolateSOCKSAuth\nSafeSocks 1\n');rc.write_text(options)
   log=(run/(role+'-tor.log')).open('x');files.append(log);processes.append(subprocess.Popen([str(network.TOR),'-f',str(rc)],stdout=log,stderr=subprocess.STDOUT))
  while not all('Bootstrapped 100%' in (run/(role+'-tor.log')).read_text() for role in ('service','client')):
   if any(p.poll() is not None for p in processes):raise RuntimeError('Tor stopped; no direct fallback')
   time.sleep(1)
  onion=(run/'service-tor/onion/hostname').read_text().strip();transport=run/'transport.json';transport.write_text(json.dumps({'onion':onion,'socks':socks,'servicePort':service})+'\n')
  # The diagnostic has one GPU worker. Wait for its complete comparison first.
  diagnostic=json.loads((ROOT/'.local/cached-approval-verification/CURRENT.json').read_text());diagnostic=pathlib.Path(diagnostic['run'])
  while not (diagnostic/'DIAGNOSTIC.json').exists():
   log=(diagnostic/'diagnostic.log').read_text()
   if 'Traceback' in log:raise RuntimeError('diagnostic failed; combined proving not started')
   time.sleep(1)
  env=dict(os.environ,RISC0_PROVER='ipc',RISC0_SERVER_PATH='/home/luke/projects/kpi-intensive-2026-10-22/proof-target/tools/r0vm-cuda',RISC0_HOME='/home/luke/projects/kpi-intensive-2026-10-22/observer/artifacts/groth16-compression-preparation/risc0-home',CUDA_VISIBLE_DEVICES='0',RAYON_NUM_THREADS='4',OMP_NUM_THREADS='4',MALLOC_ARENA_MAX='2',XDG_CACHE_HOME=str(run/'xdg-cache'));env.pop('RISC0_DEV_MODE',None);env.pop('KPI_BATCH_REUSE_FROM',None)
  with (run/'controller.log').open('x') as log:
   driver=subprocess.Popen([c['host'],'combined',c['settlement'],c['parameters'],str(run/'flow'),str(transport)],env=env,stdout=log,stderr=subprocess.STDOUT);processes.append(driver);print('Combined payment controller PID',driver.pid,flush=True);driver.wait();print('Controller exit',driver.returncode,flush=True)
   if driver.returncode:raise RuntimeError('combined flow failed; inspect retained logs')
  (run/'COMPLETE.json').write_text(json.dumps({'offlineCombinedFlowComplete':True,'secondsIncludingTorBootstrapAndDiagnosticWait':time.monotonic()-started,'testnetBroadcast':False})+'\n')
 finally:
  for p in processes:
   if p.poll() is None:p.terminate()
  for p in processes:
   try:p.wait(timeout=20)
   except subprocess.TimeoutExpired:p.kill();p.wait()
  stop.set();thread.join()
  for f in files:f.close()
if __name__=='__main__':main()
