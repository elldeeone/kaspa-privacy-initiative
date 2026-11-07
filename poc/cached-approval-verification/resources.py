#!/usr/bin/env python3
"""Summarize retained device-wide samples with their real coverage limits."""
import argparse,datetime,json,pathlib,subprocess
def main():
 a=argparse.ArgumentParser();a.add_argument('combined_run',type=pathlib.Path);a.add_argument('new_output',type=pathlib.Path);p=a.parse_args();r=p.combined_run
 start=json.loads((r/'CONTROLLER-START-OBSERVATION.json').read_text())['derivedControllerStartUnix']
 birth=subprocess.check_output(['stat','-c','%w',str(r/'resource-samples.jsonl')],text=True).strip();epoch=datetime.datetime.fromisoformat(birth).timestamp()
 rows=[]
 for line in (r/'resource-samples.jsonl').read_text().splitlines():
  d=json.loads(line)
  if 'gpu' not in d or epoch+d['elapsedSeconds']<start:continue
  power,memory,util=map(float,d['gpu'].split(','));rows.append((d['elapsedSeconds'],power,memory,util))
 assert len(rows)>1
 watt_seconds=sum((b[0]-a[0])*(a[1]+b[1])/2 for a,b in zip(rows,rows[1:]));rss=[json.loads(l) for l in (r/'process-samples-from-first-authorization.jsonl').read_text().splitlines()]
 out={'scope':'whole GPU device during original paired run, after controller start; includes original mixed-cache reference, excludes later separate cold reference and funded rehearsal','samples':len(rows),'sampledSeconds':rows[-1][0]-rows[0][0],'sampledDeviceEnergyWh':watt_seconds/3600,'sampledDevicePeakMemoryMiB':max(v[2] for v in rows),'sampledDevicePeakPowerW':max(v[1] for v in rows),'maximumSamplingGapSeconds':max(b[0]-a[0] for a,b in zip(rows,rows[1:])),'processRssSumPeakKiB':max(v['summedProcessRssKiB'] for v in rss),'processRssScope':'controller and descendants; started during first authorization, shared pages can be counted more than once; not full-run USS or system RAM peak','exclusiveProcessEnergyOrWholeHostElectricityMeasured':False,'commercialCostMeasured':False}
 with p.new_output.open('x') as f:json.dump(out,f,indent=2);f.write('\n')
 print(json.dumps(out))
if __name__=='__main__':main()
