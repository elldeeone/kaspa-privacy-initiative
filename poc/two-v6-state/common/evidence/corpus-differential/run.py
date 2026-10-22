import pathlib,json,hashlib,subprocess,time,sys
base=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/integration/poc/two-v6-state/common')
ev=base/'evidence/corpus-differential'
corpus=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/observer/artifacts/public-state-correctness-corpus-20261022T132924Z/public-corpus')
sha=lambda b:hashlib.sha256(b).hexdigest()
t0=time.monotonic()
manifest_bytes=(corpus/'manifest.json').read_bytes()
assert sha(manifest_bytes)=='19fc246c682a9545da41bec205535a6c76b6207dd05fdbf98ccf2fe1c9a74e6f'
m=json.loads(manifest_bytes)
cases=[]; paths=[]
for category in ('positives','negatives'):
 for case in m[category]:
  path=corpus/('negative' if category=='negatives' else '')/case['id']/'input.bin'
  wire=path.read_bytes(); assert sha(wire)==case['input_sha256']
  if category=='positives':
   assert sha(wire[:2846])=='7771a2e610d37fdb12b1d668b8e229bd3cd1e5fe83c5993847daa0fef8c93b36'
   expected=(path.parent/'expected-journal.bin').read_bytes(); assert len(expected)==336 and sha(expected)==case['journal_sha256']
   assert len(bytes.fromhex(case['next_state']))==105
  cases.append((category,case,path)); paths.append(str(path))
assert len(cases)==163
cargo=['/home/luke/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin/cargo','build','--locked','--offline','--manifest-path',str(base/'Cargo.toml'),'--target','x86_64-unknown-linux-gnu','--release','-j2','--example','evaluate_batch']
(ev/'build-command.json').write_text(json.dumps(cargo,indent=2)+'\n')
r=subprocess.run(cargo); assert r.returncode==0, 'adapter build failed'
binary=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/binding-target/x86_64-unknown-linux-gnu/release/examples/evaluate_batch')
(ev/'binary-identity.json').write_text(json.dumps({'path':str(binary),'bytes':binary.stat().st_size,'sha256':sha(binary.read_bytes())},indent=2)+'\n')
t1=time.monotonic(); actual=subprocess.run([str(binary)]+paths,text=True,capture_output=True,timeout=120)
(ev/'adapter-stdout.tsv').write_text(actual.stdout); (ev/'adapter-stderr.log').write_text(actual.stderr)
assert actual.returncode==0, 'adapter process failure is not semantic rejection'
lines=actual.stdout.splitlines(); assert len(lines)==163
results=[]
for (category,case,path),line in zip(cases,lines):
 fields=line.split('\t'); row={'id':case['id'],'category':category,'input_sha256':case['input_sha256'],'actual_status':fields[0]}
 assert fields[1]==case['input_sha256']
 if category=='positives':
  expected=(path.parent/'expected-journal.bin').read_bytes()
  matched=len(fields)==4 and fields[0]=='OK' and fields[2]==expected.hex() and fields[3]==case['next_state']
  row.update({'expected':'AcceptWithExactIndependentJournalAndState','exact_match':matched,'actual_journal_sha256':sha(bytes.fromhex(fields[2])) if fields[0]=='OK' else None,'actual_error':fields[2] if fields[0]=='ERR' else None})
 else:
  expected=case['expected_error_family']; error=fields[2] if fields[0]=='ERR' else None
  matched=error is not None and (error==expected or error.startswith(expected+'(') or error.startswith(expected+' {'))
  row.update({'expected_error':expected,'actual_error':error,'exact_match':matched,'class':case['class']})
 results.append(row)
summary={'format':'kpi-state-corpus-differential-v1','manifest_sha256':sha(manifest_bytes),'positive_count':128,'positive_exact_matches':sum(r['exact_match'] for r in results if r['category']=='positives'),'negative_count':35,'negative_semantic_or_framing_rejections':sum(r['actual_status']=='ERR' for r in results if r['category']=='negatives'),'negative_expected_family_matches':sum(r['exact_match'] for r in results if r['category']=='negatives'),'total_frozen_expectation_matches':sum(r['exact_match'] for r in results),'mismatches':[r for r in results if not r['exact_match']],'adapter_seconds':time.monotonic()-t1,'total_seconds':time.monotonic()-t0,'results':results,'scope':'NONFUNDABLE supplied synthetic context/local assertion; no backing/genesis/exit/chain qualification. Original expectations unchanged; all mismatches retained.'}
(ev/'report.json').write_text(json.dumps(summary,indent=2)+'\n')
ids=json.loads((ev/'identities-before.json').read_text()); after={p:{'bytes':pathlib.Path(p).stat().st_size,'sha256':sha(pathlib.Path(p).read_bytes())} for p in ids}; assert ids==after
(ev/'identities-after.json').write_text(json.dumps(after,indent=2)+'\n')
print(json.dumps({k:v for k,v in summary.items() if k!='results'},indent=2),flush=True)
raise SystemExit(0 if all(r['exact_match'] for r in results) else 1)
