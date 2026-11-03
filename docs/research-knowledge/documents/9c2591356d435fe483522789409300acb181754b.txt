# Run the frozen public synthetic model

Run only after Root pre-execution source review. This command loads all explicit
source/artifact contents with unchanged helper09, verifies the frozen code and
design before execution, and rereads the same exact bytes afterward. Python
stdlib is the only runtime dependency. It does not read any wallet, seed,
financial private plan/state, live source or controller/owner output.

From the substantive continuation worktree:

```sh
python3 - <<'PY'
import datetime, hashlib, json, pathlib, resource, runpy, sys, time, types
h = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
root = '/home/luke/projects/kpi-intensive-2026-10-22/continuation/'
directory = 'research/next-session/local-private-payment/exit-liability-model/'
freeze_bytes = h['read'](root + directory + 'SOURCE-PINS-03.json')
freeze = json.loads(freeze_bytes)
source_path = directory + 'model01.py'
design_path = directory + 'DESIGN-01.md'
source_sha = freeze['source_pins'][source_path]['sha256']
design_sha = freeze['source_pins'][design_path]['sha256']
source = h['read'](root + source_path, source_sha)
h['read'](root + design_path, design_sha)
module = types.ModuleType('closed_outbox_model01')
sys.modules[module.__name__] = module
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
clock_start = time.monotonic()
exec(compile(source, root + source_path, 'exec'), module.__dict__)
result = module.run()
result['execution'] = {
    'started_utc': started,
    'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'wall_seconds': time.monotonic() - clock_start,
    'process_peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    'source_sha256': source_sha,
    'design_sha256': design_sha,
    'freeze_sha256': hashlib.sha256(freeze_bytes).hexdigest(),
    'python': sys.version,
    'explicit_content_reads': 'unchanged helper09 only',
    'known_public_synthetic_data_only': True,
}
h['read'](root + source_path, source_sha)
h['read'](root + design_path, design_sha)
result['execution']['before_after_source_and_design_match'] = True
output = pathlib.Path(root + directory + 'RESULT-01.json')
if output.exists():
    raise SystemExit('Refusing to overwrite a previous result')
output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
print(json.dumps({
    'status': result['status'],
    'correct_cases': len(result.get('correct', [])),
    'mutants_detected': len(result.get('mutants', [])),
    'execution': result['execution'],
}, sort_keys=True, indent=2))
if result['status'] != 'complete-bounded-model':
    raise SystemExit(1)
PY
```

The exact source freeze and Root review must be retained with RESULT-01.json.
An unexpected correct-model violation is a stop, not permission to retune the
freeze. A code defect in the experiment requires retaining the failed result,
explaining the defect and creating a separate reviewed correction before rerun.
