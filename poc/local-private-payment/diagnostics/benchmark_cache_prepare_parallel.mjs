// Root-selected public-corpus benchmark only. Never admits cache or financial state.
import fs from 'node:fs';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {performance} from 'node:perf_hooks';
import {fileURLToPath} from 'node:url';
import {guardedRead} from '../chain/public.mjs';
import {canonical,checkedPath,strictJson} from '../chain/selection.mjs';
import {sha} from '../chain/wire.mjs';
import {prepareBaseParallel} from '../chain/cache_prepare_parallel.mjs';

const need=(condition,message)=>{if(!condition)throw new Error(message);};
const args={};for(let i=2;i<process.argv.length;i+=2){need(['--selection','--selection-sha256'].includes(process.argv[i])&&process.argv[i+1]&&!args[process.argv[i]],'closed benchmark arguments');args[process.argv[i]]=process.argv[i+1];}
need(Object.keys(args).length===2,'both selection arguments required');
const rawSelection=guardedRead(args['--selection'],args['--selection-sha256']),s=strictJson(rawSelection);
need(s.schema==='kpxa-six-guard-preparation-benchmark/v1'&&s.financial_admission===false&&s.expected_pages===217,'selected preparation-only benchmark');
need(Array.isArray(s.source_members)&&new Set(s.source_members.map(row=>row.path)).size===s.source_members.length,'unique selected source rows');
for(const required of [fileURLToPath(import.meta.url),fileURLToPath(new URL('../chain/cache_prepare_parallel.mjs',import.meta.url))])need(s.source_members.some(row=>row.path===required),'required benchmark source row');
for(const row of s.source_members){need(typeof row.path==='string'&&path.isAbsolute(row.path)&&/^[0-9a-f]{64}$/.test(row.sha256)&&Number.isSafeInteger(row.bytes)&&row.bytes>0,'selected source identity');const raw=guardedRead(row.path,row.sha256);need(raw.length===row.bytes,'selected source size');}
const handoff=strictJson(guardedRead(s.baseline_handoff.path,s.baseline_handoff.sha256));
need(handoff.accepted_whole_CASE_equals_expected===true&&handoff.accepted_transactions===11,'selected accepted baseline identity only');
for(const [name,row]of [['fetch.json',s.baseline_fetch],['CACHE.json',s.baseline_cache]])need(handoff.selectors[name].path===row.path&&handoff.selectors[name].sha256===row.sha256,'baseline selectors');
const base=strictJson(guardedRead(s.baseline_fetch.path,s.baseline_fetch.sha256));
const prior=strictJson(guardedRead(s.baseline_cache.path,s.baseline_cache.sha256));
need(canonical(prior.fetch)===canonical(s.baseline_fetch),'selected cache identity only');
const oldStop=strictJson(guardedRead(s.golden_trace_result.path,s.golden_trace_result.sha256));
need(oldStop.prepared_pages===217&&oldStop.status==='INCOMPLETE_PUBLIC_ACQUISITION'&&oldStop.financial_action===false,'golden is preparation output, not financial acceptance');
const begin=strictJson(guardedRead(s.serial_prepare_start.path,s.serial_prepare_start.sha256));
const end=strictJson(guardedRead(s.serial_prepare_end.path,s.serial_prepare_end.sha256));
need(begin.phase==='original-prepare-before-connect-start'&&end.phase==='original-prepare-before-connect-end'&&end.pages===217,'old preparation markers');
need(base.pages.length===216&&base.current_view.post_query_delta.pages.length===1&&s.expected_prepared.pages.length===217,'exact public217 corpus');
const output=checkedPath(s.output_root),parent=path.dirname(output);
need(parent==='/dev/shm/kpi-cache-parallel-prep-benchmark-01','dedicated benchmark parent');
try{fs.mkdirSync(parent,{mode:0o700});}catch(error){if(error.code!=='EEXIST')throw error;}
const ps=fs.lstatSync(parent);need(ps.isDirectory()&&!ps.isSymbolicLink()&&ps.uid===process.getuid()&&(ps.mode&0o777)===0o700&&!fs.existsSync(output),'fresh owned benchmark output');
const space=fs.statfsSync(parent),mem=/^MemAvailable:\s+(\d+) kB$/m.exec(fs.readFileSync('/proc/meminfo','utf8'));
need(Number(space.bavail)*Number(space.bsize)>=s.minimum_tmpfs_free_bytes&&mem&&Number(mem[1])*1024>=s.minimum_mem_available_bytes,'public pre-run headroom');
fs.mkdirSync(output,{mode:0o700});
const result={schema:'kpxa-six-guard-preparation-benchmark-result/v1',selection_sha256:args['--selection-sha256'],financial_admission:false,
 no_network_or_financial_action:true,golden_trace_was_not_accepted:true,concurrency:6,source_or_admission_time_in_timed_window:false,
 old_serial_prepare_seconds:(end.monotonic_ms-begin.monotonic_ms)/1000,old_serial_is_historical_unpaired_observation:true};
const started=performance.now(),cpu=process.cpuUsage();
try{
 const prepared=await prepareBaseParallel({base},{'baseline-bundle-directory':path.dirname(s.baseline_fetch.path)},output);
 result.parallel_prepare_seconds=(performance.now()-started)/1000;result.parent_node_cpu_microseconds=process.cpuUsage(cpu);
 need(canonical(prepared.pages)===canonical(s.expected_prepared.pages),'all217 prepared records differ');
 need(canonical(prepared.frontier)===canonical(s.expected_prepared.frontier)&&prepared.accepted===s.expected_prepared.accepted,'prepared frontier/count differ');
 need(prepared.fingerprint===sha(canonical({pages:s.expected_prepared.pages,frontier:s.expected_prepared.frontier,accepted:s.expected_prepared.accepted})),'prepared fingerprint differs');
 const expectedEdges=new Map();for(let i=1;i<base.transactions.length;i++){const row=base.transactions[i],p=row.transaction.inputs[0].previousOutpoint;
  expectedEdges.set(`${p.transactionId}:${p.index}`,[{page:row.source_page_index,group:row.source_group_index,transaction:row.source_transaction_index,id:row.transaction.id,input_index:0}]);}
 const founding=base.transactions[0];need(canonical([...prepared.edges])===canonical([...expectedEdges])&&canonical(prepared.founding)===canonical({page:founding.source_page_index,group:founding.source_group_index,transaction:founding.source_transaction_index,id:founding.transaction.id})&&prepared.base===base,'unchanged metadata result differs');
 result.all217_records_fingerprint_and_graph_match=true;
 // Post-verification is outside the timed window. Use the unchanged helper for BOTH bodies.
 const verifyCode="import runpy,json,sys,os\nh=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')\ns=json.loads(h['read'](sys.argv[1],sys.argv[2]))\nassert s['schema']=='kpxa-six-guard-preparation-benchmark/v1' and len(s['expected_prepared']['pages'])==217\nassert sys.argv[3]==s['output_root']\nfor row in s['expected_prepared']['pages']:\n name=row['path'];assert name.startswith('cached/') and '..' not in name.split('/') and not os.path.isabs(name)\n old=h['read'](os.path.join(s['golden_root'],name),row['gzip_sha256'])\n new=h['read'](os.path.join(sys.argv[3],name),row['gzip_sha256'])\n assert len(old)==len(new)==row['gzip_bytes'] and old==new\nprint(json.dumps({'compared_files':217,'fresh_both_body_sha_and_full_byte_equality':True,'helper09_unchanged':True,'financial_admission':False}))\n";
 const verification=await new Promise((resolve,reject)=>execFile('/usr/bin/python3',['-B','-c',verifyCode,args['--selection'],args['--selection-sha256'],output],{env:{PATH:'/usr/bin:/bin'},maxBuffer:1024*1024,encoding:'utf8'},(error,stdout)=>error?reject(new Error('post-copy equality verification refused')):resolve(strictJson(stdout))));
 need(verification.compared_files===217&&verification.fresh_both_body_sha_and_full_byte_equality===true,'all217 post-copy equality');
 result.post_verification=verification;result.status='PUBLIC217_PREPARATION_EQUIVALENCE_MEASURED_NO_FINANCIAL_ADMISSION';
}catch(error){result.status='FAILED_PRESERVED_NO_FINANCIAL_ADMISSION';result.safe_error=String(error.message).slice(0,500);process.exitCode=2;}
result.total_prepare_and_postverify_seconds=(performance.now()-started)/1000;
result.limitations=['Historical serial timing is unpaired and from a different host-load moment; no controlled sixfold speedup claim.','Source/admission/golden selection checks and post-copy full-byte verification are excluded from parallel_prepare_seconds.','Pure preparation equivalence does not admit financial state or change existing cache authority.'];
const raw=canonical(result)+'\n';fs.writeFileSync(path.join(output,'RESULT.json'),raw,{flag:'wx',mode:0o600});
process.stdout.write(canonical({status:result.status,result_sha256:sha(raw),output})+'\n');
