"""UNSELECTED METHOD03 pure source-record extractor. No file/network/body IO.

The closed role supplies admitted actual journal/receiver/contact/A-exposure
records, decoded by its pinned packet/Exit parser. No truth or caller-supplied
allowed-edge/coverage/PASS interface exists. Unsupported facts remain PRIMARY
unmodeled; this never upgrades receiver037's absent raw4096 padding capture.
The frozen5ace matcher remains unchanged. Source/capture/budget freeze is Root's.
"""
import copy
import hashlib
import json
import re
import uuid
import time
from urllib.parse import urlparse
from pathlib import PurePosixPath

VIEW = 'CONTROLLER+TERMINAL'
ARMS = ('A', 'B')
OWNERS = (0, 1, 2)
SECONDARIES = ('TERMINAL_CONTACT', 'GLOBAL_UNION')
REQUIRED_COVERAGE = (
    'controller_metadata', 'source_schedule', 'traffic_metadata', 'clock_snapshots',
    'reader_status', 'receiver_metadata', 'public_native_facts', 'arm_partition',
    'native_verification', 'corrupt_contacts', 'corrupt_receipts',
    'corrupt_own_payout', 'transport_outcomes',
)


def need(value, category):
    if not value:
        raise ValueError('method03-extract-' + category)


def integer(value):
    need(type(value) is int, 'integer')
    return value


def unhex(value, width=None):
    need(type(value) is str and len(value) % 2 == 0
         and re.fullmatch('[0-9a-f]*', value) is not None, 'canonical-hex')
    raw = bytes.fromhex(value)
    need(width is None or len(raw) == width, 'hex-width')
    return raw


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())


def role(arm, owner):
    need(arm in ARMS and type(owner) is int and owner in OWNERS, 'arm-owner')
    return 'transport/' + str(owner + (3 if arm == 'B' else 0))


def slot_key(slot):
    need(type(slot) is int and 0 <= slot < 6, 'slot')
    return ('A' if slot < 3 else 'B'), slot % 3


def evidence(value):
    if type(value)is dict:
        need(set(value)=={'path','sha256'} and type(value['path'])is str and value['path'],
             'strict-source-artifact-ref')
        unhex(value['sha256'],32)
        return json.dumps(value,sort_keys=True,separators=(',',':'))
    need(type(value) is str and value, 'evidence-ref')
    return value


def _context(raw):
    need(len(raw) == 276, 'Context276')
    return {'profile_hex32': raw[64:96].hex(), 'domain_hex32': raw[96:128].hex(),
        'outpoint_hex36': raw[160:196].hex(),
        'head_shape': {'cm_count': int.from_bytes(raw[260:264], 'little'),
                       'nf_count': int.from_bytes(raw[264:268], 'little'),
                       'reserve': int.from_bytes(raw[268:276], 'little'),
                       'exit_mode': 'continuing'}}


def _missing(items, category, ref, scope=VIEW):
    value = {'scope': scope, 'category': category, 'evidence_refs': [evidence(ref)]}
    if value not in items:
        items.append(value)


def _fixed_identity(plan, obj, schema):
    need(obj['schema'] == schema and obj['binding'] == plan['binding'], 'same-source-record-binding')


def check_binding(value):
    need(type(value)is dict and set(value)=={'method_sha256','selection_sha256','trial_id','phase','attempt_id'},
         'exact-five-binding-fields')
    for key in ('method_sha256','selection_sha256'):unhex(value[key],32)
    for key in ('trial_id','attempt_id'):need(str(uuid.UUID(value[key]))==value[key],'canonical-binding-uuid')
    need(value['phase']=='private-exit-route-03','fixed-binding-phase')


def _native_report_coverage(plan, reports, raw_by_ordinal, missing):
    """Only SOURCE-bound actual verifier/Native records, never a bare PASS.

    Producer/report schema is a separate selected source seam. A report that
    is absent or not the exact admitted received-byte check stays unqualified;
    caller declarations cannot fill the gap. Final strict report adapter is
    selected by Root with the complete Native source closure.
    """
    need(type(reports) is list, 'native-report-list')
    expected_pins=plan['native_source_pins']
    need(type(expected_pins)is dict and set(expected_pins)=={
         'adapter','codec','engine','verifier','parameters','manifest','tail'}, 'frozen-native-source-role-map')
    for value in expected_pins.values():
        unhex(value,32);need(value in plan['sources'].values(),'native-role-pin-admitted')
    by_ordinal = {}
    for report in reports:
        if report.get('schema') != 'kpb-method03-received-native-check/v1':
            _missing(missing, 'unsupported-native-report-schema', 'native-report')
            continue
        need(set(report)=={'schema','binding','ordinal','receiver_row_sha256','projection_sha256',
            'proof_sha256','source_pins','actual_native_returncode','native_full_accepted',
            'all_scripts_passed','actual_public_proof_verified','isolation','artifact_refs'},
            'exact-unlabelled-native-report-fields')
        need(report['binding'] == plan['binding'], 'native-report-binding')
        ordinal = integer(report['ordinal'])
        need(ordinal in raw_by_ordinal and ordinal not in by_ordinal, 'native-report-exact-universe')
        raw = raw_by_ordinal[ordinal]
        actual_row_sha=sha((json.dumps(raw,sort_keys=True,separators=(',',':'))+'\n').encode())
        need(report['receiver_row_sha256']==actual_row_sha
             and report['projection_sha256'] == raw['exit_id']
             and report['proof_sha256'] == sha(unhex(raw['proof_hex128'], 128)),
             'native-report-exact-received-bytes')
        pins=report['source_pins']
        need(pins==expected_pins,'native-report-exact-source-role-bindings')
        for value in pins.values():
            unhex(value,32)
            need(value in plan['sources'].values(), 'native-report-source-admitted')
        artifact_refs=report['artifact_refs']
        need(type(artifact_refs)is dict and set(artifact_refs)=={
             'case','normalization','native_report','proof_result'}, 'native-report-actual-artifact-refs')
        for ref in artifact_refs.values():
            need(type(ref)is dict and set(ref)=={'path','sha256'} and type(ref['path'])is str
                 and bool(ref['path']) and ref['path']!='.' and not PurePosixPath(ref['path']).is_absolute()
                 and '..' not in PurePosixPath(ref['path']).parts
                 and str(PurePosixPath(ref['path']))==ref['path'], 'native-report-finite-relative-artifact')
            unhex(ref['sha256'],32)
        integer(report['actual_native_returncode'])
        need(type(report['all_scripts_passed']) is bool
             and type(report['actual_public_proof_verified']) is bool
             and type(report['native_full_accepted'])is bool, 'native-report-outcome-types')
        need(report['isolation']=={'network':'none','input_scope':'unlabelled-public-received-exits',
                                  'originals_mounted':False}, 'native-report-actual-public-role-isolation')
        by_ordinal[ordinal] = report
    complete = set(by_ordinal) == set(raw_by_ordinal) and all(
        r['actual_native_returncode'] == 0 and r['all_scripts_passed']
        and r['actual_public_proof_verified'] and r['native_full_accepted'] for r in by_ordinal.values())
    if not complete:
        _missing(missing, 'missing-or-refused-actual-received-Native-verification', 'native-reports')
    return complete


def _publication_metadata(index,controller,final_events,missing):
    """Actual post-shutdown publication timing, never inferred or backdated."""
    value=index.get('publication_metadata')
    ref='native-publication'
    if value is None:
        _missing(missing,'missing-public-Native-publication-timing',ref);return
    need(set(value)=={'schema','pid','clock_evidence','before_public_write','after_public_fsync','public_artifacts'}
         and value['schema']=='kpb-method03-native-publication/v1','actual-publication-metadata-schema')
    need(integer(value['pid'])>0,'actual-publication-pid')
    clocks=value['clock_evidence'];before=clocks['before'];after=clocks['after']
    need(set(clocks)=={'boot_id','kernel_clock_ids','before','after','stable'}
         and type(clocks['stable'])is bool,'actual-publication-clock-evidence')
    for snapshot in (before,after):
        need(set(snapshot)=={'boot_id','time_namespace','time_for_children_namespace','timens_offsets'},
             'actual-publication-clock-snapshot')
        need(str(uuid.UUID(snapshot['boot_id']))==snapshot['boot_id'],'actual-publication-boot-id')
    comparable=(clocks['stable']is True and before==after and clocks['boot_id']==before['boot_id']
        and before['boot_id']==controller['boot_id']
        and before['time_namespace']==before['time_for_children_namespace']
        and controller['time_namespace']==controller['time_for_children_namespace']
        and clocks['kernel_clock_ids']=={'monotonic':time.CLOCK_MONOTONIC,
             'realtime':time.CLOCK_REALTIME,'boottime':time.CLOCK_BOOTTIME})
    for nskey in ('time_namespace','time_for_children_namespace'):
        ns=before[nskey];inode=integer(ns['inode'])
        need(inode>0 and ns['link']=='time:[%d]'%inode,'actual-publication-namespace')
    need(set(before['timens_offsets'])=={'monotonic_ns','boottime_ns'},'actual-publication-offset-fields')
    for n in before['timens_offsets'].values():integer(n)
    lo,hi=value['before_public_write'],value['after_public_fsync']
    for row in (lo,hi):
        need(set(row)=={'monotonic_ns','unix_ns','boottime_ns'},'actual-publication-time-fields')
        for n in row.values():integer(n)
    need(lo['monotonic_ns']<=hi['monotonic_ns'],'actual-publication-time-order')
    refs=value['public_artifacts'];need(set(refs)=={'exits','native_result'},'actual-unlabelled-public-artifacts')
    for artifact in refs.values():evidence(artifact)
    if not comparable:
        _missing(missing,'public-Native-publication-clock-not-admitted',ref);return
    delta=before['timens_offsets']['monotonic_ns']-controller['timens_offsets']['monotonic_ns']
    wait_bounds=[integer(e['wait_returned_monotonic_ns']) for e in final_events]
    if not wait_bounds or lo['monotonic_ns']-delta<max(wait_bounds):
        _missing(missing,'public-Native-publication-before-network-shutdown',ref)


def extract(plan, event_journal, receiver_index, parsed_arrivals, contact_facts,
            baseline_A_exposure, view=VIEW):
    """Construct frozen5ace input from actual SOURCE records, without truth.

    All returned observations remain PRIVATE. The selected closed launcher
    admits source/artifact identities, retains all records, seals a salted
    capsule, and enforces budgets/temporal barriers before one-owner truth IO.
    Nonempty refs and dictionaries are not independent provenance authority.
    """
    need(view == VIEW and plan['view'] == VIEW, 'primary-only-not-secondary-relabel')
    check_binding(plan['binding'])
    _fixed_identity(plan, event_journal, 'kpb-method03-controller-journal/v1')
    _fixed_identity(plan, receiver_index, 'kpb-method03-receiver-index/v1')
    _fixed_identity(plan, parsed_arrivals, 'kpb-method03-parsed-arrivals/v1')
    _fixed_identity(plan, contact_facts, 'kpb-method03-private-contact-view/v1')
    _fixed_identity(plan, baseline_A_exposure, 'kpb-method03-controller-A-exposures/v1')
    need(not set(event_journal) & {'allowed_edges', 'coverage', 'facts', 'qualified', 'complete'},
         'no-caller-model-authority')
    missing = []
    _missing(missing, 'full-global-host-view', 'scope/global-host', 'GLOBAL-HOST/UNION')
    _missing(missing, 'full-corrupt-server-view', 'scope/corrupt-server', 'GLOBAL-HOST/UNION')
    records = event_journal['records']
    need(type(records) is list and records, 'full-journal')
    by_kind, by_role, subprocesses = {}, {}, []
    for index, event in enumerate(records):
        need(event['schema'] == 'kpb-method03-controller-event/v1'
             and event['binding'] == plan['binding']
             and integer(event['sequence']) == index + 1, 'full-ordered-journal-binding')
        integer(event['recorded_monotonic_ns'])
        kind = event['kind']; need(type(kind) is str and kind, 'event-kind')
        by_kind.setdefault(kind, []).append(event)
        if 'role' in event:
            by_role.setdefault(event['role'], []).append(event)
    # Source class is explicit. Unknown semantics cannot disappear behind an
    # otherwise optimistic completeness flag; retained raw journal stays private.
    known_kinds = {'controller-clock', 'launch', 'status', 'role-exit', 'tor-status',
        'pipe-created', 'parent-pipe-ends-closed', 'candidate-metadata', 'A-exposure',
        'submission-finished', 'receiver-stop-control', 'session-parameters','controller-clock-followup'}
    for kind, events in by_kind.items():
        if kind not in known_kinds:
            for event in events:
                _missing(missing, 'unmodeled-controller-event-kind', 'journal:' + str(event['sequence']))
    sessions = by_kind.get('session-parameters', [])
    need(len(sessions) == 1, 'one-actual-shared-session')
    parameters = copy.deepcopy(sessions[0]['value'])
    needed_params = {'transport_source_sha256', 'tor_binary_sha256', 'curl_binary_sha256',
                     'onion_endpoint', 'receiver_source_sha256', 'request_policy'}
    need(set(parameters) == needed_params, 'strict-public-session-parameters')
    frozen_transport=plan['transport_source_pins']
    need(set(frozen_transport)==needed_params-{'onion_endpoint','request_policy'}
         and all(parameters[key]==value for key,value in frozen_transport.items()),
         'actual-session-exact-source-role-bindings')
    for key in needed_params - {'onion_endpoint', 'request_policy'}:
        unhex(parameters[key], 32)
        need(parameters[key] in plan['sources'].values(), 'actual-session-source-admitted')
    need(receiver_index['transport_parameters']=={a:parameters for a in ARMS},
         'receiver-index-bound-to-actual-shared-session')
    endpoint = parameters['onion_endpoint']
    need(type(endpoint) is str and endpoint, 'actual-public-endpoint')
    hostname = urlparse(endpoint if '://' in endpoint else 'http://' + endpoint).hostname
    need(hostname is not None and hostname.endswith('.onion'), 'actual-onion-host')
    clocks, receipts = {}, {}
    controller = by_kind.get('controller-clock', [])
    need(len(controller) == 1, 'actual-controller-clock')
    followup=by_kind.get('controller-clock-followup',[])
    need(len(followup)==1,'actual-vector-controller-clock-followup')
    evidence(controller[0]['source_event_ref'])
    clocks['controller'] = copy.deepcopy(controller[0]['value'])
    need(clocks['controller']['role'] == 'controller', 'controller-clock-role')
    late=followup[0]['value']
    stable_fields=('role','pid','boot_id','clock_id','time_namespace','time_for_children_namespace','timens_offsets')
    need(all(late[k]==clocks['controller'][k]for k in stable_fields)
         and clocks['controller']['sample']['monotonic_after_ns']<=late['sample']['monotonic_before_ns'],
         'actual-early-late-controller-clock-continuity')
    for event in by_kind.get('status', []):
        envelope = event['observation']; event_role = event['role']
        need(envelope['schema'] == 'kpb-method03-status-observation/v1'
             and envelope['role'] == event_role
             and envelope['reader_id'] == 'controller/' + event_role
             and envelope['reader_pid'] == clocks['controller']['pid'], 'actual-role-channel-reader')
        need(integer(envelope['reader_observed_monotonic_ns'])
             <= integer(event['consumed_monotonic_ns']), 'reader-precedes-consumer')
        value = envelope['value']
        if value.get('schema') == 'kpb-method03-clock-snapshot/v1':
            need(value['role'] == event_role and event_role not in clocks, 'one-actual-role-clock')
            clocks[event_role] = copy.deepcopy(value)
        elif value.get('schema') == 'kpb-exit-transport-status/v1':
            need(event_role.startswith('transport/') and event_role not in receipts
                 and set(value) == {'schema', 'transport_receipt', 'financial_or_chain_acceptance'}
                 and value['transport_receipt'] is True
                 and value['financial_or_chain_acceptance'] is False, 'fixed-real-202-receipt')
            copied = copy.deepcopy(envelope)
            copied['consumed_monotonic_ns'] = event['consumed_monotonic_ns']
            receipts[event_role] = copied
        elif value.get('schema') == 'kpb-method03-role-subprocess-event/v1':
            need(value['actor_role'] == event_role and value['clock_role'] == event_role,
                 'actual-subprocess-actor-clock')
            subprocesses.append((event, value))
        elif value.get('schema') not in {
            'kpb-owner-exit-pipe-status/v1', 'kpb-owner-transport-input-fd/v1',
            'kpb-probe-listener/v1', 'kpb-probe-listener-summary/v1'}:
            _missing(missing, 'unmodeled-fixed-role-status', 'journal:' + str(event['sequence']))
    core_roles = {'controller', 'receiver/0'} | {role(a,o) for a in ARMS for o in OWNERS}
    need(set(clocks) >= core_roles, 'all-actual-role-clocks')
    selected_clocks = [clocks[r] for r in sorted(core_roles)]
    launches, exits, statuses, curl_bounds = [], [], [], {}
    pipe_rows = by_kind.get('pipe-created', [])
    closed_rows = by_kind.get('parent-pipe-ends-closed', [])
    candidates = by_kind.get('candidate-metadata', [])
    for arm in ARMS:
        for owner in OWNERS:
            r = role(arm, owner); slot = owner + (3 if arm == 'B' else 0)
            launched = [e for e in by_role.get(r, []) if e['kind'] == 'launch']
            final = [e for e in by_role.get(r, []) if e['kind'] == 'role-exit']
            need(len(launched) == len(final) == 1, 'actual-six-launch-exit-lifetimes')
            launch, done = launched[0], final[0]
            need(launch['host_pid'] == done['host_pid']
                 and launch['controller_pid'] == clocks['controller']['pid']
                 and launch['sequence'] < done['sequence'], 'bound-actual-launch-lifetime')
            pipes = [p for p in pipe_rows if p['slot'] == slot]
            closure = [p for p in closed_rows if p['slot'] == slot]
            candidate = [p for p in candidates if p['slot'] == slot]
            need(len(pipes) == len(closure) == len(candidate) == 1, 'exact-actual-pipe-candidate-closure')
            for row in pipes + candidate:
                need((row['arm'], row['owner_slot']) == (arm, owner), 'actual-source-slot-mapping')
            if candidate[0]['body_read'] is not False or candidate[0]['body_hash'] is not False:
                _missing(missing, 'controller-private-candidate-body-boundary-violation',
                         'journal:' + str(candidate[0]['sequence']))
            need(candidate[0]['handle_mode'] == 'O_PATH', 'metadata-only-candidate-handle')
            pre = integer(launch['popen_started_monotonic_ns'])
            post = integer(launch['popen_returned_monotonic_ns'])
            bound_ref = 'journal:' + str(launch['sequence'])
            # The real88cb curl starts AFTER complete frame intake. Its actual
            # prePopen time is a stronger causal lower bound than the outer role
            # launch. Use the observed actor offset; never an invented zero.
            curl = [(e,v) for e,v in subprocesses if v['actor_role'] == r
                    and v.get('kind') == 'role-subprocess-launch' and v.get('operation') == 'curl']
            if len(curl) == 1:
                ev, value = curl[0]
                actor = clocks[r]; host = clocks['controller']
                need(actor['boot_id'] == host['boot_id']
                     and actor['time_namespace'] == actor['time_for_children_namespace']
                     and host['time_namespace'] == host['time_for_children_namespace'],
                     'curl-observed-comparable-clock')
                offset = actor['timens_offsets']['monotonic_ns'] - host['timens_offsets']['monotonic_ns']
                inner_pre = integer(value['pre_Popen_monotonic_ns']) - offset
                inner_post = integer(value['post_Popen_monotonic_ns']) - offset
                need(inner_pre <= inner_post and inner_pre >= pre, 'source-causal-inner-curl-bound')
                interval={'lower_host_ns':inner_pre,'upper_host_ns':None,
                          'evidence_refs':['journal:'+str(ev['sequence'])]}
                seen_exit=[(e,v) for e,v in subprocesses if v['actor_role']==r
                    and v.get('kind')=='role-subprocess-exit' and v.get('operation')=='curl'
                    and v['subprocess_index']==value['subprocess_index']
                    and v['actual_local_pid']==value['actual_local_pid']
                    and v['pid_namespace']==value['pid_namespace']]
                if len(seen_exit)==1:
                    exit_event,exit_value=seen_exit[0]
                    observed=integer(exit_value['observed_wait_monotonic_ns'])-offset
                    need(observed>=inner_pre and exit_event['sequence']>ev['sequence'],
                         'actual-curl-exit-after-launch')
                    interval['evidence_refs'].append('journal:'+str(exit_event['sequence']))
                    # curlrc0 alone is not HTTP202; the later fixed receipt
                    # establishes that THIS unique curl invocation got202.
                    if r in receipts and exit_value['returncode']==0:
                        need(observed<=receipts[r]['reader_observed_monotonic_ns'],
                             'actual-curl-completion-precedes-fixed-receipt')
                        interval['upper_host_ns']=observed
                else:
                    _missing(missing,'missing-or-ambiguous-actual-curl-exit',bound_ref)
                curl_bounds[arm,owner]=interval
            else:
                _missing(missing, 'missing-or-multiple-actual-curl-Popen-bounds', bound_ref)
            launches.append({'arm':arm,'owner':owner,'role':r,'started_ns':pre,
                'post_popen_ns':post,'pid':launch['host_pid'],'event_ref':bound_ref,
                'metadata':{'argv':copy.deepcopy(launch['argv']),
                    'mounts':{'complete_actual_launch_argv':copy.deepcopy(launch['argv'])},
                    'fd_topology':{'passed_setup_fds':copy.deepcopy(launch['passed_setup_fds']),
                        'stdio':copy.deepcopy(launch['stdio']),'pipe':copy.deepcopy(pipes[0]),
                        'parent_closure':copy.deepcopy(closure[0])},
                    'schedule':{'actual_launch_sequence':launch['sequence']},
                    'outer_launch':copy.deepcopy(launch),'inner_curl_events':copy.deepcopy(curl)}})
            exits.append({'arm':arm,'owner':owner,'role':r,'returncode':done['returncode'],
                          'event_ref':'journal:'+str(done['sequence'])})
            if r in receipts:
                status=copy.deepcopy(receipts[r]);status.update(arm=arm,owner=owner)
                statuses.append(status)
    heads = receiver_index['public_heads']
    need(type(heads) is list and heads, 'actual-public-heads')
    head_by_sha = {}
    for head in heads:
        arm = head['arm']; need(arm in ARMS, 'public-head-arm')
        raw = unhex(head['context_hex276'],276); ctx = sha(raw)
        evidence(head['evidence_ref'])
        need(ctx not in head_by_sha, 'disjoint-source-public-arm-contexts')
        need(_context(raw)['head_shape'] == plan['head_shape'], 'public-head-shape')
        head_by_sha[ctx] = head
    raw_records = receiver_index['records']
    need(type(raw_records) is list and len(raw_records) == 6, 'all-six-actual-receiver-records')
    raw_by_ordinal = {}
    for raw in raw_records:
        ordinal=integer(raw['arrival_sequence'])
        need(ordinal>0 and ordinal not in raw_by_ordinal, 'actual-global-receiver-ordinal')
        need(raw['schema']=='kpb-exit-transport-arrival/v1' and raw['framing']=='PASS'
             and raw['http_status']==202 and raw['received_body_bytes']==4096
             and raw['financial_validation']=='NOT_RUN' and raw['broadcast'] is False,
             'actual-untrusted-receiver-shape')
        projection=unhex(raw['projection_hex']);unhex(raw['proof_hex128'],128)
        need(len(projection)==1844 and sha(projection)==raw['exit_id'], 'exact-continuing-received-projection')
        unhex(raw['frame_sha256'],32)
        need('frame_hex' not in raw, 'receiver037-does-not-supply-raw-padding')
        raw_by_ordinal[ordinal]=raw
    _missing(missing,'missing-full-terminal-packet','receiver037/raw-padding-not-retained')
    parsed=parsed_arrivals['records']
    need(type(parsed) is list and len(parsed)==6, 'six-pinned-parser-results')
    arrivals={a:[] for a in ARMS}; parsed_ordinals=set()
    for row in parsed:
        ordinal=integer(row['ordinal']);need(ordinal in raw_by_ordinal and ordinal not in parsed_ordinals,
                                           'parser-exact-receiver-universe')
        parsed_ordinals.add(ordinal);raw=raw_by_ordinal[ordinal]
        need(row['projection_hex']==raw['projection_hex'] and row['proof_hex128']==raw['proof_hex128']
             and row['arrival_id']==raw['exit_id'], 'parser-bound-to-actual-received-bytes')
        native=copy.deepcopy(row['native']);ctx_raw=unhex(native['context_hex276'],276);ctx=sha(ctx_raw)
        need(ctx in head_by_sha and native['context_sha256']==ctx, 'arm-from-public-Context-only')
        expected=_context(ctx_raw)
        need(all(native[k]==v for k,v in expected.items()), 'pinned-parser-public-context-fields')
        arm=head_by_sha[ctx]['arm']
        arrivals[arm].append({'arrival_id':row['arrival_id'],'ordinal':ordinal,
            'accepted_monotonic_ns':raw['accepted_monotonic_ns'],
            'post_handler_monotonic_ns':raw['post_handler_monotonic_ns'],
            'recorded_monotonic_ns':raw['recorded_monotonic_ns'],'http_status':raw['http_status'],
            'frame_bytes':raw['received_body_bytes'],'native':native,'event_ref':'receiver:'+str(ordinal)})
    need(all(len(arrivals[a])==3 for a in ARMS), 'actual-public-context-partition-three-each')
    # Preserve actual raw index ordering within each arm, not private owner order.
    position={r['arrival_sequence']:i for i,r in enumerate(raw_records)}
    for rows in arrivals.values():rows.sort(key=lambda r:position[r['ordinal']])
    native_complete=_native_report_coverage(plan,receiver_index['native_reports'],raw_by_ordinal,missing)
    _publication_metadata(receiver_index,clocks['controller'],by_kind.get('role-exit',[]),missing)
    facts=[]
    host_clock=clocks['controller'];receiver_clock=clocks['receiver/0']
    need(receiver_clock['boot_id']==host_clock['boot_id']
         and receiver_clock['time_namespace']==receiver_clock['time_for_children_namespace'],
         'actual-receiver-clock-comparable')
    receiver_delta=(receiver_clock['timens_offsets']['monotonic_ns']
                    -host_clock['timens_offsets']['monotonic_ns'])
    for (arm,owner),interval in sorted(curl_bounds.items()):
        low=interval['lower_host_ns']+receiver_delta
        high=interval['upper_host_ns']
        high=None if high is None else high+receiver_delta
        allowed=[r['arrival_id'] for r in arrivals[arm] if low<=r['post_handler_monotonic_ns']
                 and (high is None or r['post_handler_monotonic_ns']<=high)]
        facts.append({'kind':'allowed-edges','arm':arm,'owner':owner,'arrival_ids':sorted(allowed),
            'category':'actual-inner-curl-causal-interval','evidence_refs':interval['evidence_refs']})
    exposures=baseline_A_exposure['records'];need(type(exposures) is list and len(exposures)==3,
                                             'three-actual-labelled-A-exposures')
    exposed_owners=set()
    for exposure in exposures:
        _fixed_identity(plan,exposure,'kpb-method03-controller-A-exposure/v1')
        owner=exposure['owner_slot'];need(type(owner)is int and owner in OWNERS and owner not in exposed_owners
                                        and exposure['arm']=='A','unique-A-exposure-owner')
        exposed_owners.add(owner)
        need(exposure['owner_role']=='owner/'+str(owner)
             and exposure['transport_role']==role('A',owner),'actual-A-source-role')
        frame=unhex(exposure['frame_hex']);need(sha(frame)==exposure['frame_sha256'],'actual-A-frame-hash')
        for source_key in ('packet_source_sha256','owner_source_sha256'):
            need(exposure[source_key] in plan['sources'].values(),'A-exposure-source-admitted')
        valid=exposure['owner_returncode']==0 and exposure['owner_fixed_status']=='FRAME_WRITTEN'
        if not valid or exposure['framing_valid'] is not True:
            _missing(missing,'refused-labelled-A-exposure','A-exposure:'+str(owner));continue
        projection=unhex(exposure['projection_hex']);proof=unhex(exposure['proof_hex128'],128)
        need(len(frame)==4096 and frame[:8]==b'KPBXNET1'
             and int.from_bytes(frame[8:10],'little')==len(projection)
             and frame[10:10+len(projection)]==projection
             and frame[10+len(projection):10+len(projection)+128]==proof
             and sha(projection)==exposure['projection_sha256'],'actual-A-packet-projection-binding')
        matches=[r for r in raw_records if r['exit_id']==exposure['projection_sha256']
                 and r['frame_sha256']==exposure['frame_sha256'] and r['proof_hex128']==exposure['proof_hex128']]
        need(len(matches)==1 and matches[0]['exit_id'] in {a['arrival_id'] for a in arrivals['A']},
             'actual-A-exposure-received-match')
        facts.append({'kind':'owner-arrival','arm':'A','owner':owner,
            'arrival_id':matches[0]['exit_id'],'category':'controller-labelled-release',
            'evidence_refs':['A-exposure:'+str(owner),'receiver:'+str(matches[0]['arrival_sequence'])]})
    contact_applicability={}
    for arm in ARMS:
        private=contact_facts['arms'][arm]
        contacts=private['contacts'];need(type(contacts)is list,'actual-contact-list')
        applicable=[];retained_contacts=[]
        for i,contact in enumerate(contacts):
            need(type(contact['owner']) is int and contact['owner'] in OWNERS,'legitimate-contact-owner')
            for key in ('native_pk_hex32','delivery_pk_hex32','domain_hex32','profile_hex32'):unhex(contact[key],32)
            integer(contact['invoice_index'])
            contexts=[_context(unhex(h['context_hex276'],276)) for h in heads if h['arm']==arm]
            relevant=contact['invoice_index']==plan['arms'][arm]['note_index'] and all(
                contact['domain_hex32']==h['domain_hex32'] and contact['profile_hex32']==h['profile_hex32']
                for h in contexts)
            retained_contacts.append({'contact':copy.deepcopy(contact),
                'applicability':'APPLICABLE' if relevant else 'OTHER_PUBLIC_INDEX_DOMAIN_OR_PROFILE'})
            if relevant:applicable.append(contact)
        need({c['owner'] for c in applicable}==set(OWNERS),'all-three-legitimate-current-arm-contacts')
        # Positive address equality remains legitimate even when both selected
        # wallets intend fresh payouts. Alternative known keys are UNIONED;
        # nonmatching keys do not exclude an owner under the fresh-key policy.
        # Keep every acquired other-index contact rather than selecting by truth.
        for contact_owner in OWNERS:
            keys={b'\0\0\x20'+unhex(c['native_pk_hex32'],32)+b'\xac'
                  for c in contacts if c['owner']==contact_owner}
            matching=sorted(r['arrival_id'] for r in arrivals[arm]
                            if unhex(r['native']['destination_spk_hex36'],36) in keys)
            if matching:
                facts.append({'kind':'allowed-edges','arm':arm,'owner':contact_owner,
                    'arrival_ids':matching,'category':'legitimate-contact-native-payout-equality',
                    'evidence_refs':['contact:'+arm+'/all-known-native-keys']})
        own=private['own_payouts'];need(type(own)is list and len(own)==1 and own[0]['owner']==1,
                                     'one-actual-corrupt-own-payout')
        unhex(own[0]['nf_hex32'],32);unhex(own[0]['spk_hex36'],36)
        matched=[r for r in arrivals[arm] if r['native']['nf_hex32']==own[0]['nf_hex32']
                 and r['native']['destination_spk_hex36']==own[0]['spk_hex36']]
        need(len(matched)==1,'actual-corrupt-own-NF-and-SPK-match')
        facts.append({'kind':'owner-arrival','arm':arm,'owner':1,'arrival_id':matched[0]['arrival_id'],
            'category':'corrupt-own-payout','evidence_refs':['contact:'+arm+'/own-payout','receiver:'+str(matched[0]['ordinal'])]})
        receipts=private['known_receipts'];need(type(receipts)is list and len(receipts)==1,'one-actual-corrupt-created-receipt')
        receipt=receipts[0]
        need(type(receipt['owner'])is int and receipt['owner']in OWNERS
             and type(receipt['value'])is int and receipt['value']==plan['common_amounts']['note'],
             'actual-known-receipt-economics')
        for k,w in (('rho_hex32',32),('cm_hex32',32),('invoice_hex208',208),
                    ('receipt_hex216',216),('blind_hex32',32),('tuple_hex520',520)):unhex(receipt[k],w)
        need(type(receipt['known_consumed'])is bool,'known-consumed-fact-type')
        if not receipt['known_consumed']:
            _missing(missing,'known-consumption-fact-not-modeled','contact:'+arm+'/known-receipt')
        _missing(missing,'opaque-corrupt-receipt-invoice-blind-tuple-semantics','contact:'+arm+'/known-receipt')
        for i,_ in enumerate(private['unmodeled']):
            _missing(missing,'unmodeled-legitimate-contact-source-fact','contact:'+arm+'/unmodeled:'+str(i))
        # Retain the complete real records, including domain-stable delivery PK
        # and other-index contacts. They are never silently selected using truth.
        contact_applicability[arm]=retained_contacts
    # Each completeness value is a consequence of checked source records, never
    # a caller-supplied 'complete' field. Unsupported semantics remain missing.
    derived={
        'controller_metadata':len(launches)==len(exits)==6,
        'source_schedule':len(launches)==6 and bool(records),
        'traffic_metadata':False,  # receiver037 never retained raw4096 padding
        'clock_snapshots':set(clocks)>=core_roles,
        'reader_status':len(receipts)==6,
        'receiver_metadata':False,  # set only after actual drain checks below
        'public_native_facts':len(parsed_ordinals)==6,
        'arm_partition':all(len(arrivals[a])==3 for a in ARMS),
        'native_verification':native_complete,
        'corrupt_contacts':set(contact_applicability)==set(ARMS),
        'corrupt_receipts':False,  # opaque real receipt/blind/tuple unmodeled
        'corrupt_own_payout':sum(f['category']=='corrupt-own-payout' for f in facts)==2,
        'transport_outcomes':False,
    }
    need(set(derived)==set(REQUIRED_COVERAGE),'fixed-derived-coverage-grammar')
    coverage={k:{'complete':bool(derived[k]),'evidence_refs':['source-derived/'+k]} for k in REQUIRED_COVERAGE}
    summaries=[e for e in by_kind.get('status',[]) if e['role']=='receiver/0'
               and e['observation']['value'].get('schema')=='kpb-probe-listener-summary/v1']
    completed=by_kind.get('submission-finished',[])
    outcomes_complete=len(completed)==6 and {(e['arm'],e['owner_slot']) for e in completed}=={
        (a,o) for a in ARMS for o in OWNERS}
    receiver_complete=len(summaries)==1 and summaries[0]['observation']['value']['accepted']==6
    receiver_complete &= len(summaries)==1 and summaries[0]['observation']['value']['completed']==6
    stopped=by_kind.get('receiver-stop-control',[])
    receiver_complete &= len(stopped)==1 and stopped[0]['bytes']==5
    coverage['receiver_metadata']['complete']=bool(receiver_complete)
    coverage['transport_outcomes']['complete']=outcomes_complete
    if not receiver_complete:_missing(missing,'missing-actual-complete-receiver-drain','receiver-summary')
    if not outcomes_complete:_missing(missing,'missing-actual-six-submission-outcomes','submission-finished')
    return {'schema':'kpb-method03-metadata-observation/v1','binding':copy.deepcopy(plan['binding']),
        'sources':copy.deepcopy(plan['sources']),'clocks':selected_clocks,'launches':launches,
        'statuses':statuses,'exits':exits,'arrivals':arrivals,'facts':facts,'coverage':coverage,
        'unmodeled':missing,'transport_parameters':{a:copy.deepcopy(parameters) for a in ARMS},
        'arm_partition':{'mechanism':'source-admitted-public-context',
            'contexts':{a:sorted(ctx for ctx,h in head_by_sha.items() if h['arm']==a) for a in ARMS},
            'evidence_refs':[evidence(h['evidence_ref']) for h in heads]},
        'retained_event_journal':copy.deepcopy(event_journal),'retained_receiver_index':copy.deepcopy(receiver_index),
        'retained_contact_facts':copy.deepcopy(contact_facts),'contact_applicability':contact_applicability,
        'retained_A_exposure':copy.deepcopy(baseline_A_exposure)}


def secondary_coverage(binding,label,slot_grammar_sha256,universe_sha256,capture_refs,limitations):
    """PRIVATE coverage capsule only; never a relabelled primary prediction."""
    need(label in SECONDARIES,'exact-secondary-label')
    check_binding(binding)
    unhex(slot_grammar_sha256,32);unhex(universe_sha256,32)
    need(type(capture_refs)is list and all(type(x)is str and x for x in capture_refs), 'secondary-capture-refs')
    need(type(limitations)is list and limitations and all(type(x)is dict
         and set(x)=={'category','evidence_refs'} and type(x['category'])is str and x['category']
         and type(x['evidence_refs'])is list and x['evidence_refs']
         and all(type(r)is str and r for r in x['evidence_refs']) for x in limitations), 'secondary-explicit-limitations')
    return {'schema':'kpb-method03-secondary-coverage/v1','binding':copy.deepcopy(binding),
        'label':label,'kind':'coverage','slot_grammar_sha256':slot_grammar_sha256,
        'actual_unlabelled_universe_sha256':universe_sha256,'capture_refs':copy.deepcopy(capture_refs),
        'limitations':copy.deepcopy(limitations),'status':'UNQUALIFIED' if capture_refs else 'MISSING',
        'scored':False,'gain_claimed':False}


def public_secondary_status(capsule):
    """Caller adds only salted seal/capsule refs; never private record hashes."""
    need(set(capsule)=={'schema','binding','label','kind','slot_grammar_sha256',
         'actual_unlabelled_universe_sha256','capture_refs','limitations','status','scored','gain_claimed'}
         and capsule['schema']=='kpb-method03-secondary-coverage/v1'
         and capsule['label']in SECONDARIES and capsule['kind']=='coverage'
         and capsule['scored']is False and capsule['gain_claimed']is False,'secondary-not-prediction')
    need(capsule==secondary_coverage(capsule['binding'],capsule['label'],capsule['slot_grammar_sha256'],
         capsule['actual_unlabelled_universe_sha256'],capsule['capture_refs'],capsule['limitations']),
         'exact-secondary-derived-status')
    return {'schema':'kpb-method03-secondary-coverage-status/v1','binding':copy.deepcopy(capsule['binding']),
        'label':capsule['label'],'kind':'coverage','slot_grammar_sha256':capsule['slot_grammar_sha256'],
        'actual_unlabelled_universe_sha256':capsule['actual_unlabelled_universe_sha256'],'status':capsule['status'],
        'capture_ref_count':len(capsule['capture_refs']),'limitation_count':len(capsule['limitations']),
        'scored':False,'gain_claimed':False}
