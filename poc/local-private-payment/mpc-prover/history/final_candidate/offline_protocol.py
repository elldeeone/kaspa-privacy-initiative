"""Public EGRESS -> FINAL encoding only; no MPC or settlement authority."""
FIELDS = ('raw_case','canonical_case','projection','selection','image','journal',
          'outer_receipt','native_proof')


def validate(P, value):
    P.fields(value, ('schema','nonce_hex32','history_key_hex32','registered_history_sha256',
        'server_certificates_hex32','attempt_id_hex32','locked_binding_sha256',
        'prepared_core_sha256','context','head','native_policy','egress_record','egress','candidate'))
    P.need(value['schema']=='kpb-offline-final-request/v1','offline-final-request-schema')
    for name in ('nonce_hex32','history_key_hex32','registered_history_sha256',
                 'attempt_id_hex32','locked_binding_sha256','prepared_core_sha256'):
        P.digest(value[name])
    context=value['context']
    P.fields(context,('chain_hex32','pool_hex32','profile_hex32','domain_hex32','service_hex32','epoch_hex32'))
    for item in context.values():P.digest(item)
    P.need(context['chain_hex32']==P.GENESIS,'selected-testnet-genesis')
    certs=value['server_certificates_hex32']
    P.need(type(certs) is list and len(certs)==3 and len(set(certs))==3,'ordered-three-server-roster')
    for item in certs:P.digest(item)
    key=b'KPBHKEY1'+b''.join(P.hx(context[name],32) for name in
        ('chain_hex32','pool_hex32','domain_hex32','profile_hex32','service_hex32','epoch_hex32'))
    key+=b''.join(P.hx(item,32) for item in certs)
    P.need(P.sha(key)==value['history_key_hex32'],'actual-history-key-and-roster')
    P.fields(value['egress_record'],('sequence','checkpoint_sha256'))
    P.need(P.uint(value['egress_record']['sequence'])>0,'actual-egress-sequence')
    P.digest(value['egress_record']['checkpoint_sha256'])
    head=value['head'];P.fields(head,('outpoint','state_hex112','reserve_sompi'));P.point(head['outpoint'])
    state=P.hx(head['state_hex112'],112)
    P.need(state[:8]==b'KPBAST01' and state[8:40].hex()==context['domain_hex32']
           and 60000000<=P.decimal(head['reserve_sompi'])<=P.MAX_VALUE,'exact-egress-head')
    policy=value['native_policy']
    P.fields(policy,('old_script_public_key_hex37','immutable_tail_sha256','native_parameters_sha256'))
    P.hx(policy['old_script_public_key_hex37'],37)
    P.digest(policy['immutable_tail_sha256']);P.digest(policy['native_parameters_sha256'])
    egress=value['egress']
    P.fields(egress,('core_sha256','aggregate_proof_sha256','projection_sha256','nfs_hex32'))
    for name in ('core_sha256','aggregate_proof_sha256','projection_sha256'):P.digest(egress[name])
    nfs=egress['nfs_hex32']
    P.need(type(nfs) is list and len(nfs)==3 and all(type(item) is str for item in nfs)
           and nfs==sorted(set(nfs)),'canonical-three-NF256-set')
    for item in nfs:P.digest(item)
    P.need(value['prepared_core_sha256']==egress['core_sha256'],'prepared-egress-core')
    P.fields(value['candidate'],('case','r0_receipt'))
    P.record(value['candidate']['case']);P.record(value['candidate']['r0_receipt'])
    return value


def candidate(P, request, raw_case, codec, selection, outer):
    """Compute every FINAL field from actual public artifacts/tool outputs."""
    P.need(selection['parameters']['sha256']==request['native_policy']['native_parameters_sha256'],
           'actual-egress-native-parameter-selection')
    case=P.parse(raw_case);P.validate_case(case)
    frame=P.hx(case['transaction']['inputs'][0]['signatureScript'])
    P.need(len(frame)>247,'complete-native-witness')
    journal=P.hx(codec['journal_hex104'],104)
    final={'case':request['candidate']['case'],
        'canonical_case_sha256':P.canonical_case_sha256(case),
        'r0_receipt':request['candidate']['r0_receipt'],
        'selection_sha256':selection['parameters']['sha256'],
        'image_hex32':outer['image_id_hex32'],'journal_sha256':P.sha(journal),
        'native_proof_sha256':P.sha(frame[2:130])}
    joined={**request,'final_candidate':final}
    actual,projection,journal=P.verify_candidate(joined,raw_case,codec)
    fields={'raw_case':P.sha(raw_case),'canonical_case':P.canonical_case_sha256(actual),
        'projection':P.sha(projection),'selection':selection['parameters']['sha256'],
        'image':outer['image_id_hex32'],'journal':P.sha(journal),
        'outer_receipt':request['candidate']['r0_receipt']['sha256'],
        'native_proof':P.sha(frame[2:130])}
    return actual,projection,journal,fields


def encoded_candidate(P, fields):
    P.fields(fields,FIELDS)
    for item in fields.values():P.digest(item)
    return b'KPBHFIN1'+b''.join(P.hx(fields[name],32) for name in FIELDS)


def tokens(P, request, request_sha, selection_sha, fields, evidence_sha):
    values=[request['nonce_hex32'],request_sha,selection_sha,request['locked_binding_sha256'],
        request['egress_record']['checkpoint_sha256'],request['egress']['projection_sha256'],
        P.sha(encoded_candidate(P,fields)),evidence_sha,*[fields[name] for name in FIELDS]]
    for item in values:P.digest(item)
    P.need(fields['projection']==request['egress']['projection_sha256'],'one-actual-projection')
    return values
