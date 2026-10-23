"""Cheap public emitted-byte/source conformance; never invokes native VM."""
import hashlib
import json
from pathlib import Path
import re
import fixture
import source_meter as meter

BASELINE_SHA='78a7bff9fc1038cd20cd5424e7cd7ea04bd81469692066e10f0274777d0c3ebf'
TEMPLATE_SHA='731eb10da7a96a3f1f67b3c3fb0da6d45294820c8c610dc9d7d0d0fd1dd10556'
def sha(value):return hashlib.sha256(value).hexdigest()
def old_domain(source):
    body=source.split('pub const DOMAIN: [u8; 32] = [',1)[1].split('];',1)[0]
    return bytes(int(x,16) for x in re.findall(r'0x([0-9a-f]{2})',body))
def dispatch(raw):
    tokens=meter.tokens(raw);depth=0;first=None;other=None;end=None
    for code,_,start,stop in tokens:
        if code in (0x63,0x64):
            if depth==0:first=start
            depth+=1
        elif code==0x67 and depth==1:other=stop
        elif code==0x68:
            depth-=1
            if depth==0:end=start
    if first is None or other is None or end!=len(raw)-1:raise ValueError('whole-dispatch-shape')
    return raw[:first],raw[other:end]
def normalized(raw,new_length,old_length,old_domain,new_state,old_state):
    result=bytearray()
    mapping={new_length:old_length,new_length+199:old_length+199,new_length+199-114:old_length+199-114}
    for code,value,start,end in meter.tokens(raw):
        if value is None:result+=raw[start:end];continue
        replacement=None
        if value==fixture.DOMAIN:replacement=old_domain
        elif value==new_state:replacement=old_state
        elif value==b'KPX4AU01':replacement=b'KPX3AU01'
        elif value==b'\x4d'+new_length.to_bytes(2,'little'):
            replacement=b'\x4d'+old_length.to_bytes(2,'little')
        elif len(value)<=8:
            number=meter.decode_number(value)
            if number in mapping:
                candidate=mapping[number];replacement=candidate.to_bytes(len(value),'little')
        result+=raw[start:end] if replacement is None else raw[start:end-len(value)]+replacement
    return bytes(result)
def run(root,binary,compact,wide):
    here=Path(__file__).resolve().parent
    baseline=(here/'src/baseline_policy.rs').read_bytes();source=(here/'src/policy.rs').read_bytes()
    if sha(baseline)!=BASELINE_SHA:raise ValueError('original-baseline-source-identity')
    original_domain=old_domain(baseline.decode())
    cm=fixture.cm_tree();nf_old,_,_=fixture.nf_transition()
    new_state=fixture.state(cm.root,1,nf_old,1);old_state=new_state[:8]+original_domain+new_state[40:]
    old,_=fixture.emit(binary,old_state,compact,wide,'emit-original-baseline')
    raw,metadata=fixture.emit(binary,new_state,compact,wide)
    template=(root/'poc/private-exit-recovery/kpx3-policy-template.bin').read_bytes()
    if sha(template)!=TEMPLATE_SHA:raise ValueError('sealed-baseline-template-identity')
    expected=bytearray(template)
    manifest=json.loads((root/'poc/private-exit-recovery/kpx3-policy-template.json').read_bytes())
    for slot in manifest['patch_slots']:
        value=original_domain if slot['kind']=='domain' else compact
        at=slot['data_offset'];expected[at:at+len(value)]=value
    if old!=b'\x4c\x70'+old_state+bytes(expected):raise ValueError('original-emitter-full-template-conformance')
    old_pre,old_other=dispatch(old);new_pre,new_other=dispatch(raw)
    if normalized(new_pre,len(raw),len(old),original_domain,new_state,old_state)!=old_pre:
        raise ValueError('complete-common-framing-byte-conformance')
    if normalized(new_other,len(raw),len(old),original_domain,new_state,old_state)!=old_other:
        raise ValueError('retained-ADMIT-REVEAL-byte-conformance')
    # Explicit source routing check; zeroProof serialization failures cannot
    # distinguish which of two valid placeholder keys was actually selected.
    route='pl(b,300,1); data(b,&[32]); op(b,OpEqual); op(b,OpIf); data(b,wide_vk);\n    op(b,OpElse); data(b,compact_vk); op(b,OpEndIf); data(b,&[0x20]); op(b,OpZkPrecompile)'
    if route not in source.decode():raise ValueError('explicit-role-VK-source-routing')
    pushed=[value for _,value,_,_ in meter.tokens(raw) if value is not None]
    if pushed.count(compact)!=1 or pushed.count(wide)!=1:raise ValueError('exactly-two-role-VK-operands')
    upper=meter.current_private_upper_bound(raw)
    if len(raw)>23766 or upper>15041203 or upper>16009999:raise ValueError('whole-emitter-source-envelope')
    return {'classification':'COMPLETE_EMITTED_NATIVE_PROGRAM_NOT_A_FINANCIAL_POSITIVE',
        'baseline_whole_bytes':len(old),'new_common_redeem_bytes':len(raw),
        'private_source_all_branch_upper_units':upper,'selected_private_budget':1600,
        'budget1600_capacity_units':16009999,'baseline_source_sha256':sha(baseline),
        'new_policy_source_sha256':sha(source),'whole_redeem_sha256':sha(raw),
        'baseline_full_template_exact':True,'retained_common_and_ADMIT_REVEAL_byte_conformance':True,
        'role_VK_route':'mode32=wide; validated modes0/2=compact',
        'role_route_verified_by':'source-and-two-exact-emitted-operands; not-genuine-proof',
        'native_VM_calls':0,'matched_circuit':False,'financial_positive':False,
        'wire_bytes':{'compact2':3920,'wide32':12672,'terminal0':2848}}
