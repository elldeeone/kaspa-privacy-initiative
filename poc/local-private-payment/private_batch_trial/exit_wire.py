"""ADR-0074 exact new AuthExit projection; public framing/current-head checks.

This supplies no signature/proof validity, node currentness or reserve backing.
It reuses the existing indexed-NF verifier unchanged under an explicit new ABI.
"""
from dataclasses import dataclass
import hashlib
import importlib.util
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
_spec=importlib.util.spec_from_file_location('_kpb_retained_public_wire',HERE.parent/'verification/wire.py')
old=importlib.util.module_from_spec(_spec);sys.modules[_spec.name]=old;_spec.loader.exec_module(old)
MAX,NOTE_FLOOR,PAYOUT_FLOOR=old.MAX_VALUE,old.NOTE_FLOOR,old.PAYOUT_FLOOR
BODY_LEN=1604
CONTEXT_LEN=276
STATEMENT_LEN=152
STATE_TAG=b'KPBAST01'
BODY_TAG=b'KPBXEF01'
PREFIX_TAG=b'KPBXFX01'
EFFECTS_TAG=b'KPBXDG01'
STATEMENT_TAG=b'KPBPEX01'


def need(value,category):
    if not value:raise ValueError(category)


def fixed(value,size):
    need(type(value) is bytes and len(value)==size,'exit-fixed-width');return value


def uint(value,size):
    need(type(value) is int and 0<=value<1<<(8*size),'exit-integer-range');return value.to_bytes(size,'little')


@dataclass(frozen=True)
class HeadContext:
    chain:bytes
    pool:bytes
    profile:bytes
    domain:bytes
    service:bytes
    point:bytes
    cm_root:bytes
    nf_root:bytes
    cm_count:int
    nf_count:int
    reserve:int

    def encode(self):
        need(self.domain!=old.DOMAIN and self.domain!=bytes(32),'new-exit-domain')
        need(self.point[:32]!=bytes(32) and self.profile!=bytes(32),'new-exit-head-identity')
        need(1<=self.cm_count<=1<<old.CM_DEPTH and 1<=self.nf_count<1<<old.NF_DEPTH,'exit-state-capacity')
        need(NOTE_FLOOR<=self.reserve<=MAX,'exit-reserve-range')
        raw=b''.join(fixed(value,32) for value in (self.chain,self.pool,self.profile,self.domain,self.service))
        raw+=fixed(self.point,36)+fixed(self.cm_root,32)+fixed(self.nf_root,32)
        raw+=uint(self.cm_count,4)+uint(self.nf_count,4)+uint(self.reserve,8)
        need(len(raw)==CONTEXT_LEN,'exit-context-width');return raw

    def state(self):
        self.encode();return STATE_TAG+self.domain+self.cm_root+uint(self.cm_count,4)+self.nf_root+uint(self.nf_count,4)

    @classmethod
    def parse(cls,raw):
        fixed(raw,CONTEXT_LEN)
        context=cls(*(raw[at:at+32] for at in range(0,160,32)),raw[160:196],raw[196:228],raw[228:260],
            int.from_bytes(raw[260:264],'little'),int.from_bytes(raw[264:268],'little'),int.from_bytes(raw[268:276],'little'))
        need(context.encode()==raw,'canonical-exit-context');return context


@dataclass(frozen=True)
class Body:
    raw:bytes
    context:HeadContext
    action:bytes
    new_nf_root:bytes
    new_nf_count:int
    new_reserve:int
    fee:int
    payout:int
    payout_spk:bytes
    nf:bytes
    witness:bytes

    def next_state(self):
        c=self.context;return STATE_TAG+c.domain+c.cm_root+uint(c.cm_count,4)+self.new_nf_root+uint(self.new_nf_count,4)


def parse_body(raw):
    fixed(raw,BODY_LEN);need(raw[:8]==BODY_TAG,'new-exit-body-tag')
    context=HeadContext.parse(raw[8:284])
    result=Body(raw,context,raw[284:316],raw[316:348],int.from_bytes(raw[348:352],'little'),
        int.from_bytes(raw[352:360],'little'),int.from_bytes(raw[360:368],'little'),
        int.from_bytes(raw[368:376],'little'),raw[376:412],raw[412:444],raw[444:])
    need(result.action!=bytes(32) and result.nf!=bytes(32),'exit-nonzero-action-NF')
    need(1<=result.fee<=MAX and PAYOUT_FLOOR<=result.payout<=MAX
        and (result.new_reserve==0 or NOTE_FLOOR<=result.new_reserve<=MAX)
        and result.new_reserve+result.payout+result.fee==context.reserve,'exit-exact-native-conservation')
    need(result.new_nf_count==context.nf_count+1 and result.new_nf_count<=1<<old.NF_DEPTH,'exit-NF-count')
    need(result.payout_spk[:3]==b'\0\0\x20' and result.payout_spk[-1:]==b'\xac','exit-payout-script')
    return result


def state_spk(state,tail):
    fixed(state,112);need(state[:8]==STATE_TAG,'new-state-tag')
    need(type(tail) is bytes and 0<len(tail)<=65535-114,'immutable-policy-tail')
    return b'\0\0\xaa\x20'+hashlib.blake2b(b'\x4c\x70'+state+tail,digest_size=32).digest()+b'\x87'


def body(context,action,new_nf_root,new_nf_count,new_reserve,fee,payout,payout_spk,nf,nf_witness):
    raw=BODY_TAG+context.encode()+fixed(action,32)+fixed(new_nf_root,32)+uint(new_nf_count,4)
    raw+=uint(new_reserve,8)+uint(fee,8)+uint(payout,8)+fixed(payout_spk,36)+fixed(nf,32)+fixed(nf_witness,1160)
    parse_body(raw);return raw


def projection(raw_body,tail):
    b=parse_body(raw_body);c=b.context
    outputs=([(b.new_reserve,state_spk(b.next_state(),tail))] if b.new_reserve else [])+[(b.payout,b.payout_spk)]
    prefix=PREFIX_TAG+b'\x01\0\x01\0'+c.point+b'\xff'*8+uint(c.reserve,8)+b'\x25\0'+state_spk(c.state(),tail)+uint(len(outputs),2)
    for value,script in outputs:prefix+=uint(value,8)+uint(len(script),2)+script+b'\0'
    raw=prefix+bytes(36)+uint(BODY_LEN,4)+raw_body
    validate_public(raw);return raw


def parse_projection(raw):
    need(type(raw) is bytes and len(raw) in (BODY_LEN+240,BODY_LEN+192),'new-exit-projection-width')
    prefix,raw_body=raw[:-BODY_LEN],raw[-BODY_LEN:];b=parse_body(raw_body);c=b.context
    need(prefix[:8]==PREFIX_TAG and prefix[8:12]==b'\x01\0\x01\0' and prefix[12:48]==c.point
        and prefix[48:56]==b'\xff'*8 and prefix[56:64]==uint(c.reserve,8)
        and prefix[64:66]==b'\x25\0' and prefix[66:70]==b'\0\0\xaa\x20' and prefix[102:103]==b'\x87','new-exit-native-header')
    count=int.from_bytes(prefix[103:105],'little');need(count==(2 if b.new_reserve else 1),'new-exit-output-count')
    at=105;outputs=[]
    for _ in range(count):
        need(at+10<=len(prefix),'new-exit-output-width')
        value=int.from_bytes(prefix[at:at+8],'little');size=int.from_bytes(prefix[at+8:at+10],'little')
        need(size in (36,37) and at+11+size<=len(prefix),'new-exit-output-width')
        script=prefix[at+10:at+10+size];need(prefix[at+10+size:at+11+size]==b'\0','new-exit-output-covenant')
        outputs.append((value,script));at+=11+size
    need(at+40==len(prefix) and prefix[at:at+36]==bytes(36) and prefix[at+36:]==uint(BODY_LEN,4),'new-exit-native-tail')
    need(outputs[-1]==(b.payout,b.payout_spk),'new-exit-actual-payout')
    if b.new_reserve:
        need(outputs[0][0]==b.new_reserve and len(outputs[0][1])==37 and outputs[0][1][:4]==b'\0\0\xaa\x20'
            and outputs[0][1][-1:]==b'\x87','new-exit-continuing-reserve')
    need(c.reserve-sum(value for value,_ in outputs)==b.fee,'new-exit-actual-fee')
    return prefix,b,outputs


def validate_public(raw):
    _,b,_=parse_projection(raw)
    need(old.insert_nf(b.context.nf_root,b.context.nf_count,b.nf,b.witness)==b.new_nf_root,'new-exit-actual-NF-insertion')
    return b


def require_current_head(raw,expected,tail):
    b=validate_public(raw);prefix,_,outputs=parse_projection(raw)
    need(b.context==expected,'new-exit-exact-selected-head')
    need(prefix[66:103]==state_spk(expected.state(),tail),'new-exit-input-policy')
    if b.new_reserve:need(outputs[0][1]==state_spk(b.next_state(),tail),'new-exit-output-policy')
    return b


def statement(raw):
    prefix,b,_=parse_projection(raw)
    return STATEMENT_TAG+b.context.domain+b.context.cm_root+b.nf+hashlib.sha256(EFFECTS_TAG+prefix+b.raw).digest()+uint(b.payout,8)+uint(b.fee,8)
