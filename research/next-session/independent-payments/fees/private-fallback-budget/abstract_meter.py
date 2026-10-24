"""Conservative byte-length abstract meter; never executes scripts or cryptography.

Adapted from the pinned existing source meter. Unknown arithmetic/context
numbers use nine bytes, covering even serialize_i64(i64::MIN) conservatively;
BIN2NUM retains its source-byte bound. Literal pushes/alt moves remain charged
even where upstream makes them free. No VM/proof/cryptography is invoked.
OP_SIZE refuses an upper-bound-only width: only expressly exact input/literal
widths may become numeric constants. The selected private path uses it twice,
on the initial128/65-byte items, before any variable-width abstract result.

Only the opcode subset present in the current private branch is supported.
Unknown instructions and incompatible branch stack shapes fail, never cost zero.
Both conditional alternatives are explored; push widths/hash preimage lengths
are bounded from the script. Financial validity and proof correctness are not
decided by this source analysis.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Item:
    length: int
    number: int | None = None
    exact_length: bool = False


def numeric(value=None, width=9):
    if value is None:return Item(width)
    size=(abs(value).bit_length()+7)//8
    if size and abs(value)>>(8*size-1):size+=1
    return Item(size,value)


def decode_number(raw):
    if len(raw)>8:return None
    if not raw:return 0
    magnitude=int.from_bytes(raw,'little')&~(0x80<<(8*(len(raw)-1)))
    return -magnitude if raw[-1]&0x80 else magnitude


def tokens(raw):
    result=[];at=0
    while at<len(raw):
        start=at;code=raw[at];at+=1;data=None
        if 1<=code<=75:length=code
        elif code in (0x4c,0x4d,0x4e):
            size={0x4c:1,0x4d:2,0x4e:4}[code]
            if at+size>len(raw):raise ValueError('truncated-opcode-length')
            length=int.from_bytes(raw[at:at+size],'little');at+=size
        else:length=None
        if length is not None:
            if at+length>len(raw):raise ValueError('truncated-literal')
            data=raw[at:at+length];at+=length
        result.append((code,data,start,at))
    return result


def ast(raw):
    values=tokens(raw);at=0
    def block():
        nonlocal at
        output=[]
        while at<len(values):
            item=values[at];at+=1
            if item[0] in (0x67,0x68):return output,item[0]
            if item[0] in (0x63,0x64):
                yes,end=block();no=[]
                if end==0x67:no,end=block()
                if end!=0x68:raise ValueError('unbalanced-conditional')
                output.append(('if',yes,no))
            else:output.append(item)
        return output,None
    result,end=block()
    if end is not None or at!=len(values):raise ValueError('unexpected-conditional-end')
    return result


class Meter:
    def __init__(self,stack=(),alt=()):
        self.stack=list(stack);self.alt=list(alt);self.units=0

    def pop(self):
        if not self.stack:raise ValueError('abstract-stack-underflow')
        return self.stack.pop()

    def push(self,item):
        if item.length<0 or item.length>1_000_000:raise ValueError('abstract-element-range')
        self.units+=item.length;self.stack.append(item)

    def run(self,nodes):
        for node in nodes:
            if node[0]=='if':
                self.pop();left=Meter(self.stack,self.alt);right=Meter(self.stack,self.alt)
                left.run(node[1]);right.run(node[2])
                if len(left.stack)!=len(right.stack) or len(left.alt)!=len(right.alt):
                    raise ValueError('abstract-conditional-stack-shape')
                def merge(a,b):return Item(max(a.length,b.length),a.number if a.number==b.number else None)
                self.stack=[merge(a,b) for a,b in zip(left.stack,right.stack)]
                self.alt=[merge(a,b) for a,b in zip(left.alt,right.alt)]
                self.units+=max(left.units,right.units);continue
            code,data,_,_=node
            if data is not None:self.push(Item(len(data),decode_number(data),True));continue
            if code==0:self.push(numeric(0))
            elif code==0x4f:self.push(numeric(-1))
            elif 0x51<=code<=0x60:self.push(numeric(code-0x50))
            elif code==0x75:self.pop()
            elif code==0x76:self.push(self.stack[-1])
            elif code==0x7c:self.stack[-2:]=self.stack[-2:][::-1]
            elif code==0x74:self.push(numeric(len(self.stack)))
            elif code==0x82:
                if not self.stack[-1].exact_length:raise ValueError('SIZE-requires-exact-length')
                self.push(numeric(self.stack[-1].length))
            elif code==0x6b:
                item=self.pop();self.alt.append(item);self.units+=item.length # Safe upper: charge even a move.
            elif code==0x6c:self.push(self.alt.pop())
            elif code in (0x69,):self.pop()
            elif code in (0x88,0x9d):self.pop();self.pop()
            elif code in (0x87,0x9a,0x9b,0x9c,0x9f,0xa0,0xa1,0xa2):
                self.pop();self.pop();self.push(Item(1))
            elif code in (0x91,0x92):self.pop();self.push(Item(1))
            elif code in (0x93,0x94,0x95,0x96,0x97):
                right=self.pop();left=self.pop();value=None
                if left.number is not None and right.number is not None:
                    a,b=left.number,right.number
                    if code==0x93:value=a+b
                    elif code==0x94:value=a-b
                    elif code==0x95:value=a*b
                    elif b and code==0x96:value=abs(a)//abs(b)*(1 if a*b>=0 else -1)
                    elif b and code==0x97:value=a-(abs(a)//abs(b)*(1 if a*b>=0 else -1))*b
                self.push(numeric(value))
            elif code==0x7e:
                right=self.pop();left=self.pop();self.push(Item(left.length+right.length))
            elif code==0xce:
                item=self.pop();self.push(numeric(item.number,min(item.length,8)))
            elif code==0xcd:
                width=self.pop();self.pop()
                if width.number is None or not 0<=width.number<=1_000_000:raise ValueError('unbounded-num2bin')
                self.push(Item(width.number))
            elif code in (0xb8,0xbc,0xc6,0xc8):
                end=self.pop();start=self.pop()
                if code!=0xb8:self.pop()
                if start.number is None or end.number is None or not 0<=start.number<=end.number:
                    raise ValueError('unbounded-context-substring')
                self.push(Item(end.number-start.number))
            elif code==0x7f:
                end=self.pop();start=self.pop();data=self.pop()
                size=(end.number-start.number if end.number is not None and start.number is not None else data.length)
                if not 0<=size<=data.length:raise ValueError('abstract-substring-range')
                self.push(Item(size))
            elif code in (0xa8,0xaa):
                data=self.pop();self.units+=data.length*(1 if code==0xa8 else 2);self.push(Item(32))
            elif code==0xa6:
                tag=self.pop();vk=self.pop();proof=self.pop();count=self.pop()
                if tag.number!=0x20 or vk.length!=328 or proof.length!=128 or count.number!=2:
                    raise ValueError('only-fixed-two-input-Groth16-supported')
                self.pop();self.pop();self.units+=14_750_000;self.push(Item(1))
            elif code in (0xb2,0xb3,0xb4,0xb5,0xb7,0xb9,0xc4):self.push(Item(9))
            elif code==0xb6:self.push(Item(20))
            elif code in (0xba,0xcf):self.pop();self.push(Item(32))
            elif code==0xbd:self.pop();self.push(Item(8))
            elif code in (0xbb,0xbe,0xc0,0xc1,0xc2,0xc5,0xc7,0xc9,0xd6):self.pop();self.push(Item(9))
            elif code in (0xbf,0xc3):self.pop();self.push(Item(37))
            else:raise ValueError(f'unsupported-source-opcode-{code:02x}')
        return self


def current_private_upper_bound(redeem):
    tree=ast(redeem)
    if tree[-1][0]!='if':raise ValueError('expected-final-private-dispatch')
    meter=Meter([Item(65,exact_length=True),Item(128,exact_length=True)])
    # Witness pushes + outer P2SH hash/literals, plus an overcharge of the full
    # 35-byte input SPK at 100 units/byte (actual standard-size allowance is free).
    meter.units=3*len(redeem)+258+3500
    meter.run(tree[:-1]);meter.pop();meter.run(tree[-1][1])
    if len(meter.stack)!=1 or meter.alt:raise ValueError('expected-one-final-success-item')
    return meter.units
