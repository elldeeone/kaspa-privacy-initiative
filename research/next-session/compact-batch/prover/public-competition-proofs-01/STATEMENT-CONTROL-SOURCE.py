from pathlib import Path
import hashlib,json
base=Path(__file__).resolve().parent
names=('compact2','wide32','compact-after-reveal')
a={name:(base/name/'proof/authorization528.bin').read_bytes() for name in names}
assert all(len(x)==528 and x[:8]==b'KPX4AU01' for x in a.values())
c,w,r=(a[name] for name in names)
def u32(value):return int.from_bytes(value,'little')
def u64(value):return int.from_bytes(value,'little')
assert c[8:268]==w[8:268] # Domain, previous pool, entire current state, reserve, fee and both NFs.
assert c[204:268]==r[204:268] and c[204:236]!=c[236:268] and bytes(32) not in (c[204:236],c[236:268])
assert c[76:84]==r[76:84]==b'KPX2ST01' and c[84:116]==r[84:116]
assert c[116:152]==r[116:152] and u32(c[148:152])==64 # CM root/cursor remain current.
assert u32(c[184:188])==3 and u32(r[184:188])==4 and c[152:184]!=r[152:184]
assert u64(c[188:196])==32_000_000_000 and u64(r[188:196])==31_000_000_000
assert all(u64(x[196:204])==1000 for x in a.values()) and c[40:76]!=r[40:76]
assert c[300]==r[300]==2 and w[300]==32
result={'schema':'kpx4-public-competition-statement-check/v1','classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND_NO_MAIN_DATA',
'first_two_same_domain_previous_pool_current_state_reserve_fee_and_two_real_NFs':True,
'after_reveal_same_two_original_real_NFs':True,'after_reveal_current_CM_root_and_cursor_64_unchanged':True,
'after_reveal_current_NF_count':4,'before_reveal_NF_count':3,'before_reveal_reserve_sompi':32_000_000_000,
'after_reveal_reserve_sompi':31_000_000_000,'after_reveal_distinct_previous_pool_outpoint_and_NF_root':True,
'authorization_sha256':{name:hashlib.sha256(x).hexdigest() for name,x in a.items()},
'scope':'Public Auth byte consistency only; accepted REVEAL and native rejection are separate lifecycle evidence.'}
(base/'PUBLIC-STATEMENT-CHECK.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps(result,sort_keys=True))
