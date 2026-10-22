# Re-derived bound for successful S7 ordinary reserve input0

Prospective result, pending independent source review: **15,857,502 units**, below ComputeBudget1600's **16,009,999** allowance by **152,497**. This re-derives the earlier v6 accounting for the pinned S7 union; it does not extrapolate the four measured cases or change the factory's historical1700 value.

Exact source/native identities are in source-identities.json. The native revision is01b532e8b553523216471682649693af92f0fd16; S7 native.rs SHA7df243d9b94224e464cd2b49f60cbcce24b0ae2db649c89d7241fd3cdde689cb. Re-derive if any pinned charging rule, emitted guard/layout, key arity, framing or depth changes.

Scope: successful valid ordinary branch0 spends of the exact24,576-byte padded P2SH redeem,105-byte S7 state,328-byte canonical inner VK/three coefficients,128-byte proof,24,709-byte canonical two-push scriptSig and5,231-byte ordinary payload. Input0 alone is bounded. ADMIT input1 has its own budget/meter. The result includes ordinary bootstrap, admission, SPEND, partial withdrawal, continuing DRAIN and terminal DRAIN source branches. DRAIN execution remains untested in this fresh profile. It excludes arbitrary malformed/failing scripts, nonstandard SPKs, other key arities, paired branch1 and CPU/transaction-mass/economic guarantees.

## Why the union does not add an omitted charge family

Native execute_opcode (lib.rs577–598) executes an opcode only when its conditional branch is active or the opcode is conditional. It charges newly pushed runtime bytes only after that execution. Conditional controls themselves do not create bytes or hash/proof work; NOPs, literal pushes, moves/drops have no general per-op surcharge. The paired branch is skipped when branch0 is selected. It cannot execute its five-input outer verifier or claim hashing during a successful ordinary spend.

Conservatively charge32 units for **every byte of the entire24,576-byte union**, including literals, both branch bodies and padding. Every executed instruction occupies at least one byte and executes at most once; builder loops are unrolled. This already covers the new header/selector comparisons, <=10-byte selectors and their booleans. It also covers all narrow arithmetic, count and7-byte-limb numeric operations. Opcode-count validity is a separate structural constraint, not a hidden script-unit surcharge.

The ordinary body retains the same guard/helper structure. The new header adds3 payload bytes and shifts selectors by3; it changes no returned wide-selector length. The old32-byte runtime domain selector becomes a free literal of the same32-byte width. State discriminator6→7 changes one literal byte only. The prefix remains36+105+DROP=142; whole-union suffix remains24,434. Successor reconstruction therefore remains exactly24,576 bytes. No paired-branch operation is included in the executed ordinary inventory below.

## Re-counted executed ordinary inventory

Sum mutually exclusive ordinary branches together; this overcounts successful paths.

| SHA family | Calls |
|---|---:|
| Historical anchor leaf + depth16 path |17|
| Two NF insertions: three leaves + four depth17 paths each |142|
| Bootstrap history leaf + depth16 path |17|
| Two CM appends + one history append |99|
| Final ciphertext and authorization |2|
| Total |277 <=300|

SHA inputs are at most377 bytes: auth377/cipher370, Merkle node65, NF leaf69 and smaller history/CM leaves. Payload5231 itself is not hashed wholesale by the covenant. Thus300*(377+32)=122,700 is still safe. The one ordinary successor Blake2b charge is2*24,576+32=49,184. External P2SH wrapper costs2*24,576+33=49,185; raw standard P2SH SPK35 incurs zero initial excess-SPK charge.

All nonhash runtime pushes above32 bytes remain:

| Selector family | Returned lengths/count | Excess above32 |
|---|---|---:|
| Successor prefix/state/suffix |36,105,24434 |24479|
| Anchor count/root, funding SPK, payout SPK |36 each |12|
| NF old leaf / old next link |68 twice /36 twice |80|
| Terminal zero state / ADMIT witness prefix |105 /2832 |2873|
| DRAIN zero ciphertext / append witness |370 /1536 |1842|
| Cipher/auth digest sources |370 /377 |683|
| Selector excess | |29969|

There are528 Merkle CATs plus17 other wide-leaf CATs, <=600 wide CATs. Each produces at most69 bytes, adding at most600*(69-32)=22,200 excess units. Additional comparison CATs return <=32 bytes and are already covered. Five successor CAT outputs141,142,24576,36,37 add24,772. Three possible SPK introspections return <=37 bytes on successful fixed-shape spends, adding15. Thus wide excess29969+22200+24772+15=76,956, conservatively rounded to100,000.

The only ordinary DUP is a32-byte SHA digest. Stack moves/altstack operations do not incur hidden copy charges. Actual proof128 and VK328 are literal-push/moved data; no extra omitted selector copies them. Small numeric results fit the generic32-byte allowance. Existing successful-input constraints bound current CM/NF counts, values and funding/payout SPKs. The inherited ADMIT index>=2^31 liveness limitation is unchanged; this is not a claim of successful full-u32 ADMIT support.

## Bound arithmetic

| Term | Units |
|---|---:|
| Inner Groth16 with2 public limbs, including true |14,750,001|
| Entire redeem generic allowance24576*32 |786,432|
| P2SH wrapper |49,185|
| Ordinary successor Blake2b |49,184|
| Full SHA ceiling |122,700|
| Rounded complete wide-push excess |100,000|
| Initial standard-P2SH SPK excess |0|
| **Total** |**15,857,502**|
| Budget1600 allowance1600*10000+9999 |16,009,999|
| **Margin** |**152,497**|

No new native execution or default change establishes this note. Independent source review must check skipped-branch charging, ordinary-only arity2, all wide pushes and the277-call enumeration against the exact source. Native candidate and boundary cases remain separately required. This is source accounting, not formal verification of compiler/runtime correctness or proof-system security.
