# Whole fast-branch script-unit bound

**Closed source bound:620,978 units** for successful valid-format spends of the
frozen candidate C fast branch with redeem length L<=49,152, including both
terminal and continuing paths. Declared ComputeBudget200 allows2,009,999 units,
leaving **1,389,021** above this conservative bound. Budget200 is unchanged.
No binary, VM, proof or benchmark was run for this review.

The claim concerns source charging for this exact public prototype. It does
not qualify its private relation, prior complete-liability I1, accepted backing,
data survival, consensus security or future code replacing the NOP envelope.
Script-unit sufficiency does not repair transaction-mass/fee failures.

## Scope and pins

Frozen source03 `main.rs` SHA:
`29f4d40c0e9457fb541411ad5b92beed3b357c2e0e8e9b4de8816686a3691bf8`.
Native revision `01b532e8b553523216471682649693af92f0fd16`.
[Exact identities](FUTURE-SOURCE-BOUND-IDENTITIES.json) pin the charging sources,
Cargo files and original pre-execution freeze. The independent second reader
recounted the core lengths,91 hashes, wide pushes and final arithmetic.

A successful input is canonical version1 P2SH/rawSPK35, one input, no covenant
ID, payload2029,65-byte SIG_HASH_ALL=1 signature and canonical redeem push.
State is fixed112 bytes. n is1..65536, m includes the sentinel, m<=n and a
successful witness authenticates legal current CM/NF indices and paths. Fixed
CMdepth16 and NFdepth17 do not grow with counts. Values, payout, fee and native
reserve obey the existing bounds up to MAX_SOMPI=2,870,000,000,000,000,000;
successful arithmetic outputs fit within8-byte ScriptNum. Count/limb arithmetic
is smaller. This includes arbitrary legal positions and amounts, not only the
small and high-index public fixtures. Invalid or missing state/authorization
is not made acceptable by this bound.

Output shape is one exact P2PK payout, plus one exact P2SH successor when
continuing. Their version-prefixed introspection widths are36/37. Arbitrary
nonstandard output scripts are outside the primary successful-spend bound.

## Fixed executed core; NOP padding creates no runtime work

The canonical minimal core is5,979 bytes. Two occurrences of `L+69` are emitted
as ScriptNum: the full signature-script-length guard and the successor
substring end. Increasing L through49,152 can increase each literal's encoding
by at most one byte. No other emitted width depends on L or state values:
the112-byte state literal, length-prefix bytes and domains/roots/counts have
fixed widths. Thus the nonpadding core is at most5,981 bytes; **6,000** is a
conservative ceiling. Frozen byte inspection independently confirms5,979 for
minimal and5,981 for both padded envelopes. This inspection reads prepared
bytes; it executes no script.

Every executed core opcode occupies at least one core byte and executes at most
once. Builder loops are unrolled. Each created item of at most32 bytes is
therefore covered by6,000*32=192,000 units. Literal pushes/moves are overcounted
by this allowance. Padding is exactly `OpNop`, which creates no item, performs
no hash/signature and consumes no script units. Native still counts its opcode
for the separate operation limit:49,152 is below1,000,000. The 49KiB envelope's
byte mass remains real even though its NOPs add no runtime units.

There is no emitted DUP/2DUP/3DUP family. OpSize peeks at the65-byte signature
and pushes only its numeric size; it does not copy that signature. Numerical
results, booleans, payload slices<=32 bytes and hash results<=32 are covered by
the generic term. Reordering operations do not secretly duplicate large items.
[Emitter helpers/core](source-03/src/main.rs), native
[charging](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L577-L598),
[Size](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L513-L520),
[NOP](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L355).

## Complete hash and signature inventory

| SHA256 family | Calls | Input bytes per call |
|---|---:|---:|
|Current CM membership|16|72|
|Old predecessor membership|17|72|
|Updated predecessor/intermediate root|17|72|
|Empty append authentication|17|72|
|New NF leaf/new root|17|72|
|K commitment|1|72|
|CM commitment|1|208|
|HMAC inner/outer|2|140 /96|
|Three NF leaves|3|76|
|**Total**|**91**|max208|

The empty NF leaf is prehashed into a literal, not hashed by an extra runtime
call. Exact input-byte tariffs sum6,792; including91 digest pushes gives9,704.
Use the larger rounded **100*(208+32)=24,000** allowance. Digest pushes are
already covered generically, so that part is deliberately double counted.
There is no hash over the whole2029-byte payload and no Groth16 call.
One native Schnorr adds **100,001** including its one-byte true result, also
conservatively double counting that result with the generic term.
[Hash pricing](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L61-L71),
[Schnorr](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L856-L873).

## Complete created-byte excess over32

| Nonhash wide-output family | Excess units |
|---|---:|
|84 node CAT pairs:64B then72B|6,048|
|Three NF leaves:40,72,76B CATs|276|
|K:40,72B CATs|48|
|CM:40,72,104,112,144,176,208B CATs|632|
|HMAC:two64B pads,two64B XORs,72/104/136/140/96B CATs|516|
|Successor selectors/CATs/SPK introspection|2L+42|
|Payout SPK construction/introspection|11|
|**Complete excess**|**2L+7,573**|

The successor explicitly selects78 bytes, produces110/114-byte prefix CATs,
selects L-114 suffix bytes, produces the L-byte reconstructed redeem, then
constructs36/37-byte expectedSPK. The actual suffix is used; no foreign policy
is substituted. No other payload selector exceeds32. Round the full excess
up to **2L+10,000**. Small numeric and comparison CATs stay within32 and need no
additional term. Initial input rawP2SH35 incurs zero extra-SPK charge.
[Successor source](source-03/src/main.rs),
[initial SPK charge](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L654-L677).

The standard external P2SH wrapper costs **2L+33**. Continuing successor
Blake2b costs at most **2L+32**, including its digest again. Terminal spends skip
that successor family; charging it anyway bounds both paths.

## Bound and practical limit

```text
U <=192000                 generic6,000corebytes*32
    +24000                 all SHA work
    +100001                one successful Schnorr
    +(2L+10000)            complete wide-byte excess
    +(2L+33)               standard P2SH wrapper
    +(2L+32)               continuing successor Blake2b
  =326066+6L
```

| Redeem L | Conservative whole-input bound | Budget200 allowance | Remaining margin |
|---:|---:|---:|---:|
|5,979|361,940|2,009,999|1,648,059|
|32,768|522,674|2,009,999|1,487,325|
|49,152|620,978|2,009,999|1,389,021|

Even before equality rejection, allowing both output-SPK introspections to
return native-legal raw scripts up to10,000 bytes needs at most another19,940
units, remaining below641k. This is an extra coarse rejection-path allowance,
not authorization for those scripts. The primary bound is for successful exact
P2PK/P2SH shapes and does not inherit acceptance from a meter bound.

The declared200 commitment is therefore source-sufficient beyond sampled
positives for this frozen fast branch. This does not select a lower commitment,
reprice any fee or change the49KiB economic failure. Re-derive if charging,
control flow, witnesses, depths, SPK shapes or emitted code change. Replacing
NOPs with a private branch requires its own source/runtime qualification;
its correctness and resource use are not implemented by this envelope.
