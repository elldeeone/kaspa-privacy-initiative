# Actual W private fallback budget bound

The exact16202-byte W private fallback has a conservative **complete-input
upper bound of14,957,286 script units**, including successful verification and
the P2SH input path. Budget1500 allows15,009,999 units, leaving52,713 units.
This is source analysis of all successful private paths, not a claim derived
from a cheap canary or a newly executed native case. Independent review is a
separate requirement before selecting the lower budget for a new owner action.

`INPUTS.json` pins the actual W program SHA256
`c03345e8e9bbd1df7cba8940e9578724c3dd2e127ad73ee6a974d0c182875f3e`,
immutable tail after its112-byte state literal
`5c9e15357f07f092e25f272ea40bb92f1c0335574e37e0e4e687297db4e56559`,
selected guest image633b3244, emitter76cfc5cc, child profile492a0981,
child Dd55d006a and compact VK074c06a5. Full identities and source hashes are
in the JSON; abbreviated identifiers here are labels only. The program bytes
were extracted from the public normalized actual-W case, then compared with
the later genuine accepted outer case. No emitter/native/prover was executed
to obtain this bound. Every one of the eight primary meter files was compared
byte-for-byte with its exact upstream Git blob at
`01b532e8b553523216471682649693af92f0fd16` (2.1.0).

The calculation copies the existing conservative source-meter method from
`poc/compact-private-policy/source_meter.py`. The meter adaptations widen
unknown arithmetic/context numbers from eight to nine bytes, including the
`i64::MIN` serialization edge, and refuse OP_SIZE unless its input width is
expressly exact. The selected private path has only two OP_SIZE uses, on its
initial128/65-byte items; its dynamic aggregate-only OP_SIZE is not executed.
BIN2NUM retains its input-width upper bound.
Literal pushes and alt-stack moves remain charged even where upstream makes
them free. The exact W final dispatch's **private ELSE arm** is selected; every
conditional inside it explores both alternatives and merges maximum lengths
and maximum accumulated cost. This includes199 conditional nodes and even
the wide-mode code that the W prefix rejects. The analysis does not use sampled
roots, amounts, cursor positions or private input count to prune paths.

The complete-input accounting is:

| Included component | Conservative charge |
| --- | ---: |
| Initial witness literals: zero65, proof128 and W program length L | L+193, although literal pushes are free upstream |
| P2SH locking-program BLAKE2b of the entire W program | 2L |
| Its digest32, expected hash literal32 and equality boolean1 | 65, including a free literal overcharge |
| Input locking SPK size | 35×100=3500, although this standard35-byte script is free |
| Total before W execution, L=16202 | 52,364 |
| W common prefix and maximum private execution | 14,904,922 |
| **Complete input** | **14,957,286** |

This covers signature-script execution, locking-program execution, saved P2SH
stack restoration, W execution and final success. Stack restoration/final
checks introduce no further charged pushes in the pinned engine. No charged
execution prelude or postlude is omitted. The program's dormant aggregate bytes
are included in L and its P2SH hash. Native byte/compute/storage transaction
mass and fee quoting are separate from execution-unit accounting.

Canonical framing is a required, source-enforced premise: the engine executes
the signature script in push-only mode; W requires depth2, argument widths128
and65, total signature length199+L, and exact push headers at0,66 and196.
Those headers partition the complete input into its65-byte literal,128-byte
proof and L-byte redeem. The private arm also requires its65-byte item to be
zero. Extra executable padding or extra witness items cannot produce another
successful trace omitted by this bound. The common W prefix still enforces
one input and its existing transaction/version/state/count/covenant checks.

The primary rules used are explicit: the [engine](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L577)
charges newly pushed bytes after each executing opcode;
[stack operations](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/data_stack.rs#L283)
record those bytes. [Literal pushes](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L160)
are unmetered, while SHA256 costs one unit per preimage byte and BLAKE2b costs
two, plus their newly pushed32-byte results. Comparisons have no additional
size-based tariff; their new boolean is at most one byte. Other stack copies,
CAT, numeric encoding and context substring results are charged at their
bounded output widths. Pure swaps/moves are free upstream and overcharged
where the old meter already did so.

The sole private Groth16 opcode has tag0x20 and exactly two public inputs. Its
[base cost](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs#L24)
is14,000,000 units and its [three gamma-ABC elements](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L16)
add3×250,000, totaling14,750,000. The final successful boolean is included by
the abstract execution, so a zero-proof failure is not mistaken for successful
verification. The native private arm has no executed Schnorr opcode: payout
script bytes are compared as data, rather than executed by this input.

The valid-path coverage is deliberately broader than the initial wallet:

| Private shape | Output layout covered |
| --- | --- |
| Mode0, positive remaining reserve and positive payout | No CM append; successor W at output0 and payout at output1 |
| Mode0, terminal reserve0 and positive payout | No CM append; payout at output0 |
| Mode2, payout0, invoice/payment and positive private change | Two CM appends; successor W only |
| Mode2, positive remaining reserve and positive payout | Two CM appends; successor W and payout |
| Either one or two real private inputs | Same two ordered native NF insertions and two-public-input verifier |

Each NF insertion has fixed depth17; every left/right index-bit conditional,
predecessor interval comparison and zero/nonzero successor-index branch is
explored. Native counts n∈[1,65535], m∈[1,131071], m≤2n+1 and m+2 capacity
checks remain in the program. Maximum-depth paths and boundary counts do not
add iterations: the emitter unrolls fixed loops. Mode2 CM append uses its fixed
subtree/path construction. Including the forbidden wide branch further
overapproximates CM work rather than silently assuming compact-only costs.
Both real-input choices and dummy padding execute these same native paths;
their private note/ownership constraints remain the selected circuit's job.

Payload lengths are fixed by the checked mode (2848 noappend,3920 compact;
unreachable wide12672 is also explored). Auth, roots, NF limbs and Merkle
siblings have fixed byte widths. Integer amounts/fees/reserve use canonical
eight-byte fields with the retained ranges up to2,870,000,000,000,000,000 sompi;
the nine-byte unknown-number abstraction is an additional overcharge. NUM2BIN
widths and context substring endpoints must be known constants or the analyzer
refuses. Successor construction copies the complete immutable W tail and
hashes the whole16202-byte program, including any CAT intermediates. A valid
successor SPK is exactly37 bytes including version; a payout SPK is36. Those
mandatory byte equalities justify the meter's37-byte context-SPK bound.
Oversized malformed output scripts can consume more before rejection; this
bound does not promise every invalid attack rejects within1500. Budget
exhaustion still rejects such an input. No check is removed or weakened.

Only the first112-byte state literal varies among W successors. It remains a
112-byte push followed by DROP; `decode_number` returns unknown for every such
literal, independent of its contents. All later reads have fixed endpoints and
both root/index branches are explored. The bound therefore covers every valid
state prefix with this exact immutable tail, not only the starting n2/m1 roots.
Changing the tail, image/profile/circuit, framing or pinned meter invalidates
this result and requires a new calculation/review.

The [unit conversion](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L5)
is10000 script units per budget unit with9999 free per input; the
[input commitment](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/tx.rs#L99)
adds that allowance. Thus1500 permits15,009,999. The actual aggregate-success
measurement is15,646,440 units (its earlier zero-proof seam was15,646,439), so
**aggregate budget1600 is unchanged**. Neither aggregate observation was used
to derive the private bound.

If root selects this reviewed option, the recovery wallet must set private
budget1500 before producing a fresh exact minimum quote, Auth and witness.
Previously fixed aggregate child authorizations, F0/F1 and totalF18,508,000
must remain unchanged. Old prepaid exit credit is surplus that can be returned;
it is not additional useful payment principal. At reference rate100, reducing
a compute-dominant private budget by100 units would reduce its fee by1,000,000
sompi; the actual amount/storage/layout fixpoint must still be normalized for
the real new fallback. This source result alone is not fee or lifecycle
qualification and no existing proof can be retargeted to the new fee.

Reproduce offline from this directory with `python3 -B bound.py`. Add
`--check-upstream /path/to/rusty-kaspa-at-01b532e8` to reauthenticate the eight
primary file hashes. Run `python3 -B -m unittest -v test_bound` for the six
source-analysis controls: complete-path accounting, program/tail mutation
refusal, branch maximum, unknown/dynamic operation refusal, and integer-width
and literal-token edges, plus refusal to treat an inexact OP_SIZE bound as a
constant. All passed; no VM/proof/PK/seed/network job was run.
