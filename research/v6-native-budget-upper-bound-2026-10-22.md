# Source upper bound for the fixed v6 reserve-input budget

**Result: budget 1600 covers every valid operation of the pinned fixed v6
standard-P2SH reserve input 0.** A deliberately loose source bound is
**15,857,502 script units**, below its **16,009,999-unit allowance** by
**152,497 units**. The argument includes bootstrap, admission, private spending,
partial withdrawal, continuing drain and terminal drain; it does not extrapolate
the 13 retained measurements. No wallet, default, circuit, native binary or
transaction was changed or executed for this analysis.

The current source still declares `BUDGET=3000`. This is evidence supporting a
separate budget-1600 decision, not a statement that the default was changed.

## Exact scope and identities

Scientific source: `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`.
Native source: `01b532e8b553523216471682649693af92f0fd16`, independently
confirmed as the cached checkout's HEAD.

The bound requires the existing `two_input::covenant::redeem` with its fixed
24,576-byte padded script, 105-byte state, 328-byte VK with exactly two public
digest limbs, 128-byte proof, exact 24,709-byte two-literal-push scriptSig and
5,228-byte payload. Input 0 is the standard 35-byte raw P2SH script produced by
`reserve_spk`. It is a bound on **successful valid fixed-shape spends**, not
arbitrary malformed scripts or transactions, a different covenant/VK, or an
alternative bare-script deployment. Input 1 has its own meter; an admission's
ordinary funding signature is not charged to input 0. This is a script-unit
bound, not a CPU-time, fee, transaction-mass or economic guarantee.
[Fixed format](/home/luke/projects/kpi-intensive-2026-10-22/observer/poc/shared-pool/src/two_input/mod.rs:23),
[covenant](/home/luke/projects/kpi-intensive-2026-10-22/observer/poc/shared-pool/src/two_input/covenant.rs).

| Source | SHA256 |
| --- | --- |
| `poc/shared-pool/src/two_input/covenant.rs` | `3b6d73c1ebada11d156f3020b444c881160e2f4d8eb7ae629a23ac267bf0d96d` |
| `poc/shared-pool/src/two_input/mod.rs` | `255f8e908fcb1c4a76dcc8ebe0ca5f4e9ddbadc8ba46f63036cb413298bc8150` |
| Native `crypto/txscript/src/opcodes/mod.rs` | `201d69b5a8de3db27b94b3e850a7ee62c4920532886c1d19544baed7fd163731` |
| Native `crypto/txscript/src/data_stack.rs` | `9caf21b92c51002099f02b140b119f9126274630365805d63837f847f4168050` |
| Native `consensus/core/src/mass/units.rs` | `0a47b4dda868da1df5064a9745c4f1278d9b3fd388db7416f5fb05068fef12ab` |

## Native charging rules

For budget 1600, the input allowance is `1600*10000 + 9999 = 16,009,999`.
There is no general per-op execution surcharge. Literal number/data pushes,
conditional-control opcodes, NOP padding, stack moves and drops cost zero.
Runtime-created/copied bytes are charged by their length; cryptographic
operations have additional explicit charges.
[Unit conversion](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L4-L23),
[input allowance](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/tx.rs#L99-L102),
[meter](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/runtime_resource_meter.rs),
[literal pushes](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L160-L184).

| Operation | Successful charge |
| --- | ---: |
| Groth16 with two public inputs | `14,000,000 + 3*250,000 + 1 = 14,750,001` |
| SHA256 of L bytes | `L + 32` |
| Blake2b of L bytes | `2*L + 32` |
| CAT, substring, copied stack item | Newly pushed byte length |
| Arithmetic / comparison | Encoded result bytes; well below the generic 32-byte allowance below |
| Standard P2SH wrapper around R-byte redeem | `2*R + 33` |

The Groth16 charge includes the returned true byte. Standard P2SH raw SPK is
35 bytes, so the initial `100*max(SPK_size-35,0)` charge is zero. Its wrapper
hashes the exact redeem and pushes a successful equality result. P2SH stack
cloning/restoration and altstack proof moves add no hidden copy charge.
[Groth16 fixed/key charge](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L18-L59),
[Groth16 base tag](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs#L29-L34),
[hash charges](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L785-L801),
[initial charge and P2SH execution](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L655-L677),
[P2SH form](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/standard.rs#L34-L37).

## Conservative counting argument

Charge **32 units for every byte of the 24,576-byte redeem script**. Every
executed instruction occupies at least one byte and executes at most once;
loops in the Rust builder are statically unrolled. This therefore covers every
instruction that creates at most 32 runtime bytes. It deliberately overcharges
literal data bytes, zero-cost padding/control, hash outputs and the Groth16
instruction. Add full hash/proof charges and the enumerated excess above
32 bytes separately. This is source accounting, not the native implementation's
explicitly heuristic script-length estimator.

All successful arithmetic results, comparison booleans and fixed four-byte
`NUM2BIN` results fit the generic allowance. `less256` uses five limbs of at
most seven bytes plus a zero sign byte; either equality branch or the repeated
less-than branch is covered. `BIN2NUM` canonicalizes these small values;
no 32-byte digest is passed directly into numeric comparisons. The only DUP
copies a 32-byte SHA digest. Other stack operations are moves or drops.
[Comparisons and limb construction](/home/luke/projects/kpi-intensive-2026-10-22/observer/poc/shared-pool/src/two_input/covenant.rs:163),
[numeric encoding](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/data_stack.rs#L127-L225),
[NUM2BIN/BIN2NUM bounds](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L1297-L1313).

### Hash count and input lengths

Sum **all** source branches together, including mutually exclusive ones:

| Family | SHA256 calls |
| --- | ---: |
| Historical anchor: leaf + depth-16 path | 17 |
| Two nullifier insertions: each three leaves + four depth-17 paths | 142 |
| Bootstrap history: leaf + depth-16 path | 17 |
| Two commitment appends and one history append | 99 |
| Final ciphertext and authorization hashes | 2 |
| Total | **277 ≤ 300** |

Merkle inputs are 65 bytes, nullifier leaves at most 69, and history/commitment
leaves smaller. Final ciphertext/auth inputs are 370/377 bytes. Therefore
**300*(377+32) = 122,700** is a safe full SHA charge. The sole redeem Blake2b
hashes the reconstructed 24,576-byte successor once; add **49,184**. The external
P2SH wrapper is separately charged **49,185**. Terminal paths omit successor
work, but including it remains conservative.
[Merkle helper](/home/luke/projects/kpi-intensive-2026-10-22/observer/poc/shared-pool/src/two_input/covenant.rs:144),
[anchor/nullifiers/bootstrap](/home/luke/projects/kpi-intensive-2026-10-22/observer/poc/shared-pool/src/two_input/covenant.rs:359),
[appends/final hashes](/home/luke/projects/kpi-intensive-2026-10-22/observer/poc/shared-pool/src/two_input/covenant.rs:493).

### Every nonhash runtime push above 32 bytes

All payload/scriptSig selectors have compile-time endpoints. The complete wide
selector inventory, counting all branches, is:

| Selector family | Returned bytes / count | Excess above 32 |
| --- | --- | ---: |
| Successor prefix/state/suffix | 36, 105, 24,434 | 24,479 |
| Anchor count/root, funding SPK, payout SPK | 36 each | 12 |
| Nullifier old leaf / old next link | 68 twice / 36 twice | 80 |
| Terminal state zero / admission witness prefix | 105 / 2,832 | 2,873 |
| Drain ciphertext zero / append-witness zero | 370 / 1,536 | 1,842 |
| Final ciphertext/auth digest sources | 370 / 377 | 683 |
| Total selector excess | | **29,969** |

There are 528 Merkle CATs, plus 17 other wide leaf CATs, excluding successor
construction: **545 ≤ 600 wide CATs**, each output at most 69 bytes. Add at most
`600*(69-32) = 22,200`. This ceiling concerns **wide** CATs; additional short
comparison CATs are already covered by the generic allowance.

The five successor CAT outputs are 141, 142, 24,576, 36 and 37 bytes, adding
**24,772** excess units. Its construction is fixed: 36-byte prefix + 105-byte
state + one DROP + 24,434-byte suffix = 24,576 bytes. The three possible SPK
introspections return at most 37 bytes in a valid fixed-shape transaction,
adding at most **15** excess units. Successful equality checks constrain the
admission funding/payout SPKs to their 36-byte authorization fields and the
successor to its 37-byte encoded P2SH SPK.
[Successor construction](/home/luke/projects/kpi-intensive-2026-10-22/observer/poc/shared-pool/src/two_input/covenant.rs:116),
[SPK version prefix](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L907-L914).

The enumerated wide-push excess is at most
`29,969 + 22,200 + 24,772 + 15 = 76,956`.
Round it upward to **100,000** units.

## Final bound and verification

| Term | Units |
| --- | ---: |
| Fixed two-input Groth16 call, including true | 14,750,001 |
| Generic redeem allowance: 24,576 × 32 | 786,432 |
| P2SH wrapper | 49,185 |
| Successor Blake2b | 49,184 |
| Rounded full SHA allowance | 122,700 |
| Rounded complete wide-push excess | 100,000 |
| Initial standard-SPK charge | 0 |
| **Conservative total** | **15,857,502** |
| **Budget-1600 allowance** | **16,009,999** |
| **Remaining margin** | **152,497** |

An independent read-only review checked the native charging schedule, P2SH
framing, arithmetic/encoding limits, all 277 SHA calls, wide CATs and selectors;
it found no omitted charge family for this scope. The small checker
`artifacts/groth16-compression-preparation/v6_native_budget_bound.py` verifies
the source hashes and enumerated arithmetic. Its result is saved beside it as
`v6_native_budget_bound.json`. This is not a second native execution or a formal
verification of the source-to-bytecode compiler.

The native lane's existing 13 genuine transactions are corroborating evidence,
not the bound's premise. Their retained budget-1600 run is
`native/poc/shared-pool/evidence/2026-10-22-public-native-budget/attempt-03/`;
`native.stdout.json` retains each original public context, ID/signatures,
metered units and recomputed mass. Bootstrap and ordinary spending have
different measured thresholds. The all-branch source bound covers both without
assuming their samples exhaust future values, nullifier ordering or tree counts.

Re-derive the bound if the covenant, padded length, payload/selector layout,
tree depths, VK/input arity, P2SH framing or native charging schedule changes.
The analysis leaves the current default and every privacy/economic limitation
unchanged.
