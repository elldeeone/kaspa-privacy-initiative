# Change-spend lifecycle proposal

Status: source-only proposal pending ADR0055 and the root-selected common
contract. No identity, setup, proving key, proof, native VM, funding or broadcast
has been created or run in this lane.

## Minimal workload

Use one initial useful 10 KAS private payment. Integer sompi are authoritative.
Let `f0` through `f4` be the five independently quoted private-action fees.

| Step | Consumed private value | Native payout | New real private values | CM/NF counts |
| --- | ---: | ---: | --- | --- |
| Direct whole Alice founding | — | — | `1,000,000,000 + f0` | 1 / 1 |
| Alice private payment | `1,000,000,000 + f0` | 0 | Bob `1,000,000,000`, plus one dummy | 3 / 3 |
| Bob partial cashout | `1,000,000,000` | `400,000,000` | Bob `600,000,000 - f1`, plus one dummy | 5 / 5 |
| Bob pays Charlie from recovered change | `600,000,000 - f1` | 0 | Charlie `300,000,000`; Bob `300,000,000 - f1 - f2` | 7 / 7 |
| Bob full cashout after another recovery | `300,000,000 - f1 - f2` | `300,000,000 - f1 - f2 - f3` | two dummies | 9 / 9 |
| Charlie terminal cashout | `300,000,000` | `300,000,000 - f4` | none | 9 / 11 |

The five proofs belong to Alice once, Bob three times, and Charlie once. Each
live Bob/Charlie proof is produced locally from only that owner's original
seed-only backup, authenticated public parameters, and a fresh independently
fetched current view. Bob's seed-only backup is unchanged across both recovery
steps. No operator-precomputed exit or private recipe enters an owner process.

One initial recipient avoids a second 10 KAS ingress claim and avoids making
two-real-input aggregation a prerequisite for the terminal owner. The core
still retains its existing two-input relation and its full validation rules.

The current 60,000,000-sompi real-note floor and 10,000,000-sompi native-payout
floor imply these exact workload conditions:

- `f1 <= 540,000,000` for the first real change;
- `f1 + f2 <= 240,000,000` for the second real change;
- `f1 + f2 + f3 <= 290,000,000` for Bob's final payout;
- `f4 <= 290,000,000` for Charlie's final payout.

All fees must be positive. Actual official mass/storage fixed points determine
the fees; no previous fee is hardcoded. Previous roughly 19M-sompi private fees
are only a sizing observation: they would leave roughly 581M and 262M real
change, well above the floor. They are not quotes for a new domain or body.

## Whole-source accounting

Let `S` be the selected ordinary source UTXO, `e` its direct-founding fee, and
`C = S - e - (1,000,000,000 + f0)` the explicit ordinary founding change. Require
`C == 0` or a legal ordinary output; never hide or silently donate this tail.

The three final native payouts sum to
`1,000,000,000 - f1 - f2 - f3 - f4`. Reconcile from actual returned bodies:

```text
S = C + all three native payouts + e + f0 + f1 + f2 + f3 + f4
```

If ordinary funding/merge consumes total `U`, charges `g`, and returns separate
ordinary change `Cf`, also require:

```text
U = Cf + C + all three native payouts + g + e + f0 + f1 + f2 + f3 + f4
```

End with reserve zero, no successor pool output, no new CM on the terminal
action, all recognized private claims spent, and all ordinary change and native
payout UTXOs explicitly accounted. Count each note principal once.

## Required interfaces

The cold wallet proposes these strict operations:

1. `recover`: seed-only discovery of current owned claims and native payouts.
2. `prepare-partial-cashout(payout_sompi)`: one own recognized claim, one real
   self-change receipt, one sealed dummy, fresh deterministic payout destination.
3. `prepare-private-payment(payment_sompi, recipient_invoice_path)`: public
   existing V2 invoice208, one own recognized input, one recipient receipt and
   one self-change receipt. The recipient's seed/opening keys never enter the
   sender witness.
4. `prepare-full-cashout`: existing continuing/terminal full-claim behavior.

No operation accepts a caller-supplied CM position, owned-note amount map, tree,
operator witness or precomputed body. Output slot permutations are selected
privately and held coherently across the selected quote/proof; recovery finds
outputs by owner recognition. The contract must freeze receive-index selection
and same-head retry behavior. Existing trial assembly forces invoice index0;
the generalized owner builder must use the recognized receipt's actual index.

Fee-dependent change needs fresh encryption for each changed receipt plaintext.
Do not reuse an encryption nonce/ephemeral secret across fee guesses. Established
SalsaBox sealing remains the encryption primitive. Retain the final selected
receipt/cipher pair before proving, and use canonical sealed dummy ciphertexts.

The controller should accept only public action effects plus accepted/current
network evidence after local preparation; private owner files stay outside Git.
Its reusable responsibilities are exact predecessor/outpoint/value/SPK links,
fee fixed points, body/proof-only substitution, actual-context revalidation,
once-only root submission requests, and final source reconciliation. The root
alone funds/submits. Owner report exports contain aggregate counts and public
transaction effects, with no owner-to-CM/index/native-emergency-key map.

## Decisive negative cases

- Reusing the consumed original claim after partial cashout: recovery recognizes
  the physical original nullifier as occupied; the owner action must refuse.
- Reusing the consumed first change after the private payment: the same occupied
  nullifier refusal, with the newly received second change still recoverable.
- Old backup plus new current head must discover change without a stored wallet
  counter or a supplied note-position map.
- A proof/body prepared for an old head must be refused before submission when
  the pool outpoint or current state changes. No transparent fallback.
- Changing payout/destination/fee/recipient/change after proof must fail the
  original body/Auth/proof binding; wrong-domain or wrong-current-root data must
  halt. Keep positive alternate statements separate from replay negatives.
- Reject zero/negative/boolean/noncanonical amounts, too-small positive change,
  payout below its floor, duplicated real inputs, stale CM/NF paths, and illegal
  terminal outputs. Preserve exact integer conservation at both range edges.

Source/component controls can test those boundaries now; genuine native and
current-state race evidence needs root-selected runtime/fixture gates later.

## Existing source inspected

- `poc/private-cashout-trial/action.py`, SHA256
  `6ee9b1066dfcccb6657518e9fb34a3f1a570b01045af715b3b02631dfc8e599f`:
  Auth528, value conservation, sequential NF witnesses, continuing CM appends,
  terminal zero/carry rules, real/dummy note floor and native payout floor.
- `poc/private-cashout-trial/prepare.py`, SHA256
  `2ffdb475a902c3c9f217b2538267f3334dcbe628108e930a95c803ef955ae52b`:
  fresh instance ownership, own receipt recognition, whole-program/native body
  binding and ordinary offline SDK signing.
- `poc/private-cashout-trial/materialize.py`, SHA256
  `3139227417fb748ac0caa4404df857a6112f953aecc4297d8ffc6e7a204e8b97`:
  actual fee fixed points, initial P0 rebinding, private slot permutation and
  whole-source accounting. Reuse formulas through new files only.
- `poc/private-cashout-wallet/private_action.py`, SHA256
  `8d952270956fa9815a9c73bab4db540d81800afcce4c2b4d3e23a77e28343c8f`:
  current full-claim owner interface lacks real change and private payments.
- `poc/private-cashout-wallet/private_wallet.py`, SHA256
  `f17f58d33a8452f27c8280bfd9c7d1068bf08d35c913a0fca9d344b79c229801`:
  parameter-ready-before-backup, owner-only witness pipe, native quote/proof
  body binding, public export and seed-only native payout recognition.
- Prior public synthetic partial fixture, SHA256
  `ae4464e5a5759fced7801877c792117a8ecec301ff5c170aef4430bbbfc40c6a`:
  one real input, payout200M, fee18,999,900, real change781,000,100 and one dummy.
  This is source/reference evidence, not a new independent private recovery run.

This functional workload does not qualify financial privacy, unlinkability,
the complete fee target, production safety, or independent consensus. Prior
closed source and evidence remain unchanged; no old trial secrets are reused.
