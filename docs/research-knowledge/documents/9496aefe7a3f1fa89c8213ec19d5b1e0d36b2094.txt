# Wallet-local payment privacy assessment

> **Correction:** the first `analyze.py` decoded genuine evidence but hard-coded
> candidate counts and the known assignment. Those counts were a case
> reconstruction, not a blinded measurement. See `CORRECTION.md` and the fresh
> sealed experiment in `RESULT.md`.

**Date:** 2026-11-01
**Frozen selection:** `SELECTION.md` SHA-256
`52c2c7d0be6c6155d8d42869df2a5ce21e426687f939e4f79f188221f8c51bd0`
**Verdict:** **needs repair**. Wallet-local proving remains a plausible minimum
cryptographic architecture, but this retained 10/4/6 lifecycle fails the frozen
unlinkability target for both observers and lacks actual independent-recovery
evidence. In this exact sparse, immediate transparent-entry/direct-exit workload,
wallet software alone cannot meet the target; a larger shared shielded history and
less distinctive exits are required. No observed leak requires permanent or joint
MPC.

## Evidence boundary

The selected public corpus contains 134 tracked evidence files: 133 entries named
by `poc/tn10-live/evidence/manifest.json`, plus the manifest. Every named file
matched its recorded SHA-256. The credit, accepted transfer, rejected transfer and
exit payload hex in the wallet reports also matched the corresponding native
publish-request bytes.

This assessment keeps four evidence classes separate:

- **Actual selected bytes and source:** public payloads, commitments, nullifiers,
  ciphertexts, amounts, timestamps, role-labelled paths, scenario-specific wallet
  source, public results and operator-custody declarations.
- **Simulated auxiliary overlay:** Alice owns the transparent deposit, Bob owns the
  payout address, the four-person contact graph, and—only for O-service—Alice's
  authenticated submission endpoint. These are not observed network facts.
- **Cryptographic ideal assumptions:** commitment hiding, ciphertext/key privacy,
  nullifier unlinkability, zero knowledge and proof soundness. None was re-proved
  or tested here. An ideal unlinkable nullifier does not enlarge a singleton set of
  plausible historical notes.
- **Unavailable evidence:** plaintext invoices; packet or endpoint logs; private
  note openings, spending keys and wallet backups; undeclared operator files;
  global-network observations; and an independent user's off-operator recovery and
  exit. Missing evidence is not scored as a pass.

## The primary-source Zcash-like target

“Zcash-like” here means the following bounded target, not protocol equivalence:

1. A shielded note carries value and a shielded address. The chain exposes its
   commitment; spending exposes a nullifier that should be infeasible to correlate
   with the commitment without the relevant key. Output note secrets are encrypted
   to a key-private recipient key.
2. For a fully shielded spend, the historical-note candidate set contains all
   earlier notes the observer neither controls nor knows to be spent. The Zcash
   specification explicitly warns that clear transaction structure and timing can
   still support linkage inference. Thus a one-note history is not rescued by sound
   cryptography.
3. Ordinary cross-address Orchard construction can add dummy sides and independently
   shuffles spends and outputs before pairing them into Actions. A public Action
   position therefore is not intended to mean “this input paid this output.”
4. A wallet scans authenticated public chain data with its viewing material and
   supplies spending authority for transaction construction. A remote permanent
   prover is not inherent to the note privacy model.
5. This target does **not** promise network anonymity or hide transfers between
   transparent and shielded value pools; the Zcash specification states that such
   pool-crossing amounts are revealed. The frozen independent service-loss recovery
   criterion is an additional requirement of this study.

Primary sources checked at current upstream heads were the Zcash protocol
specification (`zcash/zips` `ff594de6e95bb9e9e7d2ace09510281531c30447`),
Orchard (`616a669df8c9a59c33d47064d3ce04b25d026b2e`) and librustzcash
(`a551fac8a233f54799ca1920ef78ef098cfda929`):

- [notes, nullifiers, encrypted recipients, traceability sets and metadata caveat](https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L3219-L3334)
- [nullifier unlinkability requirement](https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L7755-L7773)
- [Orchard dummy notes and action-order randomization](https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L6720-L6738)
- [current Orchard cross-address spend/output shuffling](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L1479-L1528)
- [wallet scanning, witnesses and caller-provided spending authority](https://github.com/zcash/librustzcash/blob/a551fac8a233f54799ca1920ef78ef098cfda929/zcash_client_backend/src/data_api.rs#L15-L31)

## Actual lifecycle facts

The selected decoder/source is scenario-specific, not a generic black box.
`poc/private-native-tn10/src/wallet.rs` identifies the credit-transfer role as
Alice and the exit role as Bob, creates Bob's 400,000,000-sompi note first and
Alice's 600,000,000-sompi change second, then has Bob discover and exit the
400,000,000-sompi note. Public README/ADR text and evidence paths repeat those
roles and the 10/4/6 story.

The public operation sequence is:

| Event | Public fact |
|---|---|
| credit | deposit `1,000,000,000`; sole active output `cm=6c2fc8b4…ed38` |
| rejected transfer | invalid proof, about 9 seconds before the accepted transfer |
| accepted transfer | one nullifier `43eb39d1…71c5`; outputs `cm0=17391dd4…4e9a`, `cm1=ce61dd9f…5171`; two 185-byte ciphertexts |
| direct exit | `exit_value=400,000,000`; nullifier `adf06cc9…ef25`; no new private output |
| native payout | `450,000,000`: 400,000,000 principal plus 50,000,000 rent refund; 600,000,000 private liability remains |

The exit was published about 9.9 seconds after transfer settlement. The retained
record explicitly says the operator controlled logical Bob's wallet and native
recipient key. It does not show a separate user recovering from user-held secrets
and authenticated public data.

## Candidate assignments

The fixed observer views leave the same single complete assignment; O-service has
additional direct origin/custody evidence rather than additional ambiguity.

| Frozen query | O-public candidates | O-service candidates | Candidate-removing facts |
|---|---:|---:|---|
| accepted input owner | 1: Alice | 1: Alice | simulated deposit binding; sole prior active note; Alice-labelled transfer source/evidence; authenticated Alice endpoint for O-service |
| payment recipient | 1: Bob | 1: Bob | Bob-labelled source/evidence and direct exit; simulated Bob payout binding; actual operator held Bob role |
| payment principal | 1: 400,000,000 sompi | 1 | scenario source; public exit principal; 1,000,000,000 in minus 600,000,000 remaining |
| historical spent note | 1: credit `6c2fc8b4…ed38` | 1 | it is the only eligible nonzero historical note before the transfer |
| output partition | 1: `cm0` Bob payment, `cm1` Alice change | 1 | selected wallet source fixes construction and delivery order |
| later exit | 1: Bob's `adf06cc9…ef25` exit/payout | 1 | source role, amount, order, timing and simulated payout binding |

Consequently there is exactly one complete tuple:

```text
(Alice, Bob, 400,000,000 sompi, credit cm 6c2fc8b4…ed38,
 cm0=payment, cm1=change, Bob direct exit/payout)
```

The frozen requirements of two candidates per hidden item, two complete tuples and
two output partitions all fail for both observers.

## Frozen attacks and smallest fixes

| Attack | Result | Successful leak | Smallest fix class |
|---|---|---|---|
| `A-plaintext` | **success** | Selected source, filenames and public narrative disclose Alice/Bob, 400/600 and output semantics. No public spend key or note opening was found. | **1 — wallet policy/software:** generic runtime inputs, neutral artifacts, private recipient input, no publication of semantic truth. |
| `A-singleton` | **success** | The sole eligible historical note makes the spent note and sender unique despite ideal nullifier unlinkability. | **3 — public state layout:** a genuinely larger shared shielded history/accepted anchor set. Dummy inputs cannot create other users' historical ownership. |
| `A-balance-exit` | **success** | 1,000,000,000 deposit, 400,000,000 direct exit and 600,000,000 remaining value reveal recipient and exact principal. | **3 — public state layout:** concurrent pooled activity plus delayed/batched or standardized exits. MPC cannot erase a distinctive public native payout. |
| `A-order-time` | **success (corroborating)** | Rejected-to-accepted and settlement-to-exit timing reinforce the already unique path. No packet timing was invented. | **1 — wallet policy/software** for randomized scheduling; meaningful sparse-use protection may additionally require class 3 batching. |
| `A-service-origin` | **success** | The simulated authenticated endpoint identifies Alice; the actual operator also controlled logical Bob and the native recipient key. | **2 — anonymous/replaceable processing** for origin separation; **1** for a genuinely user-held Bob wallet/custody boundary. |
| `A-grouping` | **success for partition** | One-nullifier/two-output grouping plus deterministic source slot order reveals payment versus change. Grouping alone does not identify a person. | **1 — wallet software:** independently randomize payment/change output order before proof construction. |

No successful attack needs class 4 joint private computation. A fixed MPC service
would still see or leave untouched the published role labels, singleton history,
public exit arithmetic, timing, authenticated endpoint and operator custody.

## Minimal knowledge split after repair

| Party | Must learn | Must not need |
|---|---|---|
| user wallet | own note plaintexts/keys, intended recipient and payment/change partition | other users' secrets |
| replaceable processor/prover | public anchor, nullifier, commitments, ciphertexts, proof and public exit fields | note plaintexts, spending keys, Merkle witness or payment/change labels |
| public chain observer | public operation fields and transparent entry/exit facts | sender, recipient, hidden amount or historical-note mapping |
| submission relay | enough routing data to forward a fixed-shape public operation | a stable authenticated wallet identity |

A shared accepted note set and, for exits, shared batching are public-state
coordination requirements. They do not require participants to jointly reveal or
compute over private witnesses. Joint computation becomes justified only if a
later bounded test identifies an indispensable constructor that otherwise learns
a private participant-to-output map.

## Exact recovery gap

The repository has a separate `user-recovery` executable that can rebuild and
root-check public history, scan with a user backup, and prepare a public-only exit.
Its retained rehearsal is host-local and synthetic; it is not this trial's Bob
recovering under independent administration. The smallest missing live evidence
is therefore one off-operator run in which Bob holds the original backup and
native key, independently authenticates the accepted checkpoint/history and the
pinned public proving parameters, prepares the exit locally, submits only the
public operation through replacement infrastructure after the original services
are unavailable, and observes the native test-KAS payout. No such run was
performed here.

## Decision

The route **fails the selected overall target** for O-public and O-service and fails
independent recovery/exit for lack of actual evidence. It nevertheless merits
further wallet-local work because the leaks divide cleanly into wallet publication,
replaceable transport/custody and public anonymity-set/exit-layout problems; none
shows that a processor must receive private witnesses.

The smallest decisive repair sequence is:

1. make wallet construction generic, randomize output slots, and publish only
   role-neutral artifacts;
2. put recipient secrets under a genuinely independent user and use replaceable,
   origin-hiding submission;
3. freeze and test a finite workload with multiple prior notes and delayed/batched
   exits under these same observers;
4. consider joint computation only if that experiment exposes a named private map
   that an indispensable constructor must learn.

Until step 3 succeeds, wallet-local cannot meet the named end-to-end payment
unlinkability requirement for sparse immediate transparent entry and direct exit.

## Checks performed

- Offline corpus inspection only; no build, proof, MPC, protocol/network experiment,
  Testnet action, funding or broadcast. Network access was limited to retrieving
  current public Zcash source in a temporary directory.
- Manifest SHA-256 verification for all 133 listed evidence files.
- Byte equality checks between four wallet payloads and their native publish
  requests.
- Current Zcash primary sources inspected from read-only temporary shallow clones;
  no upstream code was executed.
- The paused patch content was not read, changed or executed; the checkout received
  only the permitted final read-only status check.
