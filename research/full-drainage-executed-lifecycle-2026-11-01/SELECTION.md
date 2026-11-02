# Frozen executed full-drainage lifecycle

**Freeze date:** 2026-11-01  
**Experiment:** `full-drainage-executed-lifecycle-v1`  
**Source baseline:** `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1` plus the
existing uncommitted depth-four wallet experiment  
**Asset:** integer sompi; test KAS only if the native gate passes

This selection is frozen before creating wallets, commitments, nullifiers,
ciphertexts, proofs, execution aliases, native keys or transaction IDs. Private
truth and wallet material remain outside Git.

## Question

Do two materially different gross payment histories produce the same public fact
shape and remain payment-fact ambiguous under explicit cryptographic-opacity and
auxiliary-information assumptions after every owner independently exits every
claim? Can the same wallet relation then complete exact native test-KAS settlement
and service-loss recovery without MPC, locks, delays, retained balances or
privileged withdrawal authority?

## Alternative worlds

Execute both worlds independently with fresh wallet keys, proof randomness,
deposits and payout destinations. Randomly assign private run aliases after this
freeze. Never compare literal commitments or claim that binding commitments in
one run have alternate openings.

All values below are sompi:

```text
Initial deposits: A 100,000,000; B 100,000,000

World H1:
  A -> M 40,000,000
  B -> M 20,000,000
  M -> S 10,000,000

World H2:
  A -> M 30,000,000
  A -> S 10,000,000
  B -> M 20,000,000

Terminal owner exits in both worlds:
  A 60,000,000
  B 80,000,000
  M 30,000,000 and 20,000,000
  S 10,000,000
```

Each world must contain exactly two authenticated deposits, two private credits,
three genuine one-input/two-output wallet transfers and five owner-authorized
whole-note exits. Every exit must be paid; final reserve, private liability,
pending deposit and unpaid-exit principal must all be zero.

## Process and recovery boundary

- Use one secret store per A/B/M/S wallet with mode `0600` under a private
  `0700` run directory.
- Wallet key creation, note scanning, transfer proving and exit proving execute
  in separate wallet subprocesses. The orchestration process must not serialize
  wallet secrets into public requests or evidence.
- A public ledger/relay process may receive only public operations and neutral
  request metadata. Same-host process isolation is not independent custody,
  independent hardware or independent human operation.
- After the three payments, stop the default relay/operator process. Restore
  each owner from its backup and authenticated public records, reconstruct
  current spendable notes and create exits through a replacement public process.
- M must independently discover and exit both notes. Concurrently prepared exits
  may require refresh/reproof after the first accepted state transition; no check
  may be weakened.

## Public transcript

Retain, per world:

- exact statement bytes and operation kind/order;
- anchors, verifier/domain, commitments, nullifiers, ciphertext lengths/hashes,
  proof lengths and wire lengths/hashes;
- authenticated deposit identifiers, amounts and owner fields actually exposed
  by the current PoC/native boundary;
- exit amounts, destinations, fees and confirmed payout identifiers;
- state hashes, reserve/private/pending/unpaid accounting after every step;
- monotonic request/acceptance timing and all relay-visible request metadata;
- wallet-process duration and resource totals, but no secrets, note plaintexts,
  Merkle paths or private truth.

Literal public byte strings are expected to differ across worlds because keys,
note randomness, ciphertext randomness and proofs are fresh. The comparison is
of transcript distributions and recoverable payment facts under the declared
opacity assumptions, not byte equality.

## Observer views

1. **Protocol known-owner:** full public transcript plus deposit/exit owner
   mappings. Commitments, ciphertexts, proofs and nullifiers are opaque except
   for public equality, validity, spentness, arity and order.
2. **Protocol unmapped-owner:** same transcript without exit-owner mappings.
3. **Service known-owner:** protocol known-owner plus every field actually logged
   by the neutral relay, including request size/order/time and relay token. No
   wallet label, IPC peer identity or hidden orchestration truth may be silently
   supplied unless the executed service actually observes it.
4. **Strong external/workload:** known-owner evidence plus the fact that S was
   paid by M. Retain this adverse view even if it uniquely recovers H1.
5. **Sparse failure:** A deposits 100,000,000, one private transfer occurs, and
   known-owner exits are A 60,000,000 and B 40,000,000. This must remain uniquely
   `A -> B 40,000,000`.

The possible contact graph for the ordinary candidate is exactly `A->M`,
`B->M`, `M->S`, `A->S`. Facts such as a hidden run alias, exact execution world,
wallet store path, note plaintext, output assignment or orchestration command are
private truth and are not observer inputs.

## Scoring

For each single-world public projection, enumerate gross payment fact multisets
compatible with its public fact shape, known owner mappings, declared contact
graph and cryptographic-opacity assumptions. Report candidate relationships and
amounts, not hidden labels, commitment assignments, output order or transaction
position.

The two chosen worlds demonstrate possibility only if both are members of the
same declared public-fact distribution. Do not claim equal likelihood,
computational indistinguishability, ordinary-user anonymity or alternate
openings. Report timing/size differences directly; do not discard them to make a
privacy result pass.

## Local gates

1. Both worlds use genuine depth-four wallet proofs under one newly generated,
   recorded verifier identity.
2. Every wallet independently discovers only its notes from public records and
   can re-spend/exit them from its backup.
3. Wrong domain/root, replay, unauthorized discovery, duplicate exit and
   diverted/underpaid payout controls reject atomically.
4. The replacement recovery process pays all five exits and reaches exact zero
   principal liability in each world.
5. The sparse control stays unique and the strong view is not weakened.

## Native gate

Native execution uses a fresh TN10 trial identity and only free test KAS. It may
start only after a complete unfunded local rehearsal binds:

- the exact current depth-four wallet domain and verifier;
- actual accepted state and native deposit descriptors;
- every exit's amount/destination and corresponding native payout;
- all state transitions and nullifiers without stale/old-receipt substitution;
- principal, fees, rent and refunds separately; and
- a fresh outer receipt accepted by the real native verification path.

The existing depth-two receipt/VK/domain is a historical control and cannot prove
this flow. A local fixture or unsecured payout cannot substitute for native
verification. For each failed funded attempt, preserve evidence and use a fresh
unfunded identity; never rebroadcast within a used identity.

## Stop rules

- Do not implement private merge; current one-input/two-output transfers are the
  candidate under test.
- Do not add MPC, delay, lock, mandatory batch, privileged withdrawal signature,
  permanent reserve, new token, dummy traffic or capacity beyond the existing
  depth-four profile.
- Preserve failures without redrawing worlds, changing observers or weakening
  verification.
- If exact depth-four native proving/settlement cannot be completed with existing
  local resources and code, finish the local lifecycle and concrete preparation,
  identify the exact boundary and measured resource/cost requirement, then stop.
- No mainnet, real funds, paid compute, public post, commit or push.
