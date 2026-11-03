# Existing API and real-curve construction falsifier

Selected only by ADR0061; source baseline b7b41ab0. This is not a KAS wallet,
new cryptographic primitive, MPC implementation, privacy score or transaction
acceptance test. All fixture values, signing scalars and RNG seeds are public
unsafe test constants. No backup, real key, witness, PK or financial artifact is
an input. No setup, proof generation, zkVM, GPU or broadcast is required.

## Frozen fixture before execution

Use Sapling commit88a7946b4a3066787776e11f0a502654167e022d, its actual Jubjub
value commitments, PCZT parser/prover/finalizer/extractor and RedJubjub binding
verification. Keep the registry dependency lock and source identity.

Three synthetic owners each have an input value1,000,000,000 and fee10,000,000
integer sompi. Their two outputs are600,000,000 and390,000,000. The six public
output commitments use values[600M,390M,600M,390M,600M,390M]. Public input
blindings are[10139,30727,91193]; public output blindings are
[505963,122949823,2147483647,32416190071,982451653,961748941]. Owner pairs are
[0,1], [2,3], [4,5]. Fixed permutation is[4,1,5,2,0,3].

The amount-only fixture oracle has9 eligible pairs among all15 pairs. That
count is calibration, never an extra input to the subset attacker. The attack
routine receives only an owner's input commitment point, output commitment
points/opaque IDs, fee and optional beta*R, and enumerates all15 pairs using
exact group equality. No opening, value vector or true owner pair is passed.

Expected controls, retained even if they fail:

1. Each owner's exposed beta*R selects its one true pair; the fixed permutation
   changes indices while preserving the matched opaque IDs.
2. beta+1 and fee+1 produce no matching pair. Missing beta returns missing
   attack input, not anonymity success or an alternate-world proof.
3. Canonical proof-bearing redacted PCZT records parse. With mock192-byte
   Groth16 fields and private fields absent, the actual high-level prover
   returns MissingProofGenerationKey before any panic-on-use proof backend or
   RNG. The actual IO finalizer returns MissingValueCommitTrapdoor before RNG.
4. With actual SpendAuth signatures on one fixed public test digest and an
   externally supplied aggregate blinding key, redacted records extract/sign.
   The actual commitment-derived Binding verification passes. Wrong aggregate
   key, wrong digest and value_balance(total_fee)+1 reject at the binding check.
   Wrong digest also rejects the extractor's SpendAuth check. Noncanonical
   external key[0xff;32] rejects with the typed parser error.

The positive boundary is parser/extractor/signature and Binding algebra only.
All mock proof bytes remain explicitly non-genuine; a full Sapling verifier
would reject them. No full transaction, KAS relation, hidden-membership world,
ValueShuffle execution or privacy qualification follows. No masked-sum toy is
included as a substitute for the actual protocol. The current strong observer,
amount prior, singleton failure and all heldout results remain unchanged.

Independent source ACK precedes execution. Build/run in a task-local2CPU/4GiB
slot with swap0; retain failures and fix operational causes without changing
this fixture or expected controls. The host compiler/OS and selected upstream
libraries remain trusted dependencies.
