# Fresh private-cashout service-loss trial

ADR0053 is selected; ADR0054 supersedes only its executable-launch mechanism.
One fresh unfunded identity, private source clone and private setup shape have
been created under separately archived source checks. This lane has run no
native VM, private proof, setup, funding or broadcast. Earlier Auth528 public
fixtures and the completed old-profile trial remain unchanged.

## Selected minimal route

1. Directly fund one whole Alice sender note from one ordinary funding output,
   with ordinary wallet change. GN536 establishes its coherent singleton state.
2. Alice spends it privately into Bob60M and Charlie60M claims. One real input
   plus one independently random dummy input; no admission or funding-prep action.
3. Bob cashes out his entire claim privately while Charlie's60M remains. Bob's
   two private outputs are sealed-box-shaped dummy padding.
4. Charlie privately consumes the final reserve. The payout is the only output;
   inactive notes/CMs/cipher/CM paths are zero, with no CM append.

Actual recipient slots are OS-shuffled once per identity in a fresh private
action recipe, before the first quote. Retain that choice on a failed local
attempt and leave the earlier setup-only recipe unchanged. Owners locate their
own positioned claims by recipient recognition; no public mapping is provided.

All fees are integer fixed points from actual complete bodies and amount/storage
contexts. Current source projections at rate100 are P0fee18,958,700, initial
Alice note138,958,700, Bob payout41,000,100, Charlie payout41,042,400. These are
not hardcoded authorizations. A different actual quote changes Alice's whole
note, founding value/ID and P0Auth; all following statements must be rebuilt.
Final expected counts are CM5/NF7 and no remaining positive liability.

Ordinary founding change and every fee/payout must reconcile to the single
funding output. There is no hidden founder note, payer, fee sponsor, re-entry or
privileged withdrawal. This does not improve the failed percentage fee/privacy
qualifications of the public source experiment.

## One-command fresh unfunded identity

Proposed entry point: `poc/private-cashout-trial/trial.py new NEW_PRIVATE_PATH`.
The selected ADR/source authority is checked before entropy or private writes.
The command performs only local runtime/source checks and creates an unfunded
identity in minutes; no manual qualification is part of fresh identity creation.

- Destination is new, mode0700, outside every Git worktree, without symlink
  components. All private files are exclusive0600 writes with file/parent fsync.
- Fresh OS nonce defines a new profile-specific D under the selected domain tag
  and TN10 genesis. It differs from all public AA and old-profile domains.
- Fresh Alice/Bob/Charlie seeds and a valid ordinary funding key come from OS
  randomness. The existing libsecp/cryptobox bridge handles public-key validity.
- The three exact V2 seed-only backups are written before invoices. Retain
  `kpx2-tn10-seed-backup/v1` and its five fields: schema, network, genesis, D,
  seed. No balance/tree/history/claim/native-exit fixture is added to a backup.
- Private controller metadata uses `PRIVATE_TN10_TEST_KAS_ONLY` and a new public
  program label for Auth528 private native cashouts. Public identity exposes the
  trial/D/network/genesis/funding destination/source selection, without recipient
  roles, expected operation IDs or private receipt maps.

The existing reviewed stateless filesystem, SDK identity and address conversion
helpers may be reused. Old trial creation/materialization/orchestrator APIs,
old D, Auth484, old proving keys and old profiles are never loaded or patched.

## Source and parameter matching

The fresh prover source clones only the established Auth528 relation under the
new compile-time D, retaining SHA/HMAC, integer/slack ranges, original NFs,
current CM membership, native destination binding and terminal semantics.
The new strict witness has exactly `schema: kpx3-private-action-witness/v1`,
`auth_hex528`, two inputs and two outputs. Input/output fields retain their
existing exact widths. Classification belongs to controller metadata, not this
private witness parser. Resident case labels are `spend`, `bob-full`,
`charlie-terminal`. Fixtures and any witness hashes remain outside Git and are
never public-export fields.

Materialization pins the exact base sources/Cargo.lock and records the sole D
substitution in the authoritative relation declaration. The source-matching
build is offline/locked and outside Git. No previous setup/cache is copied.
The proof owner controls the sole fresh setup, its resource allocation and the
three same-key local proofs. See [prover design](../prover/DESIGN.md).

Native policy need not be recompiled with the new D: the existing generic native
validator accepts an actual complete body. A new approved wrapper authenticates
the entire24,417-byte common program through the source-derived template, with
exactly ten D32 and one VK328 patch slots. Caller-supplied code hashes cannot
authorize other programs. The whole policy, fresh relation D/VK, native wrapper,
SDK and source software selections must match before constructing a live body.
The unchanged generic ELF is evidence infrastructure, not an old-domain factory.

The ordinary founding body is built/signed locally with the pinned SDK and the
new identity's funding key. No native/private wrapper receives a secret key.
An unsigned founding quote includes the exact eventual66-byte signature width;
its signed SDK body/ID/mass must match the quoted fields and generic native Full.

## Before-funding rehearsal must bind the future actual source

The root operator owns the ordinary merge of already available test-KAS outputs.
After the new identity supplies its funding destination, build/sign that merge
**before broadcasting it**. Give this controller only its public planned output
(transaction ID, index, integer amount, exact script, noncoinbase/covenant status) and
explicit `LOCAL_PLANNED_TN10_FUNDING_BODY` provenance. No old funding private key
or live profile is a controller input.

The complete local four-body rehearsal then references that same prospective
funding outpoint. It checks:

1. All three fresh proofs against the selected fresh VK and exact Auth528.
2. SDK canonical serialization, recomputed ID, expected outputs and mass for all
   four bodies, plus generic native Full and every input ScriptEngine.
3. Actual founding→P0→Bob→Charlie output/context links, exact fees/destinations,
   complete source/change/payout accounting and terminal reserve/liability zero.

SDK roundtrip evidence is not relabeled as an independent consensus Full API.
Local Full is supplied-context evidence until the root confirms funding/history.
The public funding merge is not an extra private action or an already accepted
source merely because its signature/ID is valid.

Only a successfully completed terminal rehearsal permits the operator prefix
plan. The root later confirms the exact planned funding output on TN10; its
outpoint/value/SPK/noncoinbase/covenant status must match before publishing the
already rehearsed founding and P0 bodies. Accepted DAA metadata cannot be known
before its future accepting block exists. Capture the real populated context
after confirmation and revalidate the fixed signed body against it, without
claiming byte-identical pre/post-acceptance metadata. Pinned
`hashing/sighash.rs:245–279` binds amount/SPK/sequence but not entry DAA;
`tx_validation_in_utxo_context.rs:138–158` uses entry DAA for relative locks.
All selected inputs must be noncoinbase and have sequenceu64MAX, including its
relative-lock-disable bit. The selected policy contains no DAA introspection;
`mass/mod.rs:378–386` uses amount/plurality cells, not DAA. Preserve actual DAA
as acceptance evidence and rerun Full with the real context; it does not require
rebinding signatures/Auth/body under these explicit preconditions.
If an actual authorization-bound source field changes, the original Auth/proof
cannot be rebound. Retain the failure and start a fresh identity/trial or an
explicitly selected new rehearsal; never silently reuse a used identity.

This avoids funding a pool before its complete terminal path works and avoids
an unnecessary fourth operator proof caused by placeholder-source substitution.
If planning the actual source ahead is unavailable, a separately selected fresh
actual-source P0 proof is mandatory; three local proofs do not authorize it.

## Prefix, shutdown and cold-client boundary

The operator publication plan contains **only founding and P0**, with exact body
and successful local validation hashes. Bob/Charlie rehearsal exits are never
operator broadcasts or cold-client inputs. The local resident prover is stopped
and its PID/unit exit is retained; it can stop before funding once all exact
prospective prefix bytes are ready. There is no hosted prover fallback.

After root publication/confirmation, each cold client is launched separately
with only:

- its own V2 seed backup and a new private destination/output directory;
- the authenticated public descriptor, public parameter manifest/PK and selected
  source-matching cold-prover/native/crypto/SDK software;
- a fresh independently acquired network capture and approved read-only public
  source/runtime libraries.

No operator profile, rehearsal fixture/archive/tree, seed belonging to another
owner, existing local exit proof/body, or resident operator PK process is mounted.
Record the mount/process boundary. A public PK copy is allowed and authenticated;
it contains no owner's private witness. The cold wallet verifies selected software
and parameter authority before deriving/reading a private witness, reconstructs
its own distinct native payout key with the wallet's selected deterministic
HMAC recipe from seed/D/founding point/CM position/retry, generates fresh dummy
randomness, proves locally and constructs a new exact body. The seed-only backup
therefore also recovers its eventual native payout key.

The first owner must discover an open two-claim head and build its own full exit.
The next owner must independently fetch the accepted successor and build the
terminal exit. No predeclared role order or expected payment map is an input to
discovery; the trial runner may schedule Bob then Charlie outside the clients.
Terminal confirmation and actual native payout queries are root's final success
gate. Emergency REVEAL remains explicit user consent, not an automatic fallback.
See [network contract](../network/CONTRACT-PROPOSED.md).

## Required checks and boundaries

Source/fixture review should challenge missing/unfrozen ADR before entropy,
inside-Git/symlink/used output paths, malformed backup/amounts, wrong new profile
or source D/VK/program, unfunded versus planned/accepted source confusion,
stale/rebound Auth, dummy/NF reuse, incorrect terminal fields, source accounting,
publication of a rehearsal exit, missing operator stop and cold mount leakage.
Tests use public synthetic fixtures under a distinct DO-NOT-FUND D, never this
future trial's private seed/fixture artifacts. No public-export command may copy
a controller profile, witness hash, seed, local proof request or PK process log.

The selected validating RPC remains the accepted-history/current-view authority;
local source/SDK/native checks do not independently establish PoW/GHOSTDAG or
durable public data. A public development setup retains its setup-trust and
parameter-availability assumptions. Successful single-owner cold recovery and
confirmed testnet payouts would not establish financial privacy, a p95 target,
all-source data availability, an audit or production/mainnet safety.
