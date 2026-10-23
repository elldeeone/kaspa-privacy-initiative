# Privacy and receiver-driven recovery execution

Baseline `63f494053b743ac9bfbd2d1842f69e0f806ef8e3` on
`research/shielded-kas-feasibility`, continuation worktree. Preserve all earlier
closed packets and funded identities. Research/testnet only, native KAS, no paid
infrastructure, real funds, mainnet or privileged exit.

## Product gates

1. Measure the actual revealing-exit channel using chain bytes alone. Keep the
   known six-body diagnostic separate from 32-role privacy qualification.
2. Recover from one backup, an authenticated minimal public instance descriptor
   and newly fetched accepted network records. Derive history, amounts and
   current witnesses locally without operator snapshots or precomputed exits.
3. Build the ADR-0050 unified proof-private cashout, including private change,
   fresh destinations, terminal capacity and exact native outputs/fees. New
   public development domain/key only; no funded instance migration.
4. After source/fixture review, execute genuine proof/native controls and complete
   local paths. Any live service-loss/private-exit test uses a fresh private TN10
   identity and reaches confirmed payout; no used identity is rebroadcast.

## Parallel ownership and resources

Design/source comparison, C-only observer, network fetch, public replay, seed-only
wallet, private proof, native policy/helper and adversarial review run separately.
A second reviewer covers proof/native critical paths while the first covers
fetch/replay/ownership/observer separation. Independent builds may use up to
14 logical CPUs collectively: native8, proof4, lightweight replay/fetch2. Keep
combined live memory below available24GiB with headroom; serialize heavy setups/
proving after measuring circuit size. No GPU backend is added without a useful
supported path. Record source, input, CPU/memory/swap and cleanup per actual run.

## Unchanged limits

The actual current canary exposes both historical output-note values and payout
links. The prior21.0977% amount result still fails20%. A private cashout hides
note openings but exposes payouts/fees and can retain arithmetic/directory
inference. Three direct verifications alone exceed the2% lifecycle target for
two10-KAS recipients. Do not pool private witnesses, hide a payer or retune gates.
Multiple RPCs are availability/corroboration, not independent consensus. Pruned
or missing ciphertexts cannot be recovered from roots. Recognized claims rely
on correct delivery; malformed accepted delivery never erases backing.

Actual genesis framing is536B: GN01,D,Note168,CM32,cipher264,cipher hash. The older
finite-adapter narrative claiming omitted D is a preserved documentation error;
the accepted bodies and native source were correct. New replay uses those bytes.
