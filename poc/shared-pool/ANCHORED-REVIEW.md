# Reusable authorization: adversarial second pass

2026-10-19. This is an implementation self-review, not an independent security
audit or proof of cryptographic correctness. Scope: `src/anchored`, the separate
`kpi-anchored` binary and `anchored*.mjs`; version-3 settlement is unchanged.

- **Inflation/backing:** UInt64/byte witnesses plus bounded slacks restrict all
  real notes, fee and payout to integer sompi. Private input = two outputs + fee
  for transfer, or payout + fee for exit. Bootstrap ties the initial note to the
  actual reserve. Native arithmetic separately enforces current reserve = next
  reserve + payout + exact authorized fee. Neither assertion substitutes for the
  other. Native maximum supply keeps legitimate arithmetic in signed-i64 range;
  private sums are much smaller than the BN254 scalar modulus. No modular amount
  equality permits a 64-bit sum overflow.
- **Double spending:** the proof derives an economic HMAC nullifier independent
  of anchor/outpoint. Native script checks it against EVERY current slot before
  appending. Replaying after Bob's accepted exit is tested with enough reserve
  to fund the attempted second payout, bypassing friendly builder filters.
- **Historical membership/state:** the proof binds a count/hash and private
  membership in that snapshot. Native script reconstructs the snapshot from an
  actual current commitment prefix. The exact successor retains every active
  old commitment/nullifier, appends only authorized items, and zero pads. It
  rejects changed/dropped/reordered state even when the attacker supplies a
  matching new output script hash. No current-state digest supplied by a prover
  is trusted. False/future anchors and stale SETTLEMENTS still fail.
  The bounded rule permits any authenticated prefix, including a count that was
  not itself a complete historical pool state. The honest wallet uses its full
  accepted commitment count. This difference from a block-boundary root registry
  is explicit; no validity claim depends on that omitted registry.
- **Unauthorized release/upgrade:** full native output shape, payout amount/SPK,
  fees, domain and ciphertext digest are authenticated. The native script copies
  its actual immutable suffix/VK into the next reserve hash. Direct changes to
  the successor domain or VK reject. No admin key or new signature bypass exists.
- **Terminal/capacity:** a transfer adds two commitments and one nullifier; an
  exit adds one nullifier. Only equality of new counts removes the reserve.
  Proof conservation plus bootstrap backing makes that exhaustion meaningful.
  Exits need no new commitment slots. The maximum reachable odd count is 23 in
  this transfer-only variant; an explicit-context native terminal fixture tests
  that boundary. This fixture does not claim an actual 23-note chain run.
- **Privacy:** public anchor count/hash reveals an earlier membership horizon,
  potentially reducing candidate notes. Amount/timing/boundary inference is not
  solved. Sealed-box delivery is retained from the earlier experiment; ciphertext
  correctness is checked by receiving wallets, not proved by this relation.
  They must reject plaintext/commitment/owner/floor mismatches. RPC/network
  exposure and common synthetic funding remain distinct from chain-only data.
- **Dependencies and trust:** public parameters, accepted history and a correct
  full-node view remain necessary. Missing or unverifiable state stops the
  wallet. Setup is experimental single-party Groth16. No guarantee covers
  arbitrary reorgs, hostile RPC consensus views, starvation or future fee rises.
  Funds remain a single serialized reserve despite cheaper transaction refresh.
- **Independence evidence:** live Bob proving stops before Alice's update. The
  rebuilder receives only pre-update public history, the public authorization,
  software/VK and an earlier chain cursor. It discovers Alice's spend by reserve
  lineage via RPC. It has no wallet or proving key mounted. A restarted Bob
  prover, after target payout confirmation, handles only the newly received
  separate claim for cleanup. This restart is not a reproof of the target exit.

Offline relation/native controls and exact SDK encoding must pass before
funding. A completed funded rehearsal precedes the measured repetition. Tests
are evidence about these cases, not an exhaustive security claim.
