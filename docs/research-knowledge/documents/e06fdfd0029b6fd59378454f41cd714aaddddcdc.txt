# H7 adversarial second pass

2026-10-19. Implementing-agent review of the new restoration code and transport;
not an independent cryptographic audit. Recheck the recorded runtime results
before treating the experiment as complete.

| Question | Boundary checked | Evidence / remaining limit |
| --- | --- | --- |
| Can the recovery helper mint value or release incorrect backing? | It calls the unchanged compact authorization/settlement relation, checks the payout against the backup-derived key and validates the native transaction. Reconstruct and validate every prior transition. | Six-transaction integer-sompi ledger, independent tree reconstruction, full drain and existing native rejection controls. These are tested instances, not a proof of soundness. |
| Can a spent claim reappear? | Reconstruct positioned nullifiers from the complete authenticated history; remove spent notes before authorization. Native settlement still enforces current spentness. | Spent-wallet recovery rejects; the inherited genuine-proof replay controls also reject. Sequential recovery does not test sustained contention. |
| Can a mirror substitute another pool or parameters? | The private backup pins exact descriptor bytes. The descriptor pins network/genesis, domain, funding identity and PK/VK hashes. Recompute the initial covenant and validate funding. | Wrong pin, network, genesis, domain, funding context, malformed amount and corrupt parameter controls. Backup integrity and the original single-party setup remain assumptions. |
| Can valid old files masquerade as current state? | Native replay alone is insufficient. Live transport follows the separately synchronized node's accepted lineage and checks the unspent reserve before proving/submitting. Compare exact accepted body/full hash after payout. | Missing/reordered/forged endpoints reject; a valid short archive extends using accepted public history. A dishonest node or arbitrary reorg rollback is not solved by this experiment. |
| Does the controller provide secret recovery information? | One pre-payment backup per sandbox, no original home/manifest/address book, no future note list and no prepared proof. Copy only a fixed public archive allowlist. | Recipient backup has no initial/incoming note; original Alice prover stops before restore. Host launcher/control plane is trusted to enforce the recorded mounts; no hostile-host security claim. |
| Can another party redirect a payout? | Derive the destination inside the recovered wallet from its native key; bind exact destination/value/fee in the private authorization; check native output matches. | No destination argument, operator signature or admin exit branch was added. Compromising the private backup still compromises the wallet. |
| What happens when services disappear? | Try another authenticated public copy; if none supplies the required inputs, stop before creating/submitting an exit. | Original source is stopped, independent retained copy used. The all-source-unavailable control safely halts; it is not recovery success. Neither history nor proving parameters can be reconstructed from roots alone. |
| What leaks? | Public descriptor omits receiver list; note scanning and proofs run locally. Publication uses a strict evidence allowlist and checks known backup secrets. | Addresses, public payouts/fees, timing, anchors and RPC connections remain observable. Evidence intentionally labels synthetic wallets for scoring; it is not a chain-observer dataset. |

Two operational problems were found before live funding: the remote host rejects
ordinary user namespaces, and a nested root namespace cannot read ubuntu-owned
private directories. The remote launcher now creates mount/PID isolation with
`sudo`, then uses `setpriv` to run the wallet as ubuntu with no effective/permitted
capabilities and `no_new_privs`. It preserves private directory permissions.
The sandbox preflight reached a separate public TN10 RPC. No host-wide policy,
node service or cryptographic check was changed. A fresh offline run covers the
finalized files before the complete funded rehearsal.

The initial-deposit control also rejects the stronger keys-only recovery premise:
the depositor must retain the initial note opening until it is spent. State this
backup requirement rather than mounting the original wallet directory as a fix.

The first funded rehearsal exposed a transport failure: synchronous cold
parameter decoding/proving occupied the Node thread long enough for its open
WebSocket to disconnect. Bob's proof was created, but no submission intent was
written and the reserve remained unspent. The fix explicitly disconnects before
local proof work, reconnects afterward, and still checks the actual current
reserve before submitting. It does not retry or weaken native validation. A
fresh offline recovery of all three saved-fixture backups exercises the revised
client and restoration constructor; a fresh cleanup identity drains the
interrupted live pool before a new complete rehearsal and measured trial.

Cleanup adopts only the three accepted pre-exit transactions and pre-payment
backups. It requires their reserve still to be unspent, generates new wallet
authorizations and never calls the earlier funding/payment broadcasters. A
cleanup result cannot satisfy the measured trial's complete-rehearsal gate.

There are no changes to the compact circuit, covenant, note/nullifier derivation,
fee policy or setup. The original experiment module only exposes existing helper
functions to the new recovery module. Public-data availability, trusted chain
view, cold startup, exact-fee authorization and finite capacity remain explicit
limits. No new privileged recovery authority was introduced.
