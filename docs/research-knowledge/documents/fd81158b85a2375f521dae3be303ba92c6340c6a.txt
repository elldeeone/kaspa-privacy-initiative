# Separate exact-zero-change payment control

Root-selected addition to the main six-body workload: one alternate local
private-payment proof/native check. This is an unbroadcast fork control, not an
extra live action or a fee charged to the main chain trace. Total planned
genuine proofs are six local plus four new owner-local live proofs under the
same newly selected setup/VK.

Fork the exact local snapshot immediately after the partial cashout. Its only
real liability is Bob's change `V = R = 600,000,000 - f1`; both Bob recovery
instances use the original unchanged backup.

1. Build a diagnostic public P0 sizing statement with the exact current
   outpoint/state/reserve, real/dummy NFs in their chosen order, valid sequential
   public NF updates, and coherent opaque output CMs/ciphers/append paths.
   Use zero128 proof. No private proof witness or claimed owned output is made
   for this diagnostic. It must reach the declared G16 seam and is not acceptance.
2. Learn the official public fee fixed point `fZ`; choose this branch's requested
   recipient amount `T = V - fZ`. Require `T >= 60,000,000` and native reserve
   `R' = T`. The branch amount is selected before its actual proof.
3. Construct the real Charlie receipt for exactly `T` and a same-format sealed
   dummy, privately shuffled once. Self-change is exactly zero. Rebuild actual
   Note/CM/cipher/append roots/state/Auth and quote that exact actual material.
4. Only after the actual quote is legal and final, construct/serialize the
   private witness, generate the distinct genuine proof, substitute proof128
   only, and require native Full/all input engines with exact body/context/fee.

If the actual-material quote changes the fee so `V - T - f != 0`, retain the
failed sizing/actual comparison and refuse or re-size before any proof. Never
reduce the requested amount silently, burn subfloor change, or rebuild after
proof. The diagnostic opaque outputs are not reused as real private receipts.

The alternate ends CM7/NF7, with reserve `V-fZ`, no remaining Bob private
liability and one Charlie claim. Its roots, body, proof and fee remain separate
from the main payment of 300M plus Bob's positive second change. Do not append
both conflicting branches to the main ledger or call the alternate a terminal
drain. The main route still ends CM9/NF11/R0 with three actual native payouts.

The owner API's general zero-change path needs the same public-sizing then
actual-material quote discipline; fee1 cannot be used to demand subfloor
positive change before sizing. This control establishes only the selected
exact-zero case. It does not establish fee-target or financial privacy claims.
