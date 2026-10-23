# Genuine competing-path native controls

Prospective follow-up to the retained63-case run. No old result is replaced.
Lifecycle owns the two new genuine proofs under the same new setup; this lane
only imports their closed artifacts, prepares exact native cases and executes
one separately reviewed/frozen run. No setup/proving/broadcast here.

1. A: current actual main private output contains Bob's unspent original1B note.
   A new genuinely verified private proof consumes that note with one dummy
   input, inserting the ORIGINAL positioned Bob NF and one constrained dummy NF,
   and appending two new positive CMs. Expected official Full and engine ACCEPT.
2. A follow-up: preserve the original Bob note/CM/position/NF and native key,
   provide CURRENT n6 CM membership and authenticated occupied spent-NF equality
   after A, bind the actual A native output ID/value/SPK, and sign the revealing
   exit correctly. Expected engine `VerifyError` at strict NF order and Full
   REJECT. No stale old root or bad signature can satisfy this expectation.
3. B: current actual main Bob reveal output has already consumed that original
   note, while current CM membership remains intact. A second genuinely verified
   private R1CS proof binds this actual current reserve/outpoint/CM/NF state,
   original positioned Bob NF and one dummy input. Its PUBLIC NF witness
   deliberately authenticates the CURRENT occupied equality. Expected native
   engine `VerifyError` before Groth16, Full REJECT. The private R1CS proof is
   genuinely verified for this exact Auth; native current spentness is the
   load-bearing check that a private ownership/conservation proof does not replace.

`prepare_forks.py` uses a retained exact assembler snapshot with only its REPO
location reset after import. Both proof report/fixture/VK identities and actual
native preceding output links are checked during preparation. Freeze exact
source, binary, input/proof reports, both prior actual body contexts and all three
signed native cases before root+independent release. Run once with the same
typed runner, retain any mismatch. Fork contexts are synthetic alternatives to
the completed primary sequence, not extra accepted payments or its fee denominator.
