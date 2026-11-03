# Source03 review corrections

Source01/02 exact preimages are retained. These changes do not change the
520-byte tuple, scalar field, stock shuffle program or financial relation.

1. The public session accepts only the exact ADR0063 D32 beginning32b4.
2. Owner input transport is exactly35 fields of76 zero-padded ASCII digits
   plus newline, total2,695 bytes. Each value still has its strict scalar
   or limb/padding bound. Only the isolated owner wrapper converts to the
   stock engine's ordinary decimal stream, inside an owner-only memory
   pipe. It never writes a variable-length normalized host file.
3. Per-party completion times are omitted from coordinator IPC. The process
   sees public session/counts, the three identical completed public engine
   projections and prepared hash. Scheduling/abort observations permitted
   by the frozen threat model are not claimed hidden.
4. A coordinator-written proposed file is untrusted ingress. Stable guarded
   reading rejects symlinks, hardlinks, nonregular files, excluded private
   paths/inodes and opened-inode swaps before any byte; exact engine bytes
   and their hash must match.
5. Exactly two distinct old roots must identify eight distinct original
   private inodes. New owner private roots cannot overlap old owner dirs or
   each other; the typed own-input route cannot override that exclusion.
6. Process waits/kills and stream closes run in a nested finally even when
   Docker cleanup raises. Public resource receipts project only neutral
   typed State fields, omitting free-text State.Error/private mount paths.
7. Stock `PRINTREGPLAIN` calls `Instruction::print` then
   `signed_output` at pinned `Processor/Instruction.hpp:1648`; it does not
   use the unsigned `gfp` stream operator. The wrapper accepts exactly the
   unique signed representative in[-floor(Q/2),floor(Q/2)], rejects -0,
   leading zeros and other aliases, and converts once to canonical[0,Q)
   public delta. Tuple limbs stay below2^248<Q/2. Private input aliases at
   or aboveQ remain rejected. Public controls cover signed-1→Q-1.

The fixed-width control uses100 public deterministic random byte rows and
canonical scalar values, checks every serialized size equals2,695 and
lossless reconstruction. It is a transport control, not an actual MPC run,
genuine proof, financial transaction or privacy qualification.
