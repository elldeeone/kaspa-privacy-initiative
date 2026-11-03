# Bounded prototype interface

All execution uses a fresh directory outside Git. Preserve prior attempts.
Only public data is accepted by the public preparation API. Every command
declares both existing LOCAL and LIVE original-trial exclusion roots; they
are metadata-only guards, never worker inputs. Also declare the three new
owner private roots in roster order using repeated
`--exclude-owner-private-directory ROOT` flags. All current secret file
inodes and those complete directories are excluded before public reads.

1. Select public `SESSION.json`. Exact schema is enforced by `codec.session`:

   ```json
   {
     "schema": "kpx7-private-construction-session/v1",
     "session_id": "<fresh32bytes lowercasehex>",
     "domain_hex": "32b4f31a58cc52d22862c20a923c59cdd0127785e9998f632eae2b3bb319919d",
     "prior_state_digest": "<selected prior state32>",
     "circuit_profile_sha256": "<selected circuit profile32>",
     "public_effects_context_sha256": "<agreed public pre-mix context32>",
     "roster": ["<participant0id32>", "<participant1id32>", "<participant2id32>"],
     "program_source_sha256": "<frozen kpx7_mix.mpc SHA256>",
     "tuple_bytes": 520,
     "outputs_per_party": 2,
     "mpc_prime": "2736030358979909402780800718157159386076813972158567259200215660948447373041"
   }
   ```

   Session identity is SHA256 of canonical JSON (sorted keys, compact
   separators, trailing newline). The raw input JSON whole-file pin is
   checked separately. Each owner checks the entire same specification.

2. Compile public program only:

   ```text
   backend.py prepare --engine-root SELECTED_EXISTING_STAGE09
     --session SESSION --session-sha256 RAW_SHA
     --program-sha256 FROZEN_PROGRAM --codec-sha256 FROZEN_CODEC
     --party-sha256 FROZEN_PARTY --coordinator-sha256 FROZEN_COORDINATOR
     --output FRESH_PREPARED
     --exclude-private-root LOCAL --exclude-private-root LIVE
     --exclude-owner-private-directory OWNER0_PRIVATE
     --exclude-owner-private-directory OWNER1_PRIVATE
     --exclude-owner-private-directory OWNER2_PRIVATE
   ```

   The selected existing installation inventory is fixed to
   `5d0def4ae617f6365fccb5f243922088faaf7a6148aa0938c3a3f9520c4ff594`.
   Only its authenticated compiler, compiler-only dependency and stock
   MASCOT members are copied. A network-off compiler namespace uses exact
   `-P BabyFr -F249`. `PREPARED.json` selects the actual finite immutable
   software and bytecode/schedule closure. No owner input or engine runs.

3. Each independently isolated owner worker imports the frozen `codec.py`,
   calls `owner_input([complete_tuple0, complete_tuple1], beta_i)` inside
   its own worker, and creates only its own `Input-P{party}-0` mode0400 in
   an opaque owner-specific directory. Exactly35 lines, each76 zero-padded
   ASCII decimal digits plus newline, for exactly2,695 bytes regardless of
   values/blindings/tuple content. Every scalar/limb range remains strict.
   The owner never sends either tuple, a tuple/proof hash or beta to the
   coordinator. Its private ground truth/oracle remains separate.

4. Run the released malicious construction under a host controller cgroup
   capped1CPU/512MiB, swap0 (the three separately limited containers plus
   anchor bring the total to at most3.8CPU/3616MiB):

   ```text
   backend.py run --prepared-root PREPARED --prepared-sha256 WHOLE_SHA
     --owner-input-directory OPAQUE0 OPAQUE1 OPAQUE2 --output FRESH_RESULT
     --exclude-private-root LOCAL --exclude-private-root LIVE --execute
     --exclude-owner-private-directory OWNER0_PRIVATE
     --exclude-owner-private-directory OWNER1_PRIVATE
     --exclude-owner-private-directory OWNER2_PRIVATE
   ```

   The host examines only input metadata. Before reading its mounted input,
   each party checks the opened device/inode against the selected metadata.
   It validates the fixed35x77byte encoding, then normalizes to ordinary
   decimal only in its own memory and own subprocess pipe; no normalized
   variable-length file is written on a host mount.
   Raw engine logs remain in that owner's fresh `mpc-private-UUID` scratch
   beside the opaque input, outside the public output tree. They are never
   copied/read by the coordinator. Party stdout is a validated complete
   public projection after successful engine completion; errors are fixed
   neutral strings. The wrapper also writes `OWN-MPC-PROJECTION.json` in
   that owner's private scratch, before the coordinator runs. Each owner
   uses this own-engine result when independently checking the entire
   final Effects before its post-mix SpendG16. All three final projections
   must be identical.

5. Result `MIXED.json` is six complete mixed tuple hex strings plus one
   canonical aggregate delta and session hash. `RESULTS.json` records
   finite counts/scope; `CLEANUP.json` records owned container removal and
   actual sampled cgroup counters. No ready/readiness/financial acceptance
   assertion follows from these files. The native adapter must verify all
   genuine output proofs, balance, state and post-mix SpendG16 proofs over
   the exact complete effects before accepting a transaction.

The trusted host launcher operates Docker but does not read any owner
tuple/opening. It is not the adversarial coordinator. It sends only
`COORDINATOR-PUBLIC-IPC.json` (public session, three identical mixed engine
projections and prepared program hash, without individual completion times) to a
separate network-off coordinator namespace. That namespace has public
stdin, pinned codec/coordinator source and its own public output directory;
no Docker socket, owner path, host home, credential, engine scratch or
execution-request API. `coordinator-public/OBSERVER.json` records actual
visible namespace surfaces. Its proposed mixed result must exactly match
the three direct engine outputs; each owner independently checks its own
engine projection as well. Docker/root administrators remain explicitly
outside the local confidentiality claim. No raw private scratch, owner
oracle, uploader map, unmixed proof hashes or private controller arguments
are publishable.
