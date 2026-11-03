# Integrated unfunded constructor

`driver.py` is trusted supervision/public-data glue. It invokes owner workers by
opaque directory handles and never opens their private files, maps or MPC streams.
The untrusted body assembler runs separately in bubblewrap, with public stdin,
four read-only public source leaves and its own output directory only. The
construction package separately isolates its public collector and MPC parties.

Every command requires both old trial roots as metadata-only exclusions:
`--exclude-private-root LOCAL --exclude-private-root LIVE`, and three
`--exclude-owner-private-directory PARTY_i` flags. Each new private party parent
contains `owner/` and `mpc/`; neither child nor its parent is a public export.
All outputs are fresh directories outside Git. No private invocation handles,
raw child argv/diagnostics or owner maps belong in publication/coordinator IPC.
Owner job roots contain private launcher plans/logs: put them under controller-
private storage and select **only** their `public/PUBLIC.json` child for ingress.
Every `INIT/PUBLIC.json`, `READY/PUBLIC.json` and `AUTH/PUBLIC.json` shorthand
below refers to that permitted `JOBROOT/public/PUBLIC.json` leaf.

Public file selectors are pairs `FILE SHA256`. Public producer exports have
strict field sets. Every external public read uses the old-eight-backup/new-
three-party metadata guards and stable opened-inode checks before bytes. After
an owner creates files, refresh those exclusions before reading its public export.

Run these phases with root's selected source/executable pins and resource limits:

1. `owner-init --party i --participant-id HEX32 --admission-sompi INTEGER
   --crypto ELF SHA --wallet-script-sha256 SHA --execute`. Only the owner process
   creates seeds/notes/private invoices. Read its permitted `PUBLIC.json` after
   all three finish; disclose no per-owner preparation timing to the coordinator.
2. `genesis --owner-public INIT0/PUBLIC.json SHA ...` (three selectors). Produces
   the canonical occupied three-CM prefix, NF sentinel, public State112 and
   membership paths. It is explicitly unfunded supplied context, not funding.
3. Select the genuine new VK profile, guest image/native template, **new** native
   budget and exact quoted fee before session/effects/authorization. `context`
   takes `--genesis FILE SHA --owners FILE SHA --component-profile-sha256 SHA
   --point-hex36 HEX --fee-sompi INTEGER --native-tail-hex HEX`. The exact fee is
   shared as `F//3,F//3,F-2*(F//3)` without a divisibility assumption. Both output
   notes for each owner must fit the preserved value floor.
4. `session --genesis FILE SHA --owners FILE SHA --component-profile-sha256 SHA
   --effects-context-sha256 CONTEXT_RAW_SHA --program-sha256 SELECTED_PROGRAM_SHA`.
   An optional explicit `--session-id HEX32` replaces a fresh public random nonce.
   Body.session is the canonical complete SESSION SHA; roster digest is
   `SHA256(KPX7RO01|three ordered participant IDs)`. No future mixed root/SPK is
   required in the pre-mix context; its approved template derives those later.
5. `mpc-prepare --engine-root STAGE09 --session FILE SHA --backend-sha256 SHA
   --program-sha256 SHA --codec-sha256 SHA --party-sha256 SHA
   --coordinator-sha256 SHA --execute`. This public compiler phase has no owner
   input. Select the currently root-reviewed construction program; the retained
   stock-shuffle negative is not a release for a changed replacement program.
6. `owner-prepare --party i --owners FILE SHA --assets FILE SHA --session FILE SHA
   --context FILE SHA --wallet-script-sha256 SHA --execute`. Each isolated owner
   creates its two genuine Output proofs and writes its own fixed private MPC
   stream directly. Its only public result is the NF/CVin readiness skeleton.
7. `mpc-run --prepared-root DIR --prepared-sha256 SHA --backend-sha256 SHA
   --execute`, under the construction backend's required1CPU/512MiB controller
   cap plus its separately limited parties/anchor. No actual engine run precedes
   root's current protocol release. A party failure is INCOMPLETE, not a subset.
8. `build --genesis FILE SHA --owners FILE SHA --session FILE SHA --context FILE SHA
   --ready READY0/PUBLIC.json SHA ... --mixed MIXED.json SHA`. The public-only
   assembler derives three current NF insertions and six sequential CM appends,
   yielding Body10780 with zero Spend slots and old/new State112. These zeros
   are placeholders for constructing effects and never count as valid proofs.
9. `native-project --body BODY.bin SHA --native-codec ELF SHA --outer-image-hex32 HEX
   --component-profile-sha256 SHA --compute-budget INTEGER`. The selected new
   emitter derives both actual same-template SPKs and canonical native case,
   Projection10973, Effects32 and Journal104. Its default outer proof is zero;
   this step explicitly performs neither financial proof nor VM verification.
10. `owner-authorize --party i --assets FILE SHA --session FILE SHA
    --projection FILE SHA --own-mpc-result RELATIVE_HANDLE
    --wallet-script-sha256 SHA --execute`. The owner independently consumes its
    own engine report, checks the whole effects/outputs/state/balance and creates
    its genuine Spend200 proof. The relative report handle stays controller-
    private; the controller does not open that report or any private directory.
11. `finalize --projection FILE SHA --spend-public AUTH0/PUBLIC.json SHA ...`
    attaches three exact-statement Spend proofs, changing no EffectsDigest.
    Run `native-project` again on the final body to regenerate its full-body
    journal/canonical case. All proof bytes are now public; no owner-output map is.
12. `verify --projection FILE SHA --verifier-host ELF SHA
    --component-profile-sha256 SHA --execute` runs the selected actual nine-proof
    predicate and its independent Arkworks pairing reference. Only that success
    sets the integration report's financial-proof flag. Genuine R0 execution/
    proving/compression and Native Full acceptance are subsequent distinct root
    jobs, not implied here. No funding or broadcast command exists.

Pure public controls: `python3 -B -m unittest -v test_public.py`. These exercise
independently built roots, stale/duplicate paths and the intentional Spend-proof
witness/output-proof digest distinction. Synthetic frame fixtures contain zero
proofs/invalid CVs and never substitute for the integrated genuine positive.

Each phase writes `INTEGRATION.json`; it contains finite public output hashes,
not private selectors or timings. `commands.OwnerHandles` provides the exact
owner/MPC invocation handles for a scheduled trusted root supervisor. It captures
and discards raw child diagnostics rather than relaying them to the coordinator.
