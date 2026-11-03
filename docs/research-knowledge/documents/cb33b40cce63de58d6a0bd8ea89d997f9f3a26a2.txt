# Current-W runtime availability

This supplies the current unfunded W wallet and its exact prebuilt tools as public bytes. It closes the software/emitter availability gap between the new capacity parameter distribution and the independent wallet rehearsal. It does not inherit the old D35/B05 software archive's financial selection.

`make_plan.py` lists explicit public sources and selected executable identities. `prepare.py` joins all eight runtime wallet files to the externally selected source freeze, verifies the complete allowlist, and creates a canonical regular-file USTAR/zstd archive. The wallet control source is excluded because its public test seed recipe is unnecessary at runtime. No backup, owner seed, witness, PK blob, actor generator or private controller plan is packaged.

`download.py` uses the unchanged pinned HTTPS transport and strict inventory/unpack helpers. The index's whole SHA and length must be supplied independently. It downloads and verifies bytes only; it never imports or executes restored wallet code. Explicitly selected wallet software is a separate execution step.

The current archive contains 64 typed files plus three authenticated metadata files. The generic member flag about absent history means **no private or accepted-history authority**: public synthetic prestate, the genuine W validation case and its public result are deliberately included as canaries. None proves accepted-chain backing or currentness.

Actual HTTPS restoration used only a trusted bootstrap, compatible OS/Python/system libraries/TLS, and a fresh output mount. Original home/repository/runtime/PK/backup paths were absent. The restored wallet launcher then receives the selected inventory, current public data, separately HTTPS-restored compact PK and one original backup. Outer proving and compression assets are unnecessary for the private fallback.

See [RESULTS.md](../../research/next-session/independent-payments/current-wrapper-runtime/RESULTS.md) for exact roots, publication and restoration evidence. Executables, the archive and proving keys remain outside Git.
