# One-v6 dependency preparation result

**PASS — both standard Cargo fetches and both one-time frozen/offline host metadata checks succeeded.** This closes the observed offline dependency-resolution blocker. It does not establish host build or verifier compatibility, and no dependency compilation, build script, check/test/run, guest/proof generation or verifier execution occurred in this lane.

Root explicitly selected the existing absolute **Cargo/rustc 1.97.1** toolchain for both workspaces and allowed its informational/host-target probes. This superseded the earlier data-only acquisition proposal before execution. The original proposal is preserved byte-for-byte at `/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/one-v6-dependency-preparation/proposals/data-only-protocol-v1.md`, SHA-256 `53df46b4d35df15849a116820fa29860031958c9e880d4068bcb8f59f42584f3`. The operative protocol/addendum is `compute/ONE-V6-DEPENDENCY-PREPARATION-PROTOCOL.md`, SHA-256 **`d61e3254949017aba48f0346cabd7c5da975997c75a43d9f44c863aebe9445be`**. No custom package manager or source replacement was implemented.

The immutable source stayed at `acba8b04237e62a5bbc3eb93eb10faa1722a59ea`, parent `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`, in `/home/luke/projects/kpi-one-v6-compatibility-2026-10-22`. All 11 recorded source/manifest/lock hashes matched after acquisition; the worktree remained clean. Original locks, adapter source acceptance, comparison protocol `b01cd6bbb4b0d9f097277e5986b0b4de7001b97896f5f74f3777d1ff50919932` and prior failed readiness receipts remain unchanged. No shared cache, system configuration, credentials or parked wrapper was changed.

The exact attempt is:

`/home/luke/projects/kpi-orchestration/2026-10-22/compute-plan/one-v6-dependency-preparation/attempt-20261022T113744Z-dd881d90`

Owner: `/root/compute_plan`. Actual execution ran **2026-10-22 11:39:57.252534–11:40:21.786701 UTC / 22:39:57–22:40:21 AEDT**, **24.534 seconds** elapsed. Its fixed deadline was 11:59:57.252534 UTC; no extension or retry occurred.

| Stage | Exit | Recorded stage wall time | Result |
| --- | ---: | ---: | --- |
| Reference fetch | 0 | 10.440114 s | Locked native-host source dependencies acquired |
| Candidate fetch | 0 | 10.879283 s | Locked native-host source dependencies acquired |
| Reference metadata | 0 | 1.485120 s | 377 packages and 377 resolved nodes; exact one_v6_reference binary |
| Candidate metadata | 0 | 1.517600 s | 501 packages and 501 resolved nodes; exact one_v6_candidate binary |

Stage durations include the controller's observation/exit delay; they are not compilation or performance benchmarks. Each fetch used the absolute pinned Cargo path with `fetch --locked --target x86_64-unknown-linux-gnu --manifest-path <exact workspace Cargo.toml>`. Each metadata observation used `metadata --frozen --offline --format-version 1 --filter-platform x86_64-unknown-linux-gnu --manifest-path <exact workspace Cargo.toml>`, once only. Raw argv, sandbox binds and sanitized environment are recorded in `status.json` and per-stage receipts.

The source worktree and selected toolchain were read-only; the fresh private `cargo-home/` was the only Cargo cache. No shared cache was seeded or mounted. Git hooks/custom credential helpers/prompts and inherited configuration were disabled. Fetch network access served the immutable crates.io and three locked public Git source identities; metadata ran with networking disabled. All **521 downloaded registry archives**, totaling **71,937,972 bytes**, were independently SHA-256 checked against the union of the two unchanged locks; all matched. The resulting Cargo cache contains **30,539 file/symlink leaves**, **558,875,384 file bytes**.

The previously missing **k256 0.13.4** archive is now present at `cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/k256-0.13.4.crate`; its SHA-256 is exactly **`f6e3919bbaa2945715f0bb6d3934a173d1e9a59ac23767fbaaef277265a7411b`**. Other previously uncached locked dependencies were also acquired. k256 was never assumed to be the only gap.

The metadata graphs contain no effective feature literally named `prove` or `cuda`. Candidate `risc0-zkvm 3.0.3` resolves `bonsai, client, default, std`; its RISC Zero circuit crates have empty feature sets, and `risc0-groth16 3.0.4` resolves `default, std`. These are graph observations, not a complete build-script/guest/native-asset verdict. The lead retains that separate qualification and the requirement to deny external network access during any later build.

| Frozen observation | SHA-256 |
| --- | --- |
| `logs/metadata-reference/stdout` | `d594c97dedb34d8eb23ae6d51f91d2e8ff01eda871993d8fba3f4130a6ed3871` |
| `logs/metadata-candidate/stdout` | `7d9f23652da7a5a7b423e8727160e6fb02d1fb1e6df151413f4bba7dcf2bb14d` |
| `closure-handoff.json` | `31b8451cc33c0db3d99907956591866356b4d5338740331ed7da5f2788328294` |
| `integrity-summary.json` | `a26b638d3b331dbeb433e84c200774fc8b9b5aae2eb7290b33ddfecf85c9e72d` |

Fresh prelaunch capacity passed two consecutive 10-second intervals: 0% full-stall, zero swap-out/OOM growth, about 0.25% host CPU busy, and **21,697,581,056 bytes of conservative headroom after the cap**. No GPU allocation was made. Execution used one owned unit, **`kpi-one-v6-dependencies-v1-113744.service`**, invocation **`8eb8966fb3364c949e18b0c609e15728`**, initial controller PID **1141192**.

Actual limits were **1 CPU / 1 GiB / zero swap / 64 PIDs**, CPU affinity 0, RuntimeMaxSec 1190 with a five-second stop limit and whole-cgroup cleanup. The 8 GiB private disk ceiling was an ordinary sampled stop threshold, not a filesystem quota. Sampled attempt disk peaked at **561,147,301 bytes** before final manifests. Unit CPU use was **8.659833 seconds** and peak cgroup memory **842,846,208 bytes**. Across the recorded 22.931-second sampling span, full memory stalls were **0.032794%**, with **zero swap-out or OOM growth**. The small nonzero pressure excursion is preserved rather than rounded to zero.

Cleanup completed at **11:42:18.528566 UTC**: the exact unit was stopped, inactive/dead with MainPID/ControlPID 0 and empty ControlGroup; its cgroup path was absent and all **21 sampled PID/start-time identities** were absent. Successful short-lived processes not caught by sampling are covered by whole-unit/cgroup absence, not a claim of exhaustive process sampling. Root accepted the handoff and released the 1 CPU / 1 GiB reservation. Cleanup receipt SHA-256: **`e3f88dd8aad18bedb19162b26cdfb6816937a7d52c4bc76f999d6d90e441de03`**.

The evidence cache is now handed off **read-only**. A later owner may mount its registry/git directories read-only into a new private Cargo home or copy them into its own exclusive cache; it must not mutate this frozen attempt. Root received both graphs and terminal cleanup before the documentation commit. The later host-build and verifier scopes belong to the lead's existing implementation owner and were not executed here.

The final cache manifest is `cache-manifest.json`, SHA-256 **`f368f2860d0b20f42a7d7ce8f6fbecdf9946dc337fedf8b3c1c6f2ba8ab86113`**. The raw receipt manifest is `receipt-manifest.json`, SHA-256 **`819fc10f87d23fef213570aa79c0390fce341f423dcb236fc1231f1e517796cd`**, covering **27 non-cache receipt leaves / 12,917,360 bytes**, including the cache manifest. These receipts preserve the command/environment/source identities, actual source acquisition, both graphs, limits, usage and terminal cleanup.
