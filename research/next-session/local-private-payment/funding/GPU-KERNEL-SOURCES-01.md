# GPU PoW source review — stopped before execution

**2026-10-25 UTC: NOT EXECUTED.** Root cancelled GPU work after identifying a CPU template/result queue bug; the chain worker reported236,805 SDK checks/s/worker and approximately6.66s/validnonce across two workers. These are Root-supplied measurements.

The [official testnet guide](https://wiki.kaspa.org/en/testnets) requests CPU-only TN10 mining (verified by the funding-source sibling). No further downloads, staging, build, GPU run or benchmark occurred after STOP.

[Official mining wiki](https://wiki.kaspa.org/mining) links [tmrlvi/kaspa-miner](https://github.com/tmrlvi/kaspa-miner), pinned `bf361d02a46c580f55f46b5dfa773477634a5753` (2022-08-23). [ZorkNetwork fork](https://github.com/ZorkNetwork/kheavyhash-miner/tree/06e1349922374d9a810ef33041778a2050aaa844), pinned `06e1349922374d9a810ef33041778a2050aaa844` (2026-05-03), lists the same sm86 PTX Git blob. The full miner includes devfund/network paths and was not selected or run.

Fourteen public files and applicable Apache/MIT notices remain at `/var/tmp/kpi-gpu-pow-public-source-01/tmrlvi-bf361d02a46c580f55f46b5dfa773477634a5753/`; `SOURCE.json` pins URLs, sizes and SHA256 hashes.

- CUDA: `plugins/cuda/kaspa-cuda-native/src/kaspa-cuda.cu`; SHA256 `4164002cb30e57aaa3a471d8c7f58b2824c7bad01211c53096dc7731fde815db`.
- PTX: `plugins/cuda/resources/kaspa-cuda-sm86.ptx`; SHA256 `e26eeb19ea77c23acb66bc9953f1ea218c5f761a3468e4f3e30369f18e5d1249`; ASCII PTX7.5/sm86,173,869B.
- ABI: `plugins/cuda/src/worker.rs`; matrix/reference: `src/pow.rs`, `src/pow/heavy_hash.rs`. Globals: matrix4096B, header72B=`prePowHash32||timestampLE8||zero32`, target32B. `heavy_hash` args: u64mask/fixed/count,u8mode,states/result device pointers.
- Untested inference: CUDA Driver API could JIT the ASCII PTX without nvcc. Compatibility, throughput and current-header correctness were not demonstrated.
- Pitfalls: XOR nonce enumeration; nonce0 sentinel; in-kernel thread0 result clear may lose a hit; strict`<target` versus CPU`<=`; signed32-bit thread index. Do not reuse the2022 RPC serializer; current SDK/CPU validation would be mandatory for any future candidate.

No private wallet read, trial reset, funding, submission, outbound miner/devfee connection or mainnet operation occurred. CPU-only gate remains in force; no GPU prototype exists.
