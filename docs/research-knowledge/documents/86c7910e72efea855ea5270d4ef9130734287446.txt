# IPC18 complete result

The unchanged public B2 claim produced a genuine223898-byte Succinct receipt
in505.118077s startup+API time. The separate original verifier passed, including
the existing cryptographic/control negatives and8 exact outer-journal field
mutation controls. Image/input/J336/claim and77,752,334usercycles are unchanged.
No development mode, unresolved assumptions or compression was used.

This is a memory/latency tradeoff, not an improvement to the reference wallet:

| Measurement | Historical IPC19 | Completed IPC18 |
|---|---:|---:|
|Startup+proof response seconds|302.925665|505.118077|
|Segments|170|390|
|Total cycles|89,128,960|102,105,088|
|User cycles|77,752,334|77,752,334|
|Sampled matching GPU peak MiB|6096|3828|
|Host cgroup peak bytes|503,586,816|482,467,840|

IPC18 is202.192s slower (+66.75%) with37.20% lower sampled peak GPU memory.
The historical job had a different CPU cap/cache/concurrent-workload context;
this single comparison does not isolate a causal segment-size effect or p95.
IPC18 had6CPU/8GiB host/zero swap; its cgroup recorded zero throttling. The
8CPU constraint suite ran concurrently. Every one of390segment proofs,
390lifts and389joins completed. Stage markers show242.708s primary broad
work, including30.832s CPU preflight and211.875s core/verification proxies;
lift markers total112.465s and join markers134.568s. These are host/prover
intervals, not isolated CUDA kernel times.

All3242 samples were well formed with0 GPU-query/cgroup/foreign-process errors;
maximum sample gap was0.254s. Complete broad phase peaks were3828MiB primary
and2926MiB recursion. The frozen original actor admission fails:
3828+2926+512=7266MiB>6656MiB. No actor job ran under that old profile. A
separate7680MiB profile is documented and selected independently; it must not
rewrite this failure. The60s latency diagnostic fails. No CPU-only wallet,
end-to-end latency, native settlement or financial privacy claim follows.

Receipt SHA256:
3ea11d808b1dac69a1aa1ba28543ce4874519270db977eb203125f557bdad83b

Successful claim:
88f54f54030b2fc884c777a872262679fa15bffca8e613a0f6d40f7d90e92aaa

Independent verifier report SHA256:
e239b556c0697b115e073c9e50a07a666cb4070a0b47cee96220aabd3c2a5635

The owned unit is inactive/dead with MainPID0 and empty cgroup. All4 observed
PID/start identities are absent and the GPU compute-app list is empty at
completion. Original guest/program/host/tool/receipt packets remain unchanged.
