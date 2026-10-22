# Native packet publication audit

**Chosen publication scope: keep all historical source, text, logs and public case data; omit only the seven compiled ELF executables.** No redundant-source pruning is recommended under this scope. Proving keys and raw producer secrets are also excluded from the combined publication, but none are present in this native allowlist.

All 389 original files match their frozen size/SHA256 identities. No frozen packet, index, commit or branch ref was edited by this audit, and no native, proof or owner job ran. This new audit document is the only repository file written.

| Measure | Result |
|---|---:|
| Authoritative original files | 389 |
| Original total bytes | 99,399,444 |
| Compiled ELF omissions | 7 files / 95,403,272 B |
| Retained source/text/public data | 382 files / 3,996,172 B |
| Largest individual original file | 14,449,376 B |
| Individual files at least 50 MB / 100 MB | 0 / 0 |
| Symlinks or nonregular allowlisted files | 0 |
| Credential-pattern or exported secret-field findings | 0 |

No original file exceeds 50 MiB or 100 MiB either. The original allowlist itself and this audit document are additional publication metadata, outside the 389-row count. A full recursive staging of the original directory would incorrectly include the seven ELF files; use the explicit omission map.

Audited UTC: 2026-10-22T21:16:00.355680+00:00.

Authoritative allowlist: `research/intensive-2026-10-22/s7-native-policy/CLOSED-PUBLIC-ALLOWLIST.json`, SHA256 `54aaa91b14788daeb95d0e7cec748b5155a78ff94b24432eb4239797c5b6c620`.

## Exact software omission map

Paths below are relative to `research/intensive-2026-10-22/s7-native-policy/` in the lifecycle checkout. Keep their identities in the existing manifests and original allowlist; omit the executable bytes from Git. Do not delete or rewrite the original local files.

| Omitted file | Bytes | SHA256 |
|---|---:|---|
| `native-checkers-final-source/kpi_s7_ordinary_spend_check` | 14,449,376 | `c8128ea5683bd3b8e4ada6c4cdc780053cbdc4e0e759e1b211f1ee12657255de` |
| `native-checkers-final-source/kpi_s7_pair_native_check` | 14,442,336 | `fa555cf57dd7f084e5146c32f0dd2962daa40d6e9a350a043f21fe21a087cf09` |
| `ordinary-native-source-01/kpi_s7_ordinary_spend_check` | 14,449,344 | `f316d7d88e86173f14f92f48201928b50f14ef57f47162896560ee01cdba22e0` |
| `pair-native-source-01/kpi_s7_pair_native_check` | 14,403,528 | `1e381d6578e969c3a9c698d000959ee0d78f0d1395fd1aec6db75ab9f8d73ee2` |
| `pair-native-source-02/kpi_s7_pair_native_check` | 14,441,456 | `48a3eaeff10538b6a636136fc7c771779c27586adbceefc2c4c9dc79423ff735` |
| `pair-native-source-03/kpi_s7_pair_native_check` | 14,442,208 | `9ad89173d9cbabee9f9f082742e8d899dc51555ff626917dd184250ee03aa92c` |
| `source-shape-01/kpi_s7_policy_shape` | 8,775,024 | `eb320c0b604e5cb3b4a90eed81b845c97795e0652ec7041e6dde9555beea23e8` |

This is the complete omission map within the 389-file native allowlist. No proving-key, wallet-backup, private-plan, raw seed-key or evaluation-truth file occurs in that inventory. The producer lane independently confirmed that its actual raw plans, two wallet JSONs and PK are excluded/ignored; its separate publication map controls those paths outside this inventory. Do not recursively stage `lifecycle/artifacts/` or `lifecycle-outer-target/` based on this native audit.

Five small non-ELF binary blobs remain: the 336-byte expected journal, P1088 projection, S105 next state, 128-byte canonical proof, and 24,576-byte emitted redeem. These are public protocol case inputs/code bytes required to inspect the native experiment. They are not host executables, shared libraries, guest ELF/program images, setup parameters or credentials. Transaction JSON also contains the actual protocol script bytes and must remain exact.

## Retained source, logs and reproduction evidence

Keep every other original allowlist row, including all historical duplicates. In particular:

1. Keep all four frozen crate source trees. The final snapshot contains 68 text source/lock files, 827,133 B, and preserves the exact tested native emitter, profile, module registration and public Cargo pins. Historical source trees preserve earlier build stages, including the initial broad-error classifier. The current native-lane source files remain in their canonical locations too.
2. Keep all six `build-journal.txt` files, historical source-freeze/manifest records, build-wrapper sources and the complete source-shape/model packet. Build journals are operational attribution rather than additional native qualification, but are intentionally retained. The shape packet is explicitly synthetic/source-only; its zero128-byte framing never established cryptographic acceptance.
3. Keep complete `pair-native-01/**` and `ordinary-spend-native-02/**` packets, including public inputs, native proof128, actual body JSON, official Full/typed-error reports, exact source/input/binary identity records, resource outcomes and live namespace evidence.
4. Keep complete `ordinary-spend-native-01/**`, `ordinary-runtime-mount-observation.json` and the corrected02 comparison. The original wrapper exposed a writable input alias; the corrected run was separately authorized and observed. Do not hide that first-stage limitation or merge the two attempts.

The scratch source with the initial uncompiled ordinary `nf_count==4` mistake is **not among the 389 archived files**. Its correction to n5/m2 is documented by the retained README and independent review trail. Do not claim those exact scratch bytes were archived here or silently reconstruct them. All source snapshots actually present in the allowlist remain retained.

The 382 retained original allowlist row objects, in their original order, have selection SHA256 `{selection_sha}` using `json.dumps(rows, sort_keys=True, separators=(',', ':'))`. The rule is simply: keep every authoritative row except the seven exact ELF omission rows above. No row content or historical hash is changed.

A native-only rebuild needs the exact final Cargo source snapshot, Rust1.95.0, target `x86_64-unknown-linux-gnu`, feature `s7-native-policy`, public pinned dependencies, and binaries `kpi_s7_pair_native_check` / `kpi_s7_ordinary_spend_check`. The retained build wrappers preserve the actual absolute-path build command. An arbitrary checkout may need path adaptation and dependency retrieval; byte-identical rebuilt executables are not promised. The original binary SHA remains the identity of the measured execution. This audit did not rebuild or execute anything.

This subset does not replace the separate initial founding/bootstrap/ADMIT factory evidence, fresh guest/image source/program identity, official SDK receipt/extractor evidence, ADR0037 or independent source reviews. Those remain separate closed publication lanes. Re-running the native cases from their retained supplied-public-input packets needs no proving key, GPU, setup, wallet backup, owner flow or RPC.

## Credential and local-data findings

- Rehashed every complete file. Scanned raw bytes, including the seven ELF blobs, for PEM private-key headers and AWS/GitHub/Slack/OpenAI credential signatures. Scanned UTF8 text for URL credentials and literal password/API/access/refresh-token assignments. No matches were found.
- Recursively inspected JSON field names for exported secrets, seeds, mnemonics, passwords, private/spending/viewing/native keys and credentials. None were present. VKs, proving-key SHA/size metadata, public authorizations/ciphertexts, SPKs and the native compressed proof are public cryptographic data.
- Wallet-named files are Rust source copies, not wallet exports. The fixture source derives explicit `DO_NOT_FUND` public test wallets from fixed labels. Source references to `SavedInput.secret`, wallet APIs or a proving-key output filename are code; the corresponding raw producer output files are not in this inventory. The producer owner independently confirmed this distinction.
- **34 retained UTF8 records contain local attribution.** They expose `/home/luke`, hostname `forge` in journal text, UID1000/systemd unit names, PID/start counters, cgroup paths, and filesystem mount/device names. These are intentional measurement provenance. This is not a scrubbed or host-anonymous export. No personal wallet contents or real mailbox was found; `user@1000.service` is a systemd unit string.
- These findings are bounded by signature, structured-key and source/data inspection. They do not turn the packet into a security or cryptographic audit. Do not redact frozen records in place. A future host-anonymous derivative would require a separate old/new-hash mapping; none was created here.

The 34 local-attribution records are listed below, relative to the lifecycle checkout. They are retained under the chosen all-source/text/data scope:

```text
research/intensive-2026-10-22/s7-native-policy/native-checkers-final-source/build-journal.txt
research/intensive-2026-10-22/s7-native-policy/native-checkers-final-source/build-s7-bin.sh
research/intensive-2026-10-22/s7-native-policy/native-checkers-final-source/build-s7-checkers.sh
research/intensive-2026-10-22/s7-native-policy/native-checkers-final-source/source-freeze.json
research/intensive-2026-10-22/s7-native-policy/ordinary-native-source-01/build-journal.txt
research/intensive-2026-10-22/s7-native-policy/ordinary-native-source-01/freeze.json
research/intensive-2026-10-22/s7-native-policy/ordinary-spend-native-01/command.json
research/intensive-2026-10-22/s7-native-policy/ordinary-spend-native-01/input-freeze.json
research/intensive-2026-10-22/s7-native-policy/ordinary-spend-native-01/result.json
research/intensive-2026-10-22/s7-native-policy/ordinary-spend-native-01/unit-journal.txt
research/intensive-2026-10-22/s7-native-policy/ordinary-spend-native-02/actual-checker-1984893-mountinfo.txt
research/intensive-2026-10-22/s7-native-policy/ordinary-spend-native-02/command.json
research/intensive-2026-10-22/s7-native-policy/ordinary-spend-native-02/input-freeze.json
research/intensive-2026-10-22/s7-native-policy/ordinary-spend-native-02/mount-boundary-check.json
research/intensive-2026-10-22/s7-native-policy/ordinary-spend-native-02/result.json
research/intensive-2026-10-22/s7-native-policy/ordinary-spend-native-02/unit-journal.txt
research/intensive-2026-10-22/s7-native-policy/pair-native-01/actual-checker-1995910-mountinfo.txt
research/intensive-2026-10-22/s7-native-policy/pair-native-01/command.json
research/intensive-2026-10-22/s7-native-policy/pair-native-01/input-freeze.json
research/intensive-2026-10-22/s7-native-policy/pair-native-01/inputs-staged-before-proof.json
research/intensive-2026-10-22/s7-native-policy/pair-native-01/mount-boundary-check.json
research/intensive-2026-10-22/s7-native-policy/pair-native-01/result.json
research/intensive-2026-10-22/s7-native-policy/pair-native-01/unit-journal.txt
research/intensive-2026-10-22/s7-native-policy/pair-native-source-01/build-journal.txt
research/intensive-2026-10-22/s7-native-policy/pair-native-source-01/source-freeze.json
research/intensive-2026-10-22/s7-native-policy/pair-native-source-02/build-journal.txt
research/intensive-2026-10-22/s7-native-policy/pair-native-source-02/source-freeze.json
research/intensive-2026-10-22/s7-native-policy/pair-native-source-03/build-journal.txt
research/intensive-2026-10-22/s7-native-policy/pair-native-source-03/source-freeze.json
research/intensive-2026-10-22/s7-native-policy/source-shape-01/build-journal.txt
research/intensive-2026-10-22/s7-native-policy/source-shape-01/freeze.json
research/intensive-2026-10-22/s7-native-policy/source-shape-01/historical-source-map.json
research/intensive-2026-10-22/s7-native-policy/source-shape-01/input-provenance.json
research/intensive-2026-10-22/s7-native-policy/source-shape-01/run.sh
```

## Claims and known negatives to preserve

The actual pair report SHA256 is `732d8b87af970a00de547f9e20dc2f54300da4b8784fa8be3e603a526bf87537`: one official isolation→Full positive, 12 exact typed Full/reserve controls and three separately labeled host-factory controls. Budget1700 and fee80M remain unchanged. Measured mass196,484 and the rate500 failure requiring98,242,000 are preserved.

The corrected ordinary report SHA256 is `f4c74a954a677e668ae1b665870eb100b309f255057df821bc82abd8b1218bbc`: two alternative same-predecessor SPEND forks, never a combined accepted ledger, plus four exact typed controls. Fee40M passes rate100 and fails200/500. DRAIN, owner/public replay and full owner lifecycle remain unexecuted/parked. The source-adapted mass/standardness/relay screen is identified separately from actual official Full validation.

These are local declared-UTXO/native observations. They do not establish accepted ancestry, financial privacy, production safety or cryptographic correctness. Existing old protocol sources, earlier historical proof packets, failed/source-only attempts and their pins retain their separate identities. No new experiment or budget-default adoption is part of this publication audit.
