# Execution amendment for the fresh private trial

ADR-0054 supersedes only the executable-launch paragraphs of ADR-0053 and
CONTRACT.md. Their original authority bytes remain unchanged for provenance.

Use ordinary SHA256-checked executable files in trusted private0700 release
directories, executable0500, read-only sandbox mounts, fixed clean environment.
Trust the host/release owner not to mutate or replace these files during an
operation. Do not claim malicious-host/inode-writer protection. Do not use a
special executable-FD/system-loader path or alter any host security policy.

Keep the same strict inputs, private witness pipe, parameters-ready-before-seed
ordering, software/manifest/VK/cache authority, current-state/NF checks, exact
whole-body/context quote identity and once-only transaction markers.

New runtime controls cover wrong hash, missing/unselected software, ordinary
read-only sandbox execution and no public/private-output mixing. They do not
rerun a population/privacy experiment or weaken protocol checks. Preserve all
superseded source/probes; no new actual trial has been funded yet.
