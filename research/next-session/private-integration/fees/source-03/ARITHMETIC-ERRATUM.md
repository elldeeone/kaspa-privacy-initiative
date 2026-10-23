# Prospective common-stack correction

Arithmetic01 and source-01 are preserved. They reproduce the historical native
cost anchors but use the previous public probe's redeem+69 REVEAL witness,
redeem+133 proof witness and hypothetical redeem+3 ingress witness. The new
union contract instead has one common redeem+199 witness in every pool branch:
canonical signature65 push66 + proof128 push130 + redeem header3. Therefore01
undercounts130 reveal bytes,66 private bytes and196 admission bytes relative to
that proposed union. Independent source review identified this before any new
native job or publication claim. These are prospective-model corrections; no
closed historical packet, body or native result changes.

Arithmetic02 prices the common witness, exact core4356 PRIVATE payload and2029
REVEAL payload, plus the1344-byte proposed one-note native ingress. It preserves
3344 public state-witness bytes per logical private payment in its unimplemented
aggregate generalization, rather than dropping those checks into an assumed
larger circuit. The old compressed projection remains visible in01 only. A
different future aggregate circuit may attest those updates, but it requires a
new reviewed relation and resource/latency/authority argument.

Budgets, exact larger-arity wire and public ingress remain prospective. A model
pass is a necessary size/economics screen, never an executed authorization or
genuine private lifecycle. The specialized one-payer/two-recipient/no-change
core pilot is now shown separately from generic payment plus payer-change.
