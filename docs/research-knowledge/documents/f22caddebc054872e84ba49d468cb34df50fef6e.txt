# Exact SHA-256 circuit cost probe

Separate, public, **DO_NOT_FUND**, synthesis-only adaptation of
`../future-private-payment`. It preserves the SHA-256 bytes, private transfer
relation, domain and native wire formats. It changes the R1CS matrices and
**cannot use an existing proving or verification key**.

Only two SHA round expressions change:

```text
Ch(e,f,g)  = e.select(f,g)
Maj(a,b,c) = (a XOR b).select(c,a)
```

Majority retains the upstream expression on constant operands so constant
folding cannot regress. The SHA schedule, arithmetic, streaming, padding and
feed-forward body are copied from pinned Arkworks 0.6.0; original MIT attribution
is retained in `LICENSE-MIT` and the module header.

The only transfer-source differences are the gadget import, local module
registration and prospective `2^22` measurement assertion. Ownership, positioned
nullifiers, dummy semantics, Merkle membership, value/range checks and public
transcript binding are unchanged.

Evidence and the source review are under
`../../research/next-session/prover-cost/`. No setup, key loading, proof,
networking or native transaction validation is part of this experiment. A
reduced constraint count does not establish proof latency or wallet RAM.
