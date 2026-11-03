# One ciphertext-format canary

This prospective synthetic C-only format experiment tests one source-derived
classifier. It is not a population, crypto, accepted-history or privacy
qualification. No funding, RPC, prover, private wallet/profile/backup or old seed
is used. Fresh experiment-only recipient material remains in generator memory.

Exactly256 genuine V2 Receipt216 sealed boxes,256 old uniform-random264 dummy
ciphertexts and256 proposed throwaway-recipient sealed boxes are independently
constructed and shuffled once. Genuine receipts use the current serializer and
bridge. Each proposed dummy seals independent random216-byte plaintext to its
own newly generated throwaway X25519 recipient. Real and proposed ciphertexts
are decrypted for a generator-local roundtrip check; no decryption key is saved.

Before generation, freeze this method, generator/attacker/scorer/controller,
recipient/bridge sources, actual bridge executable, dependency sources and Python.
The attacker gets ciphertext bytes and ordinal only in a network-isolated
filesystem. It gets no labels, recipient keys, generator state, seeds or other
files. The controller seals predictions before launching the separate scorer
with truth labels. Labels may be published afterward: they describe unfunded
format samples and contain no secrets. Only one experiment is authorized.

The fixed test is `ciphertext[31] & 0x80 != 0`. Positive means **not an honest
crypto_box0.9.1 sealed box**, hence a dummy within this controlled fixture.
Negative means unresolved. No other byte/curve tests or fitted parameters are
permitted. Report flagged/total for all three classes, plus full-coverage binary
diagnostics that guess dummy when flagged and real otherwise. Shared real
controls correlate the two diagnostics; no independent confidence interval or
privacy improvement estimate is claimed. No favorable resampling is allowed.

Source hypothesis: crypto_box prefixes its generated ephemeral public key;
dalek encodes that Montgomery coordinate canonically modulo2^255−19, so bit255
is zero. Uniform raw padding has that bit set with probability1/2. Any flag on
the genuine or proposed sealed class stops the claimed explanation and requires
diagnosis. Old class detection is measured without a preset observed count.
Terminal zero ciphertexts are explicitly public in Auth528 and excluded.

The run uses one CPU,2GiB and zero swap, records live cgroup limits before
generation, and retains source/input/prediction/truth/result hashes. These small
format operations do not measure wallet/prover performance or native fees.
The unchanged21103/100025>20% amount-prior failure remains unchanged.
