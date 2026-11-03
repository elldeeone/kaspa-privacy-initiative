# MWEB public parent join: independent delta review

**ACK: this add-on closes the earlier local parent-field evidence gap.** The supported combined conclusion is retained standalone transaction validation plus a separate explicit join to the supplied aggregate outputs. It establishes no accepted-chain UTXO, global unspentness or currentness.

## Reviewed identities and preservation

- Join source `poc/mweb-component-screen/public-parent-join/check.py`: `e716347a15075e8b7c38c027e72f8b3d853bba4ea11f9c5c0c886cdd6377239e`.
- Add-on source freeze: `76d20a3ecc0973065d78841810a205cca37e8f179b5159b8955c4fdf0c40adb2`.
- Add-on manifest/list: `8eb925fa7c3c1db3581e6866e0bfc68cdf75f2120ba5fb90b8f1774d61f10862` / `7497fd1b0fd3e8678a5f2c15bbee6665942bde05a0de7fca45d5dbda59e0fb00`.
- Original manifest/list remain `80d08a185e6590e761f814d4bfcc271bf731f8b3ab0041a48b35fce7c49e4d9f` / `a12e3ded7e70afdac97638778b71fe135eeb4bc3eb177323daba62f40ddd9b39`.
- Independent read-only checksum audit passed all 101 original payloads and all 13 add-on payloads. The three copied public transaction hashes agree with the original selected objects.
- Public inspector source remains `15f8d520dcebdf69655185b1227974c96b1dc286bb4f1fa9408f086e5f06a310`; the run pins inspector binary `39c15d3ff27486d49f8847111493be345e13ee91e8a9b955b553dc9b10e03069`. This review did not inspect or execute that binary.

## Source and result checks

`check.py:30` requires one spend input and constructs a unique index of the actual inspected aggregate outputs. It looks up the input's spent output ID, then separately compares its commitment and output authorization key to that parent's commitment and receiver public key (Ko). It uses the output authorization key rather than the input ephemeral key. It also requires the retained recipient observation's ID, checks the public kernel-fee sum against the pinned observation, and requires distinct parents for the two recipients.

The source authenticates the original packet manifest/list and exact selected transaction, receipt and prior-result bytes. Its inspector only deserializes/canonical-roundtrips public transactions and reports their fields; it does not call signing, proving or transaction/signature/range-proof validation.

The retained `public-parent-join-01/run-01/RESULTS.json` records two joins and ten expected public-field-copy rejections, with zero new cryptographic validation calls. The inspected public field reports independently show R1 ID `ec7911b3ae224ca5ba5ce7fa8dec160736d82d3fa798e8de6f991d5ddce17704` and R2 ID `8ffed90397fc629e9c615414696851af8534c23aa3b50a9d69cc3684a6a6124d`; each input commitment and authorization key exactly matches its indexed aggregate output, and each public fee is 1.

Each recipient has the five declared negative controls: same ID with another commitment; same ID with another Ko; crossed ID with original fields; all other-parent fields with the original recipient observation; and absent ID. The code requires each exact rejection boundary, and all ten retained outcomes match. These are public-field validation copies, not signed transactions or chain-valid attack demonstrations.

The addendum correctly preserves the original standalone-verifier limitation and adds this new evidence instead of rewriting the earlier packet. Amount equations remain labeled retained observations, with plaintext wire verification false. No financial privacy, native KAS, chain acceptance, reorg, backup recovery or independent cryptographic implementation claim follows.

Review actions were public source/result reads and finite checksum verification only. No experiment, inspector, cryptographic validator, RNG, private material or original work-directory access occurred.
