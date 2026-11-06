#!/usr/bin/env python3
"""Generate the isolated pinned-key variant; all other kernel text stays exact."""
from pathlib import Path
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'batched-payment-costs/common/src/lib.rs'
text = SOURCE.read_text()
start = text.index('    pub fn new(raw: &[u8]) -> Result<Self, String> {')
end = text.index('\n}\nimpl ProofVerifier', start)
replacement = '''    pub fn new(raw: &[u8]) -> Result<Self, String> {
        // Fixed bytes are fully validated and canonically re-encoded by pin().
        // The guest image binds the bytes; supplied state must match exactly.
        // No submitted proof point bypasses its existing checked decoder.
        if raw != include_bytes!("../../pins/vk-compressed.bin") {
            return Err("pinned wallet key mismatch".into());
        }
        let bytes = include_bytes!("../../pins/vk-uncompressed.bin");
        let mut input = bytes.as_slice();
        let vk = VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut input)
            .map_err(|e| e.to_string())?;
        if !input.is_empty() || vk.gamma_abc_g1.len() != 3 {
            return Err("pinned key arity/encoding".into());
        }
        Ok(Self {
            inner: kpi_accelerated_bn254::Verifier::from_validated_program_key(
                &vk, hash(raw)),
        })
    }'''
output = text[:start] + replacement + text[end:]
manifest = json.dumps({
    'source': str(SOURCE.relative_to(HERE.parents[1])),
    'sourceSha256': hashlib.sha256(text.encode()).hexdigest(),
    'generatedSha256': hashlib.sha256(output.encode()).hexdigest(),
    'onlyReplacement': 'Verifier::new; fixed validated image-bound key',
}, indent=2) + '\n'
if '--check' in sys.argv:
    assert (HERE / 'common/src/lib.rs').read_text() == output
    assert (HERE / 'KERNEL-SOURCE.json').read_text() == manifest
    print('Exact kernel reuse checked; only Verifier::new differs.')
else:
    (HERE / 'common/src/lib.rs').write_text(output)
    (HERE / 'KERNEL-SOURCE.json').write_text(manifest)
