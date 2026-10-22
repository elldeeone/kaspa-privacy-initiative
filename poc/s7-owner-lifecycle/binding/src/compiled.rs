//! Separately selected, immutable research-instance parameters for the guest.
//!
//! The generic `ConfiguredResearchGate::with_trusted_key` is unchanged and
//! always checked. Only the private zero-argument fixed-key function below may
//! skip repeated static-key subgroup validation inside the guest. Before its
//! build, an independent host preflight MUST fully validate these exact bytes,
//! then source/key/tool/ELF/image identities MUST be frozen and reviewed.
//! Submitted proofs always use the established checked verifier, unchanged.
use super::*;

// Fresh PUBLIC TEST-ONLY setup, distinct from the original rehearsal.
// Exact parameters and inputs were selected independently by root before build.
// No default rehearsal key/domain or deployed covenant is changed.
include!("profile.rs");
const COMPILED_VK_BYTES: &[u8] = include_bytes!("../pins/compiled-research-vk.bin");

fn immutable_program_key() -> Result<VerifyingKey<Bn254>> {
    #[cfg(not(target_os = "zkvm"))]
    {
        // This is the mandatory checked build preflight, including canonical
        // decoding, complete consumption, subgroup/nonidentity checks and IC3.
        checked_key(COMPILED_VK_BYTES, COMPILED_KEY_SHA256)
    }
    #[cfg(target_os = "zkvm")]
    {
        if COMPILED_VK_BYTES.len() != 328 || sha256(COMPILED_VK_BYTES) != COMPILED_KEY_SHA256 {
            return Err(Error::FixedKey);
        }
        // Exact established static-parameter optimization from Verifier::pinned.
        // This PRIVATE function accepts no bytes or key identity from input.
        // The exact immutable bytes were checked before the image was selected.
        let mut rest = COMPILED_VK_BYTES;
        let vk = VerifyingKey::<Bn254>::deserialize_compressed_unchecked(&mut rest)
            .map_err(|_| Error::CanonicalEncoding("compiled verification key"))?;
        let mut encoded = Vec::new();
        vk.serialize_compressed(&mut encoded)
            .map_err(|_| Error::CanonicalEncoding("compiled verification key"))?;
        if !rest.is_empty() || encoded != COMPILED_VK_BYTES {
            return Err(Error::CanonicalEncoding("compiled verification key"));
        }
        if vk.gamma_abc_g1.len() != 3 {
            return Err(Error::KeyArity);
        }
        if vk.alpha_g1.infinity
            || vk.beta_g2.infinity
            || vk.gamma_g2.infinity
            || vk.delta_g2.infinity
            || vk.gamma_abc_g1.iter().any(|p| p.infinity)
        {
            return Err(Error::IdentityPoint("compiled verification key"));
        }
        Ok(vk)
    }
}

/// Nonsettling gate for exactly the image-compiled key/domain. Construction
/// takes no witness-supplied key, digest or domain. This remains a separately
/// identified research instance, never the default rehearsal contract.
pub struct CompiledResearchGate {
    inner: ConfiguredResearchGate,
}
impl CompiledResearchGate {
    pub fn new() -> Result<Self> {
        let vk = immutable_program_key()?;
        Ok(Self {
            inner: ConfiguredResearchGate {
                verifier: Verifier::from_validated_program_key(&vk, COMPILED_KEY_SHA256),
                instance: Instance {
                    domain: COMPILED_DOMAIN,
                    key_sha256: COMPILED_KEY_SHA256,
                },
            },
        })
    }
    pub fn assemble(&self, bundles: [Bundle; 2]) -> Result<Witness> {
        self.inner.assemble(bundles)
    }
    pub fn verify_inner_bundle(&self, bundle: &Bundle) -> Result<()> {
        bundle.check_profile(COMPILED_DOMAIN)?;
        // verify_inputs already checks exact128 length, checked canonical
        // curve/subgroup decoding, full consumption, byte-exact re-encoding,
        // nonidentity A/B/C and input arity. Repeating checked_proof here would
        // validate submitted subgroup membership three times, with no new rule.
        self.inner
            .verifier
            .verify_inputs(&bundle.proof, &public_inputs(&bundle.authorization))
            .map_err(Error::InnerProof)
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<VerifiedBinding> {
        let witness = Witness::parse_for(bytes, self.inner.instance)?;
        witness.check_binding()?;
        for bundle in &witness.bundles {
            self.verify_inner_bundle(bundle)?;
        }
        Ok(VerifiedBinding::from_projection(
            witness.projection.bytes()?,
        ))
    }
    pub fn check_publication(&self, projection: &[u8], journal: &[u8]) -> Result<()> {
        self.inner.check_publication(projection, journal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immutable_parameters_are_fully_checked_on_the_host() {
        let checked = checked_key(COMPILED_VK_BYTES, COMPILED_KEY_SHA256).unwrap();
        let actual = immutable_program_key().unwrap();
        let mut expected_bytes = Vec::new();
        let mut actual_bytes = Vec::new();
        checked.serialize_compressed(&mut expected_bytes).unwrap();
        actual.serialize_compressed(&mut actual_bytes).unwrap();
        assert_eq!(expected_bytes, COMPILED_VK_BYTES);
        assert_eq!(actual_bytes, expected_bytes);
        CompiledResearchGate::new().unwrap();
    }
}
