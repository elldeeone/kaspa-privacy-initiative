//! One PUBLIC v6 inner-proof compatibility diagnostic, never settlement authority.
//! Reuses the established checked Arkworks decoder and accelerated Groth16
//! equation. It proves no accepted anchor, spent set, backing, payout, delivery,
//! anonymity, or two-bundle aggregation property.
use ark_bn254::{Bn254, Fr};
use ark_groth16::VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use kpi_accelerated_bn254::Verifier;
use risc0_zkvm::sha::{Impl, Sha256};

pub const AUTH_LEN: usize = 377;
pub const PROOF_LEN: usize = 128;
pub const CIPHER_LEN: usize = 185;
pub const BUNDLE_LEN: usize = AUTH_LEN + PROOF_LEN + 2 * CIPHER_LEN;
pub const JOURNAL_LEN: usize = 40;
pub const MAX_SOMPI: u64 = 2_900_000_000_000_000_000;
pub const DOMAIN: [u8; 32] = [
    0xd3, 0x6f, 0xda, 0x2e, 0x66, 0x8f, 0xa8, 0x58, 0xae, 0x85, 0x24, 0x84, 0xe6, 0x3e, 0xa6, 0xda,
    0xbb, 0x25, 0x94, 0x03, 0x90, 0x1f, 0xd9, 0xc8, 0x8a, 0x16, 0xe9, 0xc5, 0xb1, 0x7e, 0x5b, 0xaa,
];
pub const VK_SHA256: [u8; 32] = [
    0x9e, 0x6a, 0xb3, 0x0d, 0x24, 0x42, 0xfb, 0x6a, 0xb6, 0xfb, 0xb5, 0xc8, 0xaa, 0x9f, 0x11, 0xd8,
    0xf1, 0x61, 0xfe, 0x47, 0xad, 0xa0, 0x94, 0xd7, 0x81, 0x0f, 0xd9, 0x24, 0x0e, 0xe1, 0x19, 0xef,
];
// Derived only from the allowlisted public verification-key.json. Both build
// preflight and checked_key verify its exact digest. No prover-selected key.
const VK_BYTES: &[u8] = include_bytes!("../pins/vk.bin");

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Impl::hash_bytes(bytes).as_bytes().try_into().unwrap()
}

pub fn checked_key() -> Result<Verifier, &'static str> {
    if VK_BYTES.len() != 328 || sha256(VK_BYTES) != VK_SHA256 {
        return Err("fixed VK identity");
    }
    let mut rest = VK_BYTES;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&mut rest)
        .map_err(|_| "VK checked decode")?;
    vk.check().map_err(|_| "VK validity")?;
    let mut encoded = Vec::new();
    vk.serialize_compressed(&mut encoded)
        .map_err(|_| "VK encoding")?;
    if !rest.is_empty() || encoded != VK_BYTES {
        return Err("VK canonical roundtrip");
    }
    if vk.gamma_abc_g1.len() != 3 {
        return Err("VK arity");
    }
    if vk.alpha_g1.infinity
        || vk.beta_g2.infinity
        || vk.gamma_g2.infinity
        || vk.delta_g2.infinity
        || vk.gamma_abc_g1.iter().any(|p| p.infinity)
    {
        return Err("VK identity");
    }
    Ok(Verifier::from_validated_program_key(&vk, VK_SHA256))
}

pub fn public_inputs(authorization: &[u8]) -> Result<[Fr; 2], &'static str> {
    if authorization.len() != AUTH_LEN {
        return Err("authorization length");
    }
    let digest = sha256(authorization);
    Ok(std::array::from_fn(|index| {
        Fr::from(u128::from_le_bytes(
            digest[index * 16..(index + 1) * 16].try_into().unwrap(),
        ))
    }))
}

pub fn check_profile(bundle: &[u8]) -> Result<(), &'static str> {
    if bundle.len() != BUNDLE_LEN {
        return Err("bundle length");
    }
    let a = &bundle[..AUTH_LEN];
    if &a[..8] != b"KPICU06\0" || a[8..40] != DOMAIN {
        return Err("authorization magic/domain");
    }
    if a[204] != 1 || a[205..213].iter().any(|b| *b != 0) || a[221..345].iter().any(|b| *b != 0) {
        return Err("mode1 zero-payout profile");
    }
    let fee = u64::from_le_bytes(a[213..221].try_into().unwrap());
    if !(1..=MAX_SOMPI).contains(&fee) {
        return Err("fee range");
    }
    for start in [76usize, 140] {
        let first = &a[start..start + 32];
        let second = &a[start + 32..start + 64];
        if first == [0; 32] || second == [0; 32] || first == second {
            return Err("active nullifier/commitment shape");
        }
    }
    if a[345..377] != sha256(&bundle[AUTH_LEN + PROOF_LEN..]) {
        return Err("ordered ciphertext digest");
    }
    Ok(())
}

/// Diagnostic journal publishes the hash of an ALREADY PUBLIC source bundle.
/// It is deliberately distinct from the two-bundle KPI2V6J1 contract and is
/// unsuitable for hiding grouping or authorizing a native state transition.
pub fn expected_journal(bundle: &[u8]) -> Result<[u8; JOURNAL_LEN], &'static str> {
    if bundle.len() != BUNDLE_LEN {
        return Err("bundle length");
    }
    let mut journal = [0; JOURNAL_LEN];
    journal[..8].copy_from_slice(b"KPI1V6J1");
    journal[8..].copy_from_slice(&sha256(bundle));
    Ok(journal)
}

pub fn verify_bundle(bundle: &[u8]) -> Result<[u8; JOURNAL_LEN], &'static str> {
    check_profile(bundle)?;
    let verifier = checked_key()?;
    #[cfg(target_os = "zkvm")]
    println!(
        "PROFILE checked_fixed_key {}",
        risc0_zkvm::guest::env::cycle_count()
    );
    let inputs = public_inputs(&bundle[..AUTH_LEN])?;
    verifier.verify_inputs(&bundle[AUTH_LEN..AUTH_LEN + PROOF_LEN], &inputs)?;
    expected_journal(bundle)
}
