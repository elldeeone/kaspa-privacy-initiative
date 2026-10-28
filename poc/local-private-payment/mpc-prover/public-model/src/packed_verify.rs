//! Independent SNARK verification against the admitted compact metadata/VK.
//! Only public files and public instances are read; no matrix/witness/dealer.
use super::*;
use ark_bn254::Fq;
use ark_ff::BigInteger;

struct Reader<'a> { bytes: &'a [u8], at: usize }
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(count).ok_or("packed-metadata-overflow")?;
        let value = self.bytes.get(self.at..end).ok_or("packed-metadata-truncated")?;
        self.at = end;
        Ok(value)
    }
    fn u64(&mut self) -> Result<u64> { Ok(u64::from_le_bytes(self.take(8)?.try_into()?)) }
    fn fr(&mut self) -> Result<Fr> {
        let bytes = self.take(32)?;
        let mut remaining = bytes;
        let value = Fr::deserialize_compressed(&mut remaining)?;
        if !remaining.is_empty() || serialized(&value)? != bytes {
            return Err("packed-metadata-noncanonical-Fr".into());
        }
        Ok(value)
    }
    fn digest(&mut self, nonzero: bool) -> Result<[u8; 32]> {
        let value: [u8; 32] = self.take(32)?.try_into()?;
        if nonzero && value.iter().all(|b| *b == 0) { return Err("packed-empty-identity".into()); }
        Ok(value)
    }
}

fn add(a: u64, b: u64) -> Result<u64> { a.checked_add(b).ok_or_else(|| "packed-count-overflow".into()) }
fn mul(a: u64, b: u64) -> Result<u64> { a.checked_mul(b).ok_or_else(|| "packed-count-overflow".into()) }

struct Statement { instances: usize, vk_sha: [u8; 32], vk_bytes: usize }

fn statement(bytes: &[u8]) -> Result<Statement> {
    let mut reader = Reader { bytes, at: 0 };
    if reader.take(16)? != b"KPI_PACKED_V1\0\0\0" { return Err("packed-metadata-magic".into()); }
    let mode = reader.u64()?;
    if !matches!(mode, 1 | 2) { return Err("packed-prefix-mode".into()); }
    if reader.take(32)? != Fr::MODULUS.to_bytes_le() || reader.take(32)? != Fq::MODULUS.to_bytes_le() {
        return Err("packed-field-or-curve".into());
    }
    reader.digest(true)?; // Source identity.
    let legacy = reader.digest(mode == 1)?;
    if mode == 2 && legacy.iter().any(|b| *b != 0) { return Err("packed-derived-legacy-marker".into()); }
    reader.digest(true)?; // PK identity, bound by the metadata root.
    let vk_sha = reader.digest(true)?;
    reader.digest(true)?; // Complete exact matrix identity.
    for _ in 0..6 { reader.digest(true)?; } // Encoded and decoded axis identities.
    let instances = reader.u64()?;
    let witnesses = reader.u64()?;
    let rows = reader.u64()?;
    let domain = reader.u64()?;
    let variables = add(instances, witnesses)?;
    if instances < 2 || rows == 0 || domain == 0 || !domain.is_power_of_two() ||
        domain > 1 << 28 || add(rows, instances)? > domain {
        return Err("packed-statement-shape".into());
    }
    let pk_bytes = reader.u64()?;
    let vk_bytes = reader.u64()?;
    let expected_vk = add(232, mul(32, instances)?)?;
    let expected_pk = add(add(add(expected_vk, 104)?, mul(128, variables)?)?,
        add(mul(32, witnesses)?, mul(32, domain - 1)?)?)?;
    if vk_bytes != expected_vk || pk_bytes != expected_pk { return Err("packed-key-byte-shape".into()); }
    for _ in 0..3 { if reader.u64()? == 0 { return Err("packed-empty-axis".into()); } }
    let minimum_axis = add(80, mul(8, rows)?)?;
    for _ in 0..3 {
        let size = reader.u64()?;
        if size < minimum_axis || (size - minimum_axis) % 40 != 0 {
            return Err("packed-axis-byte-shape".into());
        }
    }
    let omega = reader.fr()?;
    let omega_inverse = reader.fr()?;
    let inv_n = reader.fr()?;
    let shift = reader.fr()?;
    let selected = Radix2EvaluationDomain::<Fr>::new(usize::try_from(domain)?).ok_or("packed-domain")?;
    if omega != selected.group_gen || omega_inverse != selected.group_gen_inv || inv_n != selected.size_inv ||
        shift == Fr::ZERO || shift.pow([domain]) == Fr::ONE {
        return Err("packed-domain-parameters".into());
    }
    let count = reader.u64()?;
    if mode == 1 {
        if count != instances || reader.fr()? != Fr::ONE { return Err("packed-public-prefix-shape".into()); }
        for _ in 1..count { reader.fr()?; }
    } else {
        if count != 0 || reader.u64()? != instances - 1 { return Err("packed-derived-prefix-shape".into()); }
        reader.digest(true)?; reader.digest(true)?;
    }
    if reader.at != bytes.len() { return Err("packed-metadata-trailing".into()); }
    Ok(Statement { instances: usize::try_from(instances)?, vk_sha, vk_bytes: usize::try_from(vk_bytes)? })
}

pub(super) fn verify(meta_path: &Path, vk_path: &Path, proof_path: &Path,
                     public: &str, expected_meta: &str) -> Result<bool> {
    if expected_meta.len() != 64 || !expected_meta.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("packed-expected-model-format".into());
    }
    let bytes = fs::read(meta_path)?;
    if hash(&bytes) != expected_meta { return Err("packed-model-pin".into()); }
    let selected = statement(&bytes)?;
    let values = public.split(',').map(canonical_scalar).collect::<Result<Vec<_>>>()?;
    if values.len().checked_add(1) != Some(selected.instances) { return Err("packed-public-instance-arity".into()); }
    let vk_bytes = fs::read(vk_path)?;
    if vk_bytes.len() != selected.vk_bytes || Sha256::digest(&vk_bytes).as_slice() != selected.vk_sha {
        return Err("packed-VK-pin".into());
    }
    let mut remaining = vk_bytes.as_slice();
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&mut remaining)?;
    if !remaining.is_empty() || serialized(&vk)? != vk_bytes || vk.gamma_abc_g1.len() != selected.instances ||
        vk.alpha_g1.is_zero() || vk.beta_g2.is_zero() || vk.gamma_g2.is_zero() || vk.delta_g2.is_zero() ||
        vk.gamma_abc_g1.iter().any(AffineRepr::is_zero) { return Err("packed-invalid-VK".into()); }
    let proof_bytes = fs::read(proof_path)?;
    if proof_bytes.len() != 128 { return Err("packed-Native128-length".into()); }
    let mut remaining = proof_bytes.as_slice();
    let proof = Proof::<Bn254>::deserialize_compressed(&mut remaining)?;
    if !remaining.is_empty() || serialized(&proof)? != proof_bytes ||
        proof.a.is_zero() || proof.b.is_zero() || proof.c.is_zero() {
        return Err("packed-noncanonical-or-identity-proof".into());
    }
    Ok(Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&vk), &proof, &values)?)
}
