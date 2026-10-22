//! Exact, NONSETTLING two-v6 binding contract on an ordinary host.
//!
//! Successful verification establishes only an existential partition of the
//! supplied public projection into two valid, same-anchor SPEND statements.
//! It establishes neither accepted anchors nor current spentness, native
//! backing, recipient spendability, data availability, or settlement authority.
//! The collector sees the entire input, including the otherwise hidden grouping.
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kpi_accelerated_bn254::Verifier;
use std::fmt;

#[cfg(feature = "compiled-research-instance")]
pub mod compiled;

pub type Hash = [u8; 32];
pub const AUTH_LEN: usize = 377;
pub const PROOF_LEN: usize = 128;
pub const CIPHER_LEN: usize = 185;
pub const RECORD_LEN: usize = 32 + CIPHER_LEN;
pub const BUNDLE_LEN: usize = AUTH_LEN + PROOF_LEN + 2 * CIPHER_LEN;
pub const PROJECTION_LEN: usize = 1_088;
pub const JOURNAL_LEN: usize = 42;
pub const INPUT_LEN: usize = PROJECTION_LEN + 2 * BUNDLE_LEN + 8;
pub const MAX_SOMPI: u64 = 2_900_000_000_000_000_000;
pub const DOMAIN: Hash = [
    0xd3, 0x6f, 0xda, 0x2e, 0x66, 0x8f, 0xa8, 0x58, 0xae, 0x85, 0x24, 0x84, 0xe6, 0x3e, 0xa6, 0xda,
    0xbb, 0x25, 0x94, 0x03, 0x90, 0x1f, 0xd9, 0xc8, 0x8a, 0x16, 0xe9, 0xc5, 0xb1, 0x7e, 0x5b, 0xaa,
];
pub const VK_SHA256: Hash = [
    0x9e, 0x6a, 0xb3, 0x0d, 0x24, 0x42, 0xfb, 0x6a, 0xb6, 0xfb, 0xb5, 0xc8, 0xaa, 0x9f, 0x11, 0xd8,
    0xf1, 0x61, 0xfe, 0x47, 0xad, 0xa0, 0x94, 0xd7, 0x81, 0x0f, 0xd9, 0x24, 0x0e, 0xe1, 0x19, 0xef,
];
const VK_BYTES: &[u8] = include_bytes!("../pins/rehearsal-vk.bin");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Length(&'static str),
    FixedKey,
    CanonicalEncoding(&'static str),
    IdentityPoint(&'static str),
    KeyArity,
    Profile(&'static str),
    AnchorMismatch,
    CountMismatch,
    Nullifiers,
    Commitments,
    CiphertextDigest,
    Fee,
    ProjectionOrder,
    Permutation(&'static str),
    PublicBinding(&'static str),
    InnerProof(&'static str),
    Publication,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

pub fn sha256(bytes: &[u8]) -> Hash {
    kpi_groth16_comparison::proxy::hash(bytes)
}
fn canonical<T: CanonicalDeserialize + CanonicalSerialize>(
    bytes: &[u8],
    label: &'static str,
) -> Result<T> {
    let mut rest = bytes;
    let value =
        T::deserialize_compressed(&mut rest).map_err(|_| Error::CanonicalEncoding(label))?;
    value.check().map_err(|_| Error::CanonicalEncoding(label))?;
    let mut encoded = Vec::new();
    value
        .serialize_compressed(&mut encoded)
        .map_err(|_| Error::CanonicalEncoding(label))?;
    if !rest.is_empty() || encoded != bytes {
        return Err(Error::CanonicalEncoding(label));
    }
    Ok(value)
}
fn checked_key(bytes: &[u8], expected_sha256: Hash) -> Result<VerifyingKey<Bn254>> {
    if bytes.len() != 328 || sha256(bytes) != expected_sha256 {
        return Err(Error::FixedKey);
    }
    let vk: VerifyingKey<Bn254> = canonical(bytes, "verification key")?;
    if vk.gamma_abc_g1.len() != 3 {
        return Err(Error::KeyArity);
    }
    if vk.alpha_g1.infinity
        || vk.beta_g2.infinity
        || vk.gamma_g2.infinity
        || vk.delta_g2.infinity
        || vk.gamma_abc_g1.iter().any(|point| point.infinity)
    {
        return Err(Error::IdentityPoint("verification key"));
    }
    Ok(vk)
}
fn checked_proof(bytes: &[u8]) -> Result<()> {
    if bytes.len() != PROOF_LEN {
        return Err(Error::Length("proof"));
    }
    let proof: Proof<Bn254> = canonical(bytes, "proof")?;
    if proof.a.infinity || proof.b.infinity || proof.c.infinity {
        return Err(Error::IdentityPoint("proof"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub authorization: [u8; AUTH_LEN],
    pub proof: [u8; PROOF_LEN],
    pub ciphertexts: [[u8; CIPHER_LEN]; 2],
}
impl Bundle {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BUNDLE_LEN {
            return Err(Error::Length("bundle"));
        }
        Ok(Self {
            authorization: bytes[..AUTH_LEN].try_into().unwrap(),
            proof: bytes[AUTH_LEN..AUTH_LEN + PROOF_LEN].try_into().unwrap(),
            ciphertexts: [
                bytes[AUTH_LEN + PROOF_LEN..BUNDLE_LEN - CIPHER_LEN]
                    .try_into()
                    .unwrap(),
                bytes[BUNDLE_LEN - CIPHER_LEN..].try_into().unwrap(),
            ],
        })
    }
    pub fn bytes(&self) -> [u8; BUNDLE_LEN] {
        let mut bytes = [0; BUNDLE_LEN];
        bytes[..AUTH_LEN].copy_from_slice(&self.authorization);
        bytes[AUTH_LEN..AUTH_LEN + PROOF_LEN].copy_from_slice(&self.proof);
        bytes[AUTH_LEN + PROOF_LEN..BUNDLE_LEN - CIPHER_LEN].copy_from_slice(&self.ciphertexts[0]);
        bytes[BUNDLE_LEN - CIPHER_LEN..].copy_from_slice(&self.ciphertexts[1]);
        bytes
    }
    fn nullifier(&self, slot: usize) -> Hash {
        self.authorization[76 + 32 * slot..108 + 32 * slot]
            .try_into()
            .unwrap()
    }
    fn commitment(&self, slot: usize) -> Hash {
        self.authorization[140 + 32 * slot..172 + 32 * slot]
            .try_into()
            .unwrap()
    }
    fn record(&self, slot: usize) -> [u8; RECORD_LEN] {
        let mut record = [0; RECORD_LEN];
        record[..32].copy_from_slice(&self.commitment(slot));
        record[32..].copy_from_slice(&self.ciphertexts[slot]);
        record
    }
    fn fee(&self) -> u64 {
        u64::from_le_bytes(self.authorization[213..221].try_into().unwrap())
    }
    fn check_profile(&self, domain: Hash) -> Result<()> {
        let a = &self.authorization;
        if &a[..8] != b"KPICU06\0" {
            return Err(Error::Profile("authorization magic"));
        }
        if a[8..40] != domain {
            return Err(Error::Profile("domain"));
        }
        if a[204] != 1 {
            return Err(Error::Profile("SPEND mode"));
        }
        if a[205..213].iter().any(|byte| *byte != 0) {
            return Err(Error::Profile("zero payout"));
        }
        // Every non-SPEND native effect is forbidden, including destination,
        // admission funding and bootstrap. This is the complete [221,345) span.
        if a[221..345].iter().any(|byte| *byte != 0) {
            return Err(Error::Profile("native effects"));
        }
        if !(1..=MAX_SOMPI).contains(&self.fee()) {
            return Err(Error::Fee);
        }
        let cm = [self.commitment(0), self.commitment(1)];
        if cm.contains(&[0; 32]) || cm[0] == cm[1] {
            return Err(Error::Commitments);
        }
        let ordered: Vec<u8> = self.ciphertexts.iter().flatten().copied().collect();
        if a[345..377] != sha256(&ordered) {
            return Err(Error::CiphertextDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Projection {
    // Chosen by trusted caller configuration, never parsed as a new verifier
    // identity from a prover's input. Gate compares every public identity byte.
    instance: Instance,
    pub aggregate_fee_sompi: u128,
    pub nullifiers: [Hash; 4],
    pub outputs: [[u8; RECORD_LEN]; 4],
}
impl Projection {
    fn check(&self) -> Result<()> {
        if !(2..=2 * u128::from(MAX_SOMPI)).contains(&self.aggregate_fee_sompi) {
            return Err(Error::Fee);
        }
        if self.nullifiers.contains(&[0; 32])
            || !self.nullifiers.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(Error::Nullifiers);
        }
        if !self.outputs.windows(2).all(|pair| pair[0] <= pair[1]) {
            return Err(Error::ProjectionOrder);
        }
        if self.outputs.iter().any(|record| record[..32] == [0; 32]) {
            return Err(Error::Commitments);
        }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::parse_for(bytes, Instance::REHEARSAL)
    }
    fn parse_for(bytes: &[u8], instance: Instance) -> Result<Self> {
        if bytes.len() != PROJECTION_LEN {
            return Err(Error::Length("public projection"));
        }
        if &bytes[..8] != b"KPI2V6P1"
            || bytes[8..10] != 1u16.to_le_bytes()
            || bytes[10..12] != 2u16.to_le_bytes()
            || bytes[12..44] != instance.domain
            || bytes[44..76] != instance.key_sha256
        {
            return Err(Error::Profile("public projection"));
        }
        let projection = Self {
            instance,
            aggregate_fee_sompi: u128::from_le_bytes(bytes[76..92].try_into().unwrap()),
            nullifiers: std::array::from_fn(|i| {
                bytes[92 + 32 * i..124 + 32 * i].try_into().unwrap()
            }),
            outputs: std::array::from_fn(|i| {
                bytes[220 + RECORD_LEN * i..220 + RECORD_LEN * (i + 1)]
                    .try_into()
                    .unwrap()
            }),
        };
        projection.check()?;
        Ok(projection)
    }
    pub fn bytes(&self) -> Result<[u8; PROJECTION_LEN]> {
        self.check()?;
        let mut bytes = [0; PROJECTION_LEN];
        bytes[..8].copy_from_slice(b"KPI2V6P1");
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&2u16.to_le_bytes());
        bytes[12..44].copy_from_slice(&self.instance.domain);
        bytes[44..76].copy_from_slice(&self.instance.key_sha256);
        bytes[76..92].copy_from_slice(&self.aggregate_fee_sompi.to_le_bytes());
        for i in 0..4 {
            bytes[92 + 32 * i..124 + 32 * i].copy_from_slice(&self.nullifiers[i]);
            bytes[220 + RECORD_LEN * i..220 + RECORD_LEN * (i + 1)]
                .copy_from_slice(&self.outputs[i]);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct Witness {
    pub projection: Projection,
    pub bundles: [Bundle; 2],
    /// Flattened original bundle/slot index -> sorted public nullifier index.
    pub nullifier_permutation: [u8; 4],
    /// Flattened original bundle/slot index -> sorted complete-record index.
    pub output_permutation: [u8; 4],
}
fn permutation(indices: &[u8; 4], label: &'static str) -> Result<()> {
    let mut seen = [false; 4];
    for index in indices {
        let slot = seen
            .get_mut(usize::from(*index))
            .ok_or(Error::Permutation(label))?;
        if *slot {
            return Err(Error::Permutation(label));
        }
        *slot = true;
    }
    Ok(())
}
impl Witness {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::parse_for(bytes, Instance::REHEARSAL)
    }
    fn parse_for(bytes: &[u8], instance: Instance) -> Result<Self> {
        if bytes.len() != INPUT_LEN {
            return Err(Error::Length("complete input"));
        }
        Ok(Self {
            projection: Projection::parse_for(&bytes[..PROJECTION_LEN], instance)?,
            bundles: [
                Bundle::parse(&bytes[PROJECTION_LEN..PROJECTION_LEN + BUNDLE_LEN])?,
                Bundle::parse(&bytes[PROJECTION_LEN + BUNDLE_LEN..INPUT_LEN - 8])?,
            ],
            nullifier_permutation: bytes[INPUT_LEN - 8..INPUT_LEN - 4].try_into().unwrap(),
            output_permutation: bytes[INPUT_LEN - 4..].try_into().unwrap(),
        })
    }
    pub fn bytes(&self) -> Result<[u8; INPUT_LEN]> {
        let mut bytes = [0; INPUT_LEN];
        bytes[..PROJECTION_LEN].copy_from_slice(&self.projection.bytes()?);
        bytes[PROJECTION_LEN..PROJECTION_LEN + BUNDLE_LEN]
            .copy_from_slice(&self.bundles[0].bytes());
        bytes[PROJECTION_LEN + BUNDLE_LEN..INPUT_LEN - 8].copy_from_slice(&self.bundles[1].bytes());
        bytes[INPUT_LEN - 8..INPUT_LEN - 4].copy_from_slice(&self.nullifier_permutation);
        bytes[INPUT_LEN - 4..].copy_from_slice(&self.output_permutation);
        Ok(bytes)
    }
    // Structural binding alone is deliberately private: callers cannot mistake
    // it for proof verification. All successful public acceptance uses Gate.
    fn check_binding(&self) -> Result<()> {
        self.projection.check()?;
        for bundle in &self.bundles {
            bundle.check_profile(self.projection.instance.domain)?;
        }
        if self.bundles[0].authorization[40..44] != self.bundles[1].authorization[40..44] {
            return Err(Error::CountMismatch);
        }
        if self.bundles[0].authorization[44..76] != self.bundles[1].authorization[44..76] {
            return Err(Error::AnchorMismatch);
        }
        let fee = u128::from(self.bundles[0].fee())
            .checked_add(u128::from(self.bundles[1].fee()))
            .ok_or(Error::Fee)?;
        if fee != self.projection.aggregate_fee_sompi {
            return Err(Error::PublicBinding("aggregate fee"));
        }
        permutation(&self.nullifier_permutation, "nullifiers")?;
        permutation(&self.output_permutation, "outputs")?;
        for k in 0..4 {
            let bundle = &self.bundles[k / 2];
            if self.projection.nullifiers[usize::from(self.nullifier_permutation[k])]
                != bundle.nullifier(k % 2)
            {
                return Err(Error::PublicBinding("nullifier"));
            }
            if self.projection.outputs[usize::from(self.output_permutation[k])]
                != bundle.record(k % 2)
            {
                return Err(Error::PublicBinding("commitment/ciphertext record"));
            }
        }
        Ok(())
    }
}

/// Construct the canonical projection and index bijections without proving or
/// accepting anything. `Gate::verify` is required before publishing a result.
/// Stable index sorting preserves multiplicity even for identical output records.
pub fn assemble(bundles: [Bundle; 2]) -> Result<Witness> {
    assemble_for(bundles, Instance::REHEARSAL)
}
fn assemble_for(bundles: [Bundle; 2], instance: Instance) -> Result<Witness> {
    let mut nfs: [(Hash, usize); 4] = std::array::from_fn(|k| (bundles[k / 2].nullifier(k % 2), k));
    let mut records: [([u8; RECORD_LEN], usize); 4] =
        std::array::from_fn(|k| (bundles[k / 2].record(k % 2), k));
    nfs.sort_by_key(|(value, _)| *value);
    records.sort_by_key(|(value, _)| *value);
    let mut p = [0; 4];
    let mut q = [0; 4];
    for i in 0..4 {
        p[nfs[i].1] = i as u8;
        q[records[i].1] = i as u8;
    }
    let projection = Projection {
        instance,
        aggregate_fee_sompi: u128::from(bundles[0].fee())
            .checked_add(u128::from(bundles[1].fee()))
            .ok_or(Error::Fee)?,
        nullifiers: nfs.map(|(value, _)| value),
        outputs: records.map(|(value, _)| value),
    };
    let witness = Witness {
        projection,
        bundles,
        nullifier_permutation: p,
        output_permutation: q,
    };
    witness.check_binding()?;
    Ok(witness)
}

/// Two unsigned little-endian 128-bit limbs; neither whole-digest reduction nor
/// the historical proxy journal-to-field conversion is the v6 statement.
fn public_inputs(authorization: &[u8; AUTH_LEN]) -> [Fr; 2] {
    let digest = sha256(authorization);
    std::array::from_fn(|i| {
        Fr::from(u128::from_le_bytes(
            digest[16 * i..16 * (i + 1)].try_into().unwrap(),
        ))
    })
}

/// Output-byte container returned by host verification. Constructing this
/// container independently is not verification; only `Gate::verify` performs
/// both proof checks. No receipt, program image, state qualification or native
/// transaction is generated by this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBinding {
    pub projection: [u8; PROJECTION_LEN],
    pub journal: [u8; JOURNAL_LEN],
    pub projection_digest: Hash,
    pub journal_digest: Hash,
}
impl VerifiedBinding {
    fn from_projection(projection: [u8; PROJECTION_LEN]) -> Self {
        let projection_digest = sha256(&projection);
        let mut journal = [0; JOURNAL_LEN];
        journal[..8].copy_from_slice(b"KPI2V6J1");
        journal[8..10].copy_from_slice(&1u16.to_le_bytes());
        journal[10..].copy_from_slice(&projection_digest);
        let journal_digest = sha256(&journal);
        Self {
            projection,
            journal,
            projection_digest,
            journal_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Instance {
    domain: Hash,
    key_sha256: Hash,
}
impl Instance {
    const REHEARSAL: Self = Self {
        domain: DOMAIN,
        key_sha256: VK_SHA256,
    };
}

/// The canonical contract gate: the retained rehearsal key/domain are the only
/// instance this public type accepts. Alternate experiments use a distinct type.
pub struct Gate(ConfiguredResearchGate);
impl Gate {
    pub fn new() -> Result<Self> {
        Ok(Self(ConfiguredResearchGate::rehearsal()?))
    }
    pub fn assemble(&self, bundles: [Bundle; 2]) -> Result<Witness> {
        self.0.assemble(bundles)
    }
    pub fn verify_inner_bundle(&self, bundle: &Bundle) -> Result<()> {
        self.0.verify_inner_bundle(bundle)
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<VerifiedBinding> {
        self.0.verify(bytes)
    }
    pub fn check_publication(&self, projection: &[u8], journal: &[u8]) -> Result<()> {
        self.0.check_publication(projection, journal)
    }
}

/// Separate experimental-instance verifier. A positive result here cannot
/// qualify the original rehearsal's missing compatible pair. The default CLI
/// never constructs this type with caller-selected configuration.
pub struct ConfiguredResearchGate {
    verifier: Verifier,
    instance: Instance,
}
impl ConfiguredResearchGate {
    fn rehearsal() -> Result<Self> {
        // There is intentionally no caller-supplied key/domain constructor.
        Self::with_trusted_key(DOMAIN, VK_BYTES, VK_SHA256)
    }
    /// Explicit TRUSTED caller configuration for a separately identified local
    /// research instance. The expected digest/domain must come from the fixture
    /// contract independently of the untrusted witness. This is not the default
    /// rehearsal contract; the CLI never accepts a key/domain argument.
    /// No key or expected identity is read from the 2,846-byte prover input.
    pub fn with_trusted_key(domain: Hash, bytes: &[u8], expected_sha256: Hash) -> Result<Self> {
        let vk = checked_key(bytes, expected_sha256)?;
        Ok(Self {
            verifier: Verifier::from_validated_program_key(&vk, expected_sha256),
            instance: Instance {
                domain,
                key_sha256: expected_sha256,
            },
        })
    }
    pub fn assemble(&self, bundles: [Bundle; 2]) -> Result<Witness> {
        assemble_for(bundles, self.instance)
    }
    /// Narrow single-bundle verifier for diagnostics. Success does not satisfy
    /// the two-bundle relation and returns no aggregate result or journal.
    pub fn verify_inner_bundle(&self, bundle: &Bundle) -> Result<()> {
        bundle.check_profile(self.instance.domain)?;
        checked_proof(&bundle.proof)?;
        self.verifier
            .verify_inputs(&bundle.proof, &public_inputs(&bundle.authorization))
            .map_err(Error::InnerProof)
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<VerifiedBinding> {
        let witness = Witness::parse_for(bytes, self.instance)?;
        witness.check_binding()?;
        for bundle in &witness.bundles {
            self.verify_inner_bundle(bundle)?;
        }
        Ok(VerifiedBinding::from_projection(
            witness.projection.bytes()?,
        ))
    }
    pub fn check_publication(&self, projection: &[u8], journal: &[u8]) -> Result<()> {
        check_publication_for(projection, journal, self.instance)
    }
}

/// Check complete public bytes against journal bytes independently of the
/// collector. This is publication consistency, NOT receipt/proof verification.
pub fn check_publication(projection: &[u8], journal: &[u8]) -> Result<()> {
    check_publication_for(projection, journal, Instance::REHEARSAL)
}
fn check_publication_for(projection: &[u8], journal: &[u8], instance: Instance) -> Result<()> {
    let parsed = Projection::parse_for(projection, instance)?;
    if journal.len() != JOURNAL_LEN {
        return Err(Error::Length("journal"));
    }
    let expected = VerifiedBinding::from_projection(parsed.bytes()?);
    if journal != expected.journal {
        return Err(Error::Publication);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hex(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    const ROW6: &[u8] =
        include_bytes!("../pins/rehearsal-row-6.bundle.bin");
    const ROW8: &[u8] =
        include_bytes!("../pins/rehearsal-row-8.bundle.bin");

    // Deliberately invalid zero proof bytes. These fixtures exercise ONLY
    // structural binding, not proof acceptance. Gate rejects them below.
    fn structural_bundles() -> [Bundle; 2] {
        std::array::from_fn(|i| {
            let mut a = [0; AUTH_LEN];
            a[..8].copy_from_slice(b"KPICU06\0");
            a[8..40].copy_from_slice(&DOMAIN);
            a[40..44].copy_from_slice(&0x04030201u32.to_le_bytes());
            a[44..76].copy_from_slice(&std::array::from_fn::<_, 32, _>(|j| j as u8));
            for slot in 0..2 {
                a[76 + 32 * slot..108 + 32 * slot].fill([[0x40, 0x10], [0x30, 0x20]][i][slot]);
                a[140 + 32 * slot..172 + 32 * slot].fill([[0x60, 0x20], [0x40, 0x10]][i][slot]);
            }
            a[204] = 1;
            let fee = [0x0102030405060708u64, 17][i];
            a[213..221].copy_from_slice(&fee.to_le_bytes());
            let ciphertexts =
                std::array::from_fn(|slot| [0xa0 + 0x20 * i as u8 + 0x10 * slot as u8; CIPHER_LEN]);
            let ordered: Vec<u8> = ciphertexts.iter().flatten().copied().collect();
            a[345..377].copy_from_slice(&sha256(&ordered));
            Bundle {
                authorization: a,
                proof: [0; PROOF_LEN],
                ciphertexts,
            }
        })
    }
    fn structural_witness() -> Witness {
        assemble(structural_bundles()).unwrap()
    }
    fn pinned_row(bytes: &[u8], expected_hash: &str) -> Bundle {
        assert_eq!(test_hex(sha256(bytes)), expected_hash);
        Bundle::parse(bytes).unwrap()
    }
    fn row6() -> Bundle {
        pinned_row(
            ROW6,
            "10d201fc946f983e263277413e87c1e1bc6b7342642e13f82ec2a5814e81319e",
        )
    }
    fn row8() -> Bundle {
        pinned_row(
            ROW8,
            "d7096ebf3468a28a5c9860c1dca07fe65acfc6c5b15bd1908e0acd639fad770c",
        )
    }

    #[test]
    fn independent_public_encoding_golden_and_exact_wire_boundaries() {
        let w = structural_witness();
        assert_eq!(w.nullifier_permutation, [3, 0, 2, 1]);
        assert_eq!(w.output_permutation, [3, 1, 2, 0]);
        let p = w.projection.bytes().unwrap();
        // Expected hashes independently computed with Python hashlib and the
        // literal contract concatenation; no Rust serializer produced them.
        assert_eq!(
            test_hex(sha256(&p)),
            "2927ea698f9bfbe2ee19e356b66388ffee9db365c1c347f880e87022d3d094f7"
        );
        assert_eq!(&p[..12], b"KPI2V6P1\x01\x00\x02\x00");
        assert_eq!(&p[12..44], &DOMAIN);
        assert_eq!(&p[44..76], &VK_SHA256);
        assert_eq!(&p[76..92], &(0x0102030405060708u128 + 17).to_le_bytes());
        for (i, nf) in [0x10, 0x20, 0x30, 0x40].iter().enumerate() {
            assert_eq!(&p[92 + 32 * i..124 + 32 * i], &[*nf; 32]);
        }
        assert_eq!(&p[220..252], &[0x10; 32]);
        assert_eq!(&p[252..437], &[0xd0; CIPHER_LEN]);
        assert_eq!(&p[1056..1088], &[0xa0; 32]);
        let result = VerifiedBinding::from_projection(p);
        assert_eq!(
            test_hex(result.journal),
            "4b50493256364a3101002927ea698f9bfbe2ee19e356b66388ffee9db365c1c347f880e87022d3d094f7"
        );
        assert_eq!(
            test_hex(result.journal_digest),
            "dcd533b74e82226174e6e0386d7549168866f48c8a4d71915a5e43269eb35ebc"
        );
        assert_ne!(result.projection_digest, result.journal_digest);
        let input = w.bytes().unwrap();
        assert_eq!(&input[1088..1465], &w.bundles[0].authorization);
        assert_eq!(&input[1465..1593], &w.bundles[0].proof);
        assert_eq!(&input[1593..1778], &w.bundles[0].ciphertexts[0]);
        assert_eq!(&input[1778..1963], &w.bundles[0].ciphertexts[1]);
        assert_eq!(&input[1963..2340], &w.bundles[1].authorization);
        assert_eq!(&input[2340..2468], &w.bundles[1].proof);
        assert_eq!(&input[2468..2653], &w.bundles[1].ciphertexts[0]);
        assert_eq!(&input[2653..2838], &w.bundles[1].ciphertexts[1]);
        assert_eq!(&input[2838..2842], &[3, 0, 2, 1]);
        assert_eq!(&input[2842..2846], &[3, 1, 2, 0]);
        assert_eq!(Witness::parse(&input).unwrap().bytes().unwrap(), input);
        for length in [0, 42, 1_087, 1_088, 2_845] {
            assert_eq!(
                Witness::parse(&input[..length]).unwrap_err(),
                Error::Length("complete input")
            );
        }
        let mut trailing = input.to_vec();
        trailing.push(0);
        assert_eq!(
            Witness::parse(&trailing).unwrap_err(),
            Error::Length("complete input")
        );
        assert!(Bundle::parse(&ROW6[..874]).is_err());
        assert!(Bundle::parse(&[ROW6, &[0]].concat()).is_err());
    }

    #[test]
    fn all_forced_zero_bytes_magic_domain_and_modes_are_checked() {
        for offset in (205..213).chain(221..345) {
            let mut b = structural_bundles();
            b[0].authorization[offset] = 1;
            assert!(
                matches!(assemble(b), Err(Error::Profile(_))),
                "offset {offset}"
            );
        }
        for offset in 0..40 {
            let mut b = structural_bundles();
            b[1].authorization[offset] ^= 1;
            assert!(
                matches!(assemble(b), Err(Error::Profile(_))),
                "offset {offset}"
            );
        }
        for mode in [0, 2, 3, 255] {
            let mut b = structural_bundles();
            b[0].authorization[204] = mode;
            assert_eq!(assemble(b).unwrap_err(), Error::Profile("SPEND mode"));
        }
    }

    #[test]
    fn common_anchor_and_count_are_independently_required() {
        for offset in 40..76 {
            let mut b = structural_bundles();
            b[1].authorization[offset] ^= 1;
            let expected = if offset < 44 {
                Error::CountMismatch
            } else {
                Error::AnchorMismatch
            };
            assert_eq!(assemble(b).unwrap_err(), expected);
        }
    }

    #[test]
    fn exact_fee_ranges_boundaries_and_public_sum_are_checked() {
        for fee in [1, MAX_SOMPI] {
            let mut b = structural_bundles();
            for bundle in &mut b {
                bundle.authorization[213..221].copy_from_slice(&fee.to_le_bytes());
            }
            let w = assemble(b).unwrap();
            assert_eq!(w.projection.aggregate_fee_sompi, u128::from(fee) * 2);
        }
        for fee in [0, MAX_SOMPI + 1, u64::MAX] {
            let mut b = structural_bundles();
            b[0].authorization[213..221].copy_from_slice(&fee.to_le_bytes());
            assert_eq!(assemble(b).unwrap_err(), Error::Fee);
        }
        let mut w = structural_witness();
        w.projection.aggregate_fee_sompi += 1;
        assert_eq!(
            w.check_binding(),
            Err(Error::PublicBinding("aggregate fee"))
        );
        for sum in [0, 1, u128::from(MAX_SOMPI) * 2 + 1, u128::MAX] {
            w.projection.aggregate_fee_sompi = sum;
            assert_eq!(w.check_binding(), Err(Error::Fee));
        }
    }

    #[test]
    fn all_active_nullifiers_nonzero_and_pairwise_distinct() {
        for k in 0..4 {
            let mut b = structural_bundles();
            b[k / 2].authorization[76 + 32 * (k % 2)..108 + 32 * (k % 2)].fill(0);
            assert_eq!(assemble(b).unwrap_err(), Error::Nullifiers);
            for j in k + 1..4 {
                let mut b = structural_bundles();
                let value = b[k / 2].nullifier(k % 2);
                b[j / 2].authorization[76 + 32 * (j % 2)..108 + 32 * (j % 2)]
                    .copy_from_slice(&value);
                assert_eq!(assemble(b).unwrap_err(), Error::Nullifiers);
            }
        }
    }

    #[test]
    fn commitment_multiplicity_and_complete_record_pairing_are_preserved() {
        let mut b = structural_bundles();
        let cm = b[0].commitment(0);
        b[1].authorization[140..172].copy_from_slice(&cm);
        // Same CM across bundles is allowed, even with a different ciphertext.
        let w = assemble(b.clone()).unwrap();
        w.check_binding().unwrap();
        assert_eq!(
            w.projection
                .outputs
                .iter()
                .filter(|r| r[..32] == cm)
                .count(),
            2
        );
        // Same complete record across bundles is also allowed and retained twice.
        b[1].ciphertexts[0] = b[0].ciphertexts[0];
        b[1].authorization[345..377].copy_from_slice(&sha256(&b[1].ciphertexts.concat()));
        let mut w = assemble(b).unwrap();
        w.check_binding().unwrap();
        assert_ne!(w.output_permutation[0], w.output_permutation[2]);
        let repeated = w.bundles[0].record(0);
        assert_eq!(
            w.projection
                .outputs
                .iter()
                .filter(|r| **r == repeated)
                .count(),
            2
        );
        // Exchange equal indices is valid; reuse of the same index is not.
        w.output_permutation.swap(0, 2);
        w.check_binding().unwrap();
        w.output_permutation[0] = w.output_permutation[2];
        assert_eq!(w.check_binding(), Err(Error::Permutation("outputs")));
        for slot in 0..2 {
            let mut b = structural_bundles();
            b[0].authorization[140 + 32 * slot..172 + 32 * slot].fill(0);
            assert_eq!(assemble(b).unwrap_err(), Error::Commitments);
        }
        let mut b = structural_bundles();
        let cm = b[0].commitment(0);
        b[0].authorization[172..204].copy_from_slice(&cm);
        assert_eq!(assemble(b).unwrap_err(), Error::Commitments);
    }

    #[test]
    fn all_index_vectors_are_bijections_and_mapping_is_not_an_independent_set() {
        let original = structural_witness();
        for encoded in 0..256 {
            let p = std::array::from_fn(|i| ((encoded >> (2 * i)) & 3) as u8);
            let mut w = original.clone();
            w.nullifier_permutation = p;
            let result = w.check_binding();
            assert_eq!(result.is_ok(), p == original.nullifier_permutation);
            let mut w = original.clone();
            w.output_permutation = p;
            assert_eq!(w.check_binding().is_ok(), p == original.output_permutation);
        }
        for value in [4, 5, 128, 255] {
            let mut w = original.clone();
            w.output_permutation[3] = value;
            assert_eq!(w.check_binding(), Err(Error::Permutation("outputs")));
        }
        // Keep both independent CM and ciphertext multisets, but re-pair them.
        let mut w = original;
        let c0: Vec<_> = w.projection.outputs[0][32..].to_vec();
        let c1: Vec<_> = w.projection.outputs[1][32..].to_vec();
        w.projection.outputs[0][32..].copy_from_slice(&c1);
        w.projection.outputs[1][32..].copy_from_slice(&c0);
        assert_eq!(
            w.check_binding(),
            Err(Error::PublicBinding("commitment/ciphertext record"))
        );
    }

    #[test]
    fn original_ciphertext_order_and_unsigned_public_order_are_required() {
        let mut b = structural_bundles();
        b[0].ciphertexts.swap(0, 1);
        assert_eq!(assemble(b).unwrap_err(), Error::CiphertextDigest);
        for k in 0..4 {
            let mut w = structural_witness();
            w.projection.outputs[k][RECORD_LEN - 1] ^= 1;
            assert_eq!(
                w.check_binding(),
                Err(Error::PublicBinding("commitment/ciphertext record"))
            );
        }
        let mut w = structural_witness();
        w.projection.nullifiers.swap(0, 1);
        assert_eq!(w.check_binding(), Err(Error::Nullifiers));
        let mut w = structural_witness();
        w.projection.outputs.swap(0, 1);
        assert_eq!(w.check_binding(), Err(Error::ProjectionOrder));
        let mut b = structural_bundles();
        b[0].authorization[76..108].fill(0x80);
        b[0].authorization[108..140].fill(0x7f);
        let w = assemble(b).unwrap();
        assert_eq!(w.projection.nullifiers[2], [0x7f; 32]);
        assert_eq!(w.projection.nullifiers[3], [0x80; 32]);
    }

    #[test]
    fn publication_requires_complete_projection_and_exact_journal_not_its_hash() {
        let p = structural_witness().projection.bytes().unwrap();
        let result = VerifiedBinding::from_projection(p);
        check_publication(&p, &result.journal).unwrap();
        assert_eq!(
            check_publication(&result.projection_digest, &result.journal),
            Err(Error::Length("public projection"))
        );
        assert_eq!(
            check_publication(&p, &result.journal_digest),
            Err(Error::Length("journal"))
        );
        for i in 0..JOURNAL_LEN {
            let mut j = result.journal;
            j[i] ^= 1;
            assert_eq!(check_publication(&p, &j), Err(Error::Publication));
        }
        for i in 0..76 {
            let mut changed = p;
            changed[i] ^= 1;
            assert_eq!(
                Projection::parse(&changed).unwrap_err(),
                Error::Profile("public projection")
            );
        }
        let mut extra = result.journal.to_vec();
        extra.push(0);
        assert_eq!(check_publication(&p, &extra), Err(Error::Length("journal")));
    }

    #[test]
    fn checked_real_inner_proofs_accept_but_original_pair_prerequisite_is_absent() {
        let gate = Gate::new().unwrap();
        let a = row6();
        let b = row8();
        gate.verify_inner_bundle(&a).unwrap();
        gate.verify_inner_bundle(&b).unwrap();
        assert_eq!(
            assemble([a.clone(), b.clone()]).unwrap_err(),
            Error::CountMismatch
        );
        // Both genuine profile-compliant statements are valid individually,
        // but their private count and anchor differ. No auth/proof is rewritten.
        assert_ne!(&a.authorization[40..44], &b.authorization[40..44]);
        assert_ne!(&a.authorization[44..76], &b.authorization[44..76]);
        assert_eq!(assemble([a.clone(), a]).unwrap_err(), Error::Nullifiers);
    }

    #[test]
    fn altered_real_statement_reaches_typed_cryptographic_rejection() {
        let gate = Gate::new().unwrap();
        let mut a = row6();
        gate.verify_inner_bundle(&a).unwrap();
        a.authorization[40] ^= 1;
        assert_eq!(
            gate.verify_inner_bundle(&a),
            Err(Error::InnerProof("invalid proof"))
        );
        // Explicit expected constants from the previous independently qualified
        // one-v6 input control, not a second copy of our digest conversion.
        let inputs = public_inputs(&row6().authorization);
        assert_eq!(
            inputs,
            [
                Fr::from(272864832706577085329381808629324299780u128),
                Fr::from(233458794052009950193355542024787113152u128)
            ]
        );
    }

    #[test]
    fn malformed_identity_noncanonical_keys_and_proofs_never_accept() {
        let gate = Gate::new().unwrap();
        let mut a = row6();
        for fill in [0, 0xff] {
            a.proof.fill(fill);
            assert!(gate.verify_inner_bundle(&a).is_err());
        }
        let original: Proof<Bn254> = canonical(&row6().proof, "proof").unwrap();
        for point in 0..3 {
            let mut proof = original.clone();
            match point {
                0 => proof.a = Default::default(),
                1 => proof.b = Default::default(),
                _ => proof.c = Default::default(),
            }
            let mut raw = Vec::new();
            proof.serialize_compressed(&mut raw).unwrap();
            assert_eq!(checked_proof(&raw), Err(Error::IdentityPoint("proof")));
        }
        assert!(
            canonical::<Proof<Bn254>>(&[row6().proof.as_slice(), &[0]].concat(), "proof").is_err()
        );
        let raw = VK_BYTES.to_vec();
        checked_key(&raw, VK_SHA256).unwrap();
        let mut changed = raw.clone();
        changed[0] ^= 1;
        assert!(matches!(
            ConfiguredResearchGate::with_trusted_key(DOMAIN, &changed, VK_SHA256),
            Err(Error::FixedKey)
        ));
        assert!(canonical::<VerifyingKey<Bn254>>(
            &[raw.as_slice(), &[0]].concat(),
            "verification key"
        )
        .is_err());
        let mut vk: VerifyingKey<Bn254> = canonical(&raw, "verification key").unwrap();
        vk.alpha_g1 = Default::default();
        let mut identity = Vec::new();
        vk.serialize_compressed(&mut identity).unwrap();
        assert!(matches!(
            ConfiguredResearchGate::with_trusted_key(DOMAIN, &identity, sha256(&identity)),
            Err(Error::IdentityPoint("verification key"))
        ));
        // No synthetic structural fixture can reach an accepted host result.
        assert!(gate.verify(&structural_witness().bytes().unwrap()).is_err());
    }

    #[test]
    fn configured_instance_is_trusted_outside_witness_and_default_remains_exact() {
        let raw = VK_BYTES.to_vec();
        let same = ConfiguredResearchGate::with_trusted_key(DOMAIN, &raw, VK_SHA256).unwrap();
        same.verify_inner_bundle(&row6()).unwrap();
        let other = ConfiguredResearchGate::with_trusted_key([9; 32], &raw, VK_SHA256).unwrap();
        assert_eq!(
            other.verify_inner_bundle(&row6()),
            Err(Error::Profile("domain"))
        );
        let input = structural_witness().bytes().unwrap();
        assert_eq!(
            other.verify(&input).unwrap_err(),
            Error::Profile("public projection")
        );
    }
}
