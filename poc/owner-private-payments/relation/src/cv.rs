//! Native value commitments and canonical Baby-Jubjub wire encodings.
//! The public Pedersen transcript is never Groth16 setup entropy. Its unknown
//! discrete-log relation remains an assumption about the pinned sampler/RNG.
use crate::{CV, Error, H, MAX, NOTE_FLOOR, Result, hash};
use ark_crypto_primitives::commitment::{
    CommitmentScheme,
    pedersen::{Commitment, Parameters, Randomness, Window},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as BabyFr};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::OnceLock;

pub const GENERATOR_SEED_LABEL: &[u8] =
    b"KPI owner-private payments v1 / transparent Pedersen parameters / BN254 BabyJubjub";
pub const SCALAR_MODULUS_DECIMAL: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

#[derive(Clone)]
pub struct ValueWindow;

impl Window for ValueWindow {
    const WINDOW_SIZE: usize = 64;
    const NUM_WINDOWS: usize = 1;
}

pub type Pedersen = Commitment<EdwardsProjective, ValueWindow>;

/// Canonical uncompressed coordinates, x32LE followed by y32LE.
pub fn point_bytes(point: &EdwardsAffine) -> CV {
    let mut bytes = [0; 64];
    point
        .serialize_uncompressed(&mut bytes[..])
        .expect("fixed public point encoding length");
    bytes
}

/// Decode an individual CV, including curve/subgroup and identity checks.
pub fn point_from_bytes(bytes: &[u8]) -> Result<EdwardsAffine> {
    if bytes.len() != 64 {
        return Err(Error::Length);
    }
    let mut reader = bytes;
    // Checked arkworks deserialization validates both curve and prime subgroup.
    let point =
        EdwardsAffine::deserialize_uncompressed(&mut reader).map_err(|_| Error::Encoding)?;
    if !reader.is_empty() || point_bytes(&point).as_slice() != bytes {
        return Err(Error::Encoding);
    }
    if point.is_zero() {
        return Err(Error::Identity);
    }
    Ok(point)
}

pub fn scalar_bytes(scalar: &BabyFr) -> H {
    let mut bytes = [0; 32];
    scalar
        .serialize_uncompressed(&mut bytes[..])
        .expect("fixed scalar encoding length");
    bytes
}

/// Exact canonical subgroup scalar, including zero. Never reduce wire bytes.
pub fn scalar_from_bytes(bytes: &[u8]) -> Result<BabyFr> {
    if bytes.len() != 32 {
        return Err(Error::Length);
    }
    let mut reader = bytes;
    let scalar = BabyFr::deserialize_uncompressed(&mut reader).map_err(|_| Error::Encoding)?;
    if !reader.is_empty() || scalar_bytes(&scalar).as_slice() != bytes {
        return Err(Error::Encoding);
    }
    Ok(scalar)
}

fn validate_parameters(parameters: &Parameters<EdwardsProjective>) -> Result<()> {
    if parameters.randomness_generator.len() != 251
        || parameters.generators.len() != 1
        || parameters.generators[0].len() != 64
        || BabyFr::MODULUS_BIT_SIZE != 251
    {
        return Err(Error::Parameters);
    }
    let r = parameters.randomness_generator[0];
    let v = parameters.generators[0][0];
    if r.is_zero() || v.is_zero() || v == r || v == -r {
        return Err(Error::Parameters);
    }
    r.into_affine().check().map_err(|_| Error::Parameters)?;
    v.into_affine().check().map_err(|_| Error::Parameters)?;
    // Shape and exact doubling relations also protect the circuit's power table
    // contract. Once the first point is checked, its doubles remain subgroup.
    for table in [&parameters.randomness_generator, &parameters.generators[0]] {
        for pair in table.windows(2) {
            if pair[1] != pair[0] + pair[0] {
                return Err(Error::Parameters);
            }
        }
    }
    Ok(())
}

fn derive_parameters() -> Result<Parameters<EdwardsProjective>> {
    let mut rng = ChaCha20Rng::from_seed(hash(&[GENERATOR_SEED_LABEL]));
    // Stock setup samples the R table first, followed by the one V table.
    // Never retry with another seed, or replace a rejected base with a chosen one.
    let parameters = Pedersen::setup(&mut rng).map_err(|_| Error::Parameters)?;
    validate_parameters(&parameters)?;
    Ok(parameters)
}

pub fn parameters() -> &'static Parameters<EdwardsProjective> {
    static PARAMETERS: OnceLock<Parameters<EdwardsProjective>> = OnceLock::new();
    PARAMETERS.get_or_init(|| {
        // A frozen public transcript failure must halt; it cannot be repaired by
        // retuning generators. This message contains no private input or error.
        derive_parameters().expect("fixed public Pedersen parameters rejected")
    })
}

/// Returns (V, R), even though stock setup draws R before V.
pub fn generators_bytes() -> (CV, CV) {
    let parameters = parameters();
    (
        point_bytes(&parameters.generators[0][0].into_affine()),
        point_bytes(&parameters.randomness_generator[0].into_affine()),
    )
}

pub fn parameter_powers_digest() -> H {
    let parameters = parameters();
    let mut wire = Vec::with_capacity(8 + 4 + 251 * 64 + 4 + 64 * 64);
    wire.extend_from_slice(b"KPX7CV01");
    for table in [&parameters.randomness_generator, &parameters.generators[0]] {
        wire.extend_from_slice(&(table.len() as u32).to_le_bytes());
        for point in table {
            wire.extend_from_slice(&point_bytes(&point.into_affine()));
        }
    }
    hash(&[&wire])
}

pub fn value_commitment(value: u64, blinding: &H) -> Result<CV> {
    if !(NOTE_FLOOR..=MAX).contains(&value) {
        return Err(Error::Range);
    }
    let scalar = scalar_from_bytes(blinding)?;
    let point = Pedersen::commit(parameters(), &value.to_le_bytes(), &Randomness(scalar))
        .map_err(|_| Error::Parameters)?;
    if point.is_zero() {
        return Err(Error::Identity);
    }
    Ok(point_bytes(&point))
}

/// Group conservation only: the caller must separately verify the financial
/// proofs, integer ranges and state/NF rules. Individual CVs cannot be identity;
/// aggregate differences and canonical Delta=0 are valid.
pub fn check_balance(inputs: &[CV], outputs: &[CV], fee: u64, delta: &H) -> Result<bool> {
    if inputs.len() > 64 || outputs.len() > 64 || fee > MAX {
        return Err(Error::Range);
    }
    let scalar = scalar_from_bytes(delta)?;
    let parameters = parameters();
    let mut difference = EdwardsProjective::zero();
    for bytes in inputs {
        difference += point_from_bytes(bytes)?.into_group();
    }
    for bytes in outputs {
        difference -= point_from_bytes(bytes)?.into_group();
    }
    difference -= parameters.generators[0][0] * BabyFr::from(fee);
    Ok(difference == parameters.randomness_generator[0] * scalar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AdditiveGroup;
    use ark_ed_on_bn254::Fq;
    use ark_ff::{BigInteger, Field};

    fn scalar(value: u64) -> H {
        scalar_bytes(&BabyFr::from(value))
    }

    #[test]
    fn frozen_seed_and_stock_table_shape_are_exact() {
        assert_eq!(
            hash(&[GENERATOR_SEED_LABEL]),
            [
                0xbc, 0x05, 0xb2, 0x1a, 0x63, 0x58, 0x68, 0xb7, 0x72, 0xc2, 0x07, 0xe2, 0x66, 0xb1,
                0xbb, 0x54, 0x43, 0xee, 0x2d, 0xdd, 0x5d, 0xe3, 0xb1, 0x08, 0xb0, 0x22, 0x7c, 0x14,
                0xfc, 0x79, 0x5c, 0x87,
            ]
        );
        assert_eq!(parameters().randomness_generator.len(), 251);
        assert_eq!(parameters().generators.len(), 1);
        assert_eq!(parameters().generators[0].len(), 64);
        assert!(validate_parameters(parameters()).is_ok());
        let (v, r) = generators_bytes();
        assert_ne!(v, r);
        assert_ne!(
            point_from_bytes(&v).unwrap(),
            -point_from_bytes(&r).unwrap()
        );
    }

    #[test]
    fn invalid_base_or_power_table_is_not_retuned() {
        let mut bad = parameters().clone();
        bad.randomness_generator[0] = EdwardsProjective::zero();
        assert!(matches!(validate_parameters(&bad), Err(Error::Parameters)));
        let mut bad = parameters().clone();
        bad.generators[0][0] = bad.randomness_generator[0];
        assert!(matches!(validate_parameters(&bad), Err(Error::Parameters)));
        let mut bad = parameters().clone();
        bad.generators[0][0] = -bad.randomness_generator[0];
        assert!(matches!(validate_parameters(&bad), Err(Error::Parameters)));
        let mut bad = parameters().clone();
        bad.generators[0][10] = bad.generators[0][9];
        assert!(matches!(validate_parameters(&bad), Err(Error::Parameters)));
        let mut bad = parameters().clone();
        bad.randomness_generator.pop();
        assert!(matches!(validate_parameters(&bad), Err(Error::Parameters)));
    }

    #[test]
    fn scalar_wire_is_canonical_and_zero_is_allowed() {
        for value in [BabyFr::ZERO, BabyFr::ONE, -BabyFr::ONE] {
            assert_eq!(scalar_from_bytes(&scalar_bytes(&value)).unwrap(), value);
        }
        for bad in [vec![], vec![0; 31], vec![0; 33]] {
            assert!(matches!(scalar_from_bytes(&bad), Err(Error::Length)));
        }
        let modulus = BabyFr::MODULUS.to_bytes_le();
        assert!(matches!(scalar_from_bytes(&modulus), Err(Error::Encoding)));
        assert!(matches!(
            scalar_from_bytes(&[0xff; 32]),
            Err(Error::Encoding)
        ));
        let mut high_bit = [0; 32];
        high_bit[31] = 0x08;
        assert!(matches!(scalar_from_bytes(&high_bit), Err(Error::Encoding)));
    }

    #[test]
    fn point_wire_rejects_noncanonical_offcurve_torsion_and_identity() {
        for point in [generators_bytes().0, generators_bytes().1] {
            assert_eq!(point_bytes(&point_from_bytes(&point).unwrap()), point);
        }
        for bad in [vec![], vec![0; 63], vec![0; 65]] {
            assert!(matches!(point_from_bytes(&bad), Err(Error::Length)));
        }
        let identity = point_bytes(&EdwardsAffine::zero());
        assert!(matches!(point_from_bytes(&identity), Err(Error::Identity)));
        let torsion = EdwardsAffine::new_unchecked(Fq::ZERO, -Fq::ONE);
        assert!(matches!(
            point_from_bytes(&point_bytes(&torsion)),
            Err(Error::Encoding)
        ));
        assert!(matches!(point_from_bytes(&[0; 64]), Err(Error::Encoding)));
        let mut noncanonical = generators_bytes().0;
        noncanonical[..32].copy_from_slice(&Fq::MODULUS.to_bytes_le());
        assert!(matches!(
            point_from_bytes(&noncanonical),
            Err(Error::Encoding)
        ));
    }

    #[test]
    fn stock_commitment_matches_value_and_blinding_equation_at_boundaries() {
        let parameters = parameters();
        for value in [NOTE_FLOOR, MAX] {
            for r in [BabyFr::ZERO, BabyFr::ONE, -BabyFr::ONE] {
                let cv = value_commitment(value, &scalar_bytes(&r)).unwrap();
                let expected = parameters.generators[0][0] * BabyFr::from(value)
                    + parameters.randomness_generator[0] * r;
                assert_eq!(point_from_bytes(&cv).unwrap().into_group(), expected);
            }
        }
        for value in [0, NOTE_FLOOR - 1, MAX + 1, u64::MAX] {
            assert!(matches!(
                value_commitment(value, &scalar(1)),
                Err(Error::Range)
            ));
        }
        assert!(value_commitment(NOTE_FLOOR, &[0xff; 32]).is_err());
    }

    #[test]
    fn balance_binds_values_fee_and_global_blinding() {
        let fee = 123;
        let inputs = [value_commitment(3 * NOTE_FLOOR + fee, &scalar(9)).unwrap()];
        let outputs = [
            value_commitment(NOTE_FLOOR, &scalar(2)).unwrap(),
            value_commitment(2 * NOTE_FLOOR, &scalar(3)).unwrap(),
        ];
        assert!(check_balance(&inputs, &outputs, fee, &scalar(4)).unwrap());
        assert!(!check_balance(&inputs, &outputs, fee, &scalar(5)).unwrap());
        assert!(!check_balance(&inputs, &outputs, fee + 1, &scalar(4)).unwrap());
        let mut changed = outputs;
        changed[0] = value_commitment(NOTE_FLOOR + 1, &scalar(2)).unwrap();
        assert!(!check_balance(&inputs, &changed, fee, &scalar(4)).unwrap());
    }

    #[test]
    fn balance_allows_identity_aggregate_but_not_identity_components() {
        let cv = value_commitment(NOTE_FLOOR, &scalar(0)).unwrap();
        assert!(check_balance(&[cv], &[cv], 0, &scalar(0)).unwrap());
        assert!(check_balance(&[], &[], 0, &scalar(0)).unwrap());
        assert!(!check_balance(&[], &[], 0, &scalar(1)).unwrap());
        let identity = point_bytes(&EdwardsAffine::zero());
        assert!(matches!(
            check_balance(&[identity], &[], 0, &scalar(0)),
            Err(Error::Identity)
        ));
        assert!(matches!(
            check_balance(&[], &[identity], 0, &scalar(0)),
            Err(Error::Identity)
        ));
    }

    #[test]
    fn balance_rejects_oversized_counts_fee_and_malformed_scalars_or_points() {
        let cv = value_commitment(NOTE_FLOOR, &scalar(1)).unwrap();
        assert!(check_balance(&[cv; 64], &[cv; 64], 0, &scalar(0)).unwrap());
        assert!(matches!(
            check_balance(&[cv; 65], &[], 0, &scalar(0)),
            Err(Error::Range)
        ));
        assert!(matches!(
            check_balance(&[], &[cv; 65], 0, &scalar(0)),
            Err(Error::Range)
        ));
        assert!(matches!(
            check_balance(&[], &[], MAX + 1, &scalar(0)),
            Err(Error::Range)
        ));
        assert!(matches!(
            check_balance(&[], &[], 0, &[0xff; 32]),
            Err(Error::Encoding)
        ));
        assert!(matches!(
            check_balance(&[[0; 64]], &[], 0, &scalar(0)),
            Err(Error::Encoding)
        ));
    }
}
