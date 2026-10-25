//! Separate genuine relations. Public statements are hashed inside the circuit.
//! No action output-subset digest or public note native key exists here.
use crate::{exact_sha256::Sha256Gadget, *};
use ark_bn254::Fr;
use ark_ed_on_bn254::{Fr as Scalar, constraints::EdwardsVar};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    convert::{ToBitsGadget, ToBytesGadget},
    eq::EqGadget,
    fields::fp::FpVar,
    groups::CurveVar,
    uint8::UInt8,
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
};
type B = UInt8<Fr>;
type R<T> = core::result::Result<T, SynthesisError>;
fn digest(bytes: &[B]) -> R<Vec<B>> {
    Ok(Sha256Gadget::digest(bytes)?.0)
}
fn tagged(tag: &[u8; 8], domain: &[B], parts: &[&[B]]) -> R<Vec<B>> {
    let mut b = B::constant_vec(tag);
    b.extend_from_slice(domain);
    for p in parts {
        b.extend_from_slice(p)
    }
    digest(&b)
}
fn bits(bytes: &[B]) -> R<Vec<Boolean<Fr>>> {
    Ok(bytes
        .iter()
        .map(ToBitsGadget::to_bits_le)
        .collect::<R<Vec<_>>>()?
        .concat())
}
fn field(bytes: &[B]) -> R<FpVar<Fr>> {
    if bytes.len() > 16 {
        return Err(SynthesisError::Unsatisfiable);
    }
    Boolean::le_bits_to_fp(&bits(bytes)?)
}
fn bind_public(cs: ConstraintSystemRef<Fr>, statement: &[B], inputs: [Fr; 2]) -> R<()> {
    let d = digest(statement)?;
    for i in 0..2 {
        let p = FpVar::new_input(cs.clone(), || Ok(inputs[i]))?;
        field(&d[i * 16..i * 16 + 16])?.enforce_equal(&p)?
    }
    Ok(())
}
fn range(value: &[B]) -> R<()> {
    bounded_u64(value, NOTE_FLOOR, MAX)
}
fn bounded_u64(value: &[B], minimum: u64, maximum: u64) -> R<()> {
    let b = bits(value)?;
    if b.len() != 64 {
        return Err(SynthesisError::Unsatisfiable);
    }
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(&b, [maximum])?;
    // v>=floor iff the unsigned reverse bitwise complement is <=MAX_u64-floor.
    let complement = b.iter().map(|b| !b).collect::<Vec<_>>();
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(&complement, [u64::MAX - minimum])?;
    Ok(())
}
fn value_cv(cs: ConstraintSystemRef<Fr>, value: &[B], r: &H, expected: &[B]) -> R<()> {
    range(value)?;
    let r = B::new_witness_vec(cs, &r[..])?;
    let rb = bits(&r)?;
    // ALL256 bits are bounded by the subgroup scalar modulus, not BN254 Fr.
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(&rb, (-Scalar::ONE).into_bigint())?;
    let vb = bits(value)?;
    let p = cv::parameters();
    if vb.len() != 64
        || rb.len() != 256
        || p.generators[0].len() != 64
        || p.randomness_generator.len() != 251
    {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut result = EdwardsVar::zero();
    result.precomputed_base_scalar_mul_le(vb.iter().zip(p.generators[0].iter()))?;
    result.precomputed_base_scalar_mul_le(rb[..251].iter().zip(p.randomness_generator.iter()))?;
    result.is_zero()?.enforce_equal(&Boolean::FALSE)?;
    // Canonical full x/y bytes; this also enforces subgroup by fixed-base equality.
    result.to_bytes_le()?.as_slice().enforce_equal(expected)?;
    Ok(())
}
fn note_vars(cs: ConstraintSystemRef<Fr>, domain: &[B], note: &Note) -> R<(Vec<B>, Vec<B>)> {
    let b = B::new_witness_vec(cs, &note.bytes())?;
    let cm = tagged(NOTE_TAG, domain, &[&b])?;
    Ok((b, cm))
}
fn original_nf(domain: &[B], key: &[B], cm: &[B], position: &[B]) -> R<Vec<B>> {
    let mut inner = key
        .iter()
        .map(|b| b ^ B::constant(0x36))
        .collect::<Vec<_>>();
    inner.extend(B::constant_vec(&[0x36; 32]));
    inner.extend(B::constant_vec(NF_TAG));
    inner.extend_from_slice(domain);
    inner.extend_from_slice(cm);
    inner.extend_from_slice(position);
    let inner = digest(&inner)?;
    let mut outer = key
        .iter()
        .map(|b| b ^ B::constant(0x5c))
        .collect::<Vec<_>>();
    outer.extend(B::constant_vec(&[0x5c; 32]));
    outer.extend(inner);
    digest(&outer)
}
#[derive(Clone)]
pub struct SpendCircuit {
    pub statement: SpendStatement,
    pub witness: SpendWitness,
}
#[derive(Clone)]
pub struct OutputCircuit {
    pub statement: OutputStatement,
    pub witness: OutputWitness,
}
#[derive(Clone)]
pub struct ExitCircuit {
    pub statement: ExitStatement,
    pub witness: ExitWitness,
}
impl ConstraintSynthesizer<Fr> for SpendCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R<()> {
        let s = B::new_witness_vec(cs.clone(), &self.statement.bytes())?;
        s[..8].enforce_equal(&B::constant_vec(statements::SPEND_TAG))?;
        s[8..40].enforce_equal(&B::constant_vec(&DOMAIN))?;
        let d = &s[8..40];
        let (n, cm) = note_vars(cs.clone(), d, &self.witness.note)?;
        // Real occupied leaves cannot be the zero/empty marker.
        cm.is_eq(&B::constant_vec(&[0; 32]))?
            .enforce_equal(&Boolean::FALSE)?;
        let owner_secret = B::new_witness_vec(cs.clone(), &self.witness.owner_secret)?;
        let key = B::new_witness_vec(cs.clone(), &self.witness.nullifier_secret)?;
        n[..32].enforce_equal(&tagged(OWNER_TAG, d, &[&owner_secret, &n[32..64]])?)?;
        n[104..136].enforce_equal(&tagged(KEY_TAG, d, &[&key])?)?;
        value_cv(cs.clone(), &n[64..72], &self.witness.blinding, &s[104..168])?;
        let pos = B::new_witness_vec(cs.clone(), &self.witness.position.to_le_bytes())?;
        // Essential NF uniqueness: membership must not ignore high position bits.
        pos[2..].enforce_equal(&B::constant_vec(&[0; 2]))?;
        let pb = bits(&pos)?;
        let mut root = cm.clone();
        for (level, sibling) in self.witness.path.iter().enumerate() {
            let sibling = B::new_witness_vec(cs.clone(), sibling)?;
            let left = sibling
                .iter()
                .zip(&root)
                .map(|(sib, r)| pb[level].select(sib, r))
                .collect::<R<Vec<_>>>()?;
            let right = sibling
                .iter()
                .zip(&root)
                .map(|(sib, r)| pb[level].select(r, sib))
                .collect::<R<Vec<_>>>()?;
            root = tagged(CM_NODE, &[], &[&left, &right])?;
        }
        root.as_slice().enforce_equal(&s[40..72])?;
        original_nf(d, &key, &cm, &pos)?
            .as_slice()
            .enforce_equal(&s[72..104])?;
        s[72..104]
            .is_eq(&B::constant_vec(&[0; 32]))?
            .enforce_equal(&Boolean::FALSE)?;
        // All bytes, including the effects digest, constrain these TWO inputs.
        bind_public(cs, &s, self.statement.public_inputs())
    }
}
impl ConstraintSynthesizer<Fr> for OutputCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R<()> {
        let s = B::new_witness_vec(cs.clone(), &self.statement.bytes())?;
        s[..8].enforce_equal(&B::constant_vec(statements::OUTPUT_TAG))?;
        s[8..40].enforce_equal(&B::constant_vec(&DOMAIN))?;
        let (n, cm) = note_vars(cs.clone(), &s[8..40], &self.witness.note)?;
        cm.as_slice().enforce_equal(&s[40..72])?;
        value_cv(cs.clone(), &n[64..72], &self.witness.blinding, &s[72..136])?;
        // CFH is bound by the statement hash; encryption correctness is recipient-owned.
        bind_public(cs, &s, self.statement.public_inputs())
    }
}
impl ConstraintSynthesizer<Fr> for ExitCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R<()> {
        let s = B::new_witness_vec(cs.clone(), &self.statement.bytes())?;
        s[..8].enforce_equal(&B::constant_vec(statements::EXIT_TAG))?;
        s[8..40].enforce_equal(&B::constant_vec(&DOMAIN))?;
        let d = &s[8..40];
        let (n, cm) = note_vars(cs.clone(), d, &self.witness.note)?;
        cm.is_eq(&B::constant_vec(&[0; 32]))?
            .enforce_equal(&Boolean::FALSE)?;
        let owner_secret = B::new_witness_vec(cs.clone(), &self.witness.owner_secret)?;
        let key = B::new_witness_vec(cs.clone(), &self.witness.nullifier_secret)?;
        n[..32].enforce_equal(&tagged(OWNER_TAG, d, &[&owner_secret, &n[32..64]])?)?;
        n[104..136].enforce_equal(&tagged(KEY_TAG, d, &[&key])?)?;
        range(&n[64..72])?;
        bounded_u64(&s[136..144], PAYOUT_FLOOR, MAX)?;
        bounded_u64(&s[144..152], 1, MAX)?;
        // Every term is a bounded u64 and their sum is below 2^65, so this
        // equality is exact integer conservation, never a field-wrap equality.
        field(&n[64..72])?.enforce_equal(&(field(&s[136..144])? + field(&s[144..152])?))?;
        let pos = B::new_witness_vec(cs.clone(), &self.witness.position.to_le_bytes())?;
        pos[2..].enforce_equal(&B::constant_vec(&[0; 2]))?;
        let pb = bits(&pos)?;
        let mut root = cm.clone();
        for (level, sibling) in self.witness.path.iter().enumerate() {
            let sibling = B::new_witness_vec(cs.clone(), sibling)?;
            let left = sibling
                .iter()
                .zip(&root)
                .map(|(sib, r)| pb[level].select(sib, r))
                .collect::<R<Vec<_>>>()?;
            let right = sibling
                .iter()
                .zip(&root)
                .map(|(sib, r)| pb[level].select(r, sib))
                .collect::<R<Vec<_>>>()?;
            root = tagged(CM_NODE, &[], &[&left, &right])?;
        }
        root.as_slice().enforce_equal(&s[40..72])?;
        original_nf(d, &key, &cm, &pos)?
            .as_slice()
            .enforce_equal(&s[72..104])?;
        s[72..104]
            .is_eq(&B::constant_vec(&[0; 32]))?
            .enforce_equal(&Boolean::FALSE)?;
        // Effects authorizes current state, NF update, reserve, recipient and
        // fee through native reconstruction. This circuit does not replace
        // native current-state and authenticated indexed-NF insertion checks.
        bind_public(cs, &s, self.statement.public_inputs())
    }
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Shape {
    pub constraints: usize,
    pub witnesses: usize,
    pub instances: usize,
    pub matrix_sha256: String,
}
pub fn check<C: ConstraintSynthesizer<Fr>>(c: C) -> crate::Result<(Shape, bool)> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    c.generate_constraints(cs.clone())
        .map_err(|_| Error::Synthesis)?;
    cs.finalize();
    let sat = cs.is_satisfied().map_err(|_| Error::Synthesis)?;
    let shape = Shape {
        constraints: cs.num_constraints(),
        witnesses: cs.num_witness_variables(),
        instances: cs.num_instance_variables(),
        matrix_sha256: matrix_fingerprint(&cs).map_err(|_| Error::Synthesis)?,
    };
    Ok((shape, sat))
}
pub fn matrix_fingerprint(cs: &ConstraintSystemRef<Fr>) -> R<String> {
    use ark_serialize::CanonicalSerialize;
    use sha2::{Digest, Sha256};
    fn count(h: &mut Sha256, n: usize) {
        h.update((n as u64).to_le_bytes())
    }
    let mut h = Sha256::new();
    h.update(b"KPX8/GR1CS-MATRIX/v1\0");
    for n in [
        cs.num_constraints(),
        cs.num_instance_variables(),
        cs.num_witness_variables(),
    ] {
        count(&mut h, n)
    }
    let matrices = cs.to_matrices()?;
    count(&mut h, matrices.len());
    for (label, group) in matrices {
        count(&mut h, label.len());
        h.update(label.as_bytes());
        count(&mut h, group.len());
        for matrix in group {
            count(&mut h, matrix.len());
            for row in matrix {
                count(&mut h, row.len());
                for (coefficient, index) in row {
                    let mut b = [0; 32];
                    coefficient
                        .serialize_compressed(b.as_mut_slice())
                        .map_err(|_| SynthesisError::Unsatisfiable)?;
                    h.update(b);
                    count(&mut h, index)
                }
            }
        }
    }
    Ok(hex::encode(h.finalize()))
}
/// PUBLIC SYNTHETIC fixtures only, never actual owner data or financial authority.
pub fn fixture() -> (SpendCircuit, OutputCircuit) {
    let s = [0x31; 32];
    let k = [0x71; 32];
    let incoming = [0x22; 32];
    let note = Note {
        owner: owner(&DOMAIN, &s, &incoming),
        incoming,
        value: 2_000_000_000,
        rho: [0x44; 32],
        key_commitment: key_commitment(&DOMAIN, &k),
        native_pk: [0x55; 32],
    };
    let mut r = [0; 32];
    r[0] = 7;
    let cv = value_commitment(note.value, &r).expect("synthetic CV");
    let path = [[9; 32]; 16];
    let cm = note.commitment(&DOMAIN);
    let anchor = membership_root(&cm, 3, &path).unwrap();
    (
        SpendCircuit {
            statement: SpendStatement {
                domain: DOMAIN,
                anchor,
                nf: nullifier(&DOMAIN, &k, &cm, 3),
                cv,
                effects_digest: [0x99; 32],
            },
            witness: SpendWitness {
                note: note.clone(),
                owner_secret: s,
                nullifier_secret: k,
                position: 3,
                path,
                blinding: r,
            },
        },
        OutputCircuit {
            statement: OutputStatement {
                domain: DOMAIN,
                cm,
                cv,
                cf_hash: hash(&[&[0xab; 264]]),
            },
            witness: OutputWitness { note, blinding: r },
        },
    )
}
/// Public synthetic full-note exit, never financial owner data or authority.
pub fn exit_fixture() -> ExitCircuit {
    let (spend, _) = fixture();
    ExitCircuit {
        statement: ExitStatement {
            domain: DOMAIN,
            anchor: spend.statement.anchor,
            nf: spend.statement.nf,
            effects_digest: [0x98; 32],
            payout: spend.witness.note.value - 20_000_000,
            fee: 20_000_000,
        },
        witness: ExitWitness {
            note: spend.witness.note,
            owner_secret: spend.witness.owner_secret,
            nullifier_secret: spend.witness.nullifier_secret,
            position: spend.witness.position,
            path: spend.witness.path,
        },
    }
}
