//! Private relation only. Native code authenticates current NF updates, empty CM
//! appends and real transaction context; no host verdict is accepted as a witness.
use crate::*;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar,
    uint8::UInt8, uint64::UInt64,
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
type B = UInt8<Fr>;
type Flag = Boolean<Fr>;
type R<T> = std::result::Result<T, SynthesisError>;

#[derive(Clone, Debug)]
pub struct InputWitness {
    pub real: bool,
    pub note: Note,
    pub owner_secret: H,
    pub nullifier_secret: H,
    pub position: u32,
    pub path: [H; CM_DEPTH],
    pub dummy_key: H,
    pub dummy_seed: H,
}
impl InputWitness {
    pub fn padding<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> Self {
        let mut key = [0; 32];
        let mut seed = [0; 32];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut seed);
        Self {
            real: false,
            note: Note::zero(),
            owner_secret: [0; 32],
            nullifier_secret: [0; 32],
            position: 0,
            path: [[0; 32]; CM_DEPTH],
            dummy_key: key,
            dummy_seed: seed,
        }
    }
}
#[derive(Clone, Debug)]
pub struct TransferCircuit {
    pub authorization: Authorization,
    pub inputs: [InputWitness; 2],
    pub outputs: [Note; 2],
}
#[derive(Clone, Debug)]
pub struct ConstraintStats {
    pub constraints: usize,
    pub instance_variables: usize,
    pub witness_variables: usize,
    pub satisfied: bool,
}

/// This conversion is used only for u32/u64 and the two128-bit digest limbs.
/// A full256-bit digest must never pass through field reduction.
fn field(bytes: &[B]) -> R<FpVar<Fr>> {
    if bytes.len() > 16 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let bits = bytes
        .iter()
        .map(ToBitsGadget::to_bits_le)
        .collect::<R<Vec<_>>>()?
        .concat();
    Boolean::le_bits_to_fp(&bits)
}
fn hash_g(b: &[B]) -> R<Vec<B>> {
    Ok(Sha256Gadget::digest(b)?.0)
}
fn digest(tag: &[u8; 8], d: &[B], parts: &[&[B]]) -> R<Vec<B>> {
    let mut b = B::constant_vec(tag);
    b.extend_from_slice(d);
    for p in parts {
        b.extend_from_slice(p)
    }
    hash_g(&b)
}
fn hmac_g(key: &[B], message: &[B]) -> R<Vec<B>> {
    if key.len() != 32 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut padded = key.to_vec();
    padded.extend(B::constant_vec(&[0; 32]));
    let mut inner = padded
        .iter()
        .map(|b| b ^ B::constant(0x36))
        .collect::<Vec<_>>();
    inner.extend_from_slice(message);
    let mut outer = padded
        .iter()
        .map(|b| b ^ B::constant(0x5c))
        .collect::<Vec<_>>();
    outer.extend(hash_g(&inner)?);
    hash_g(&outer)
}
fn slack(cs: ConstraintSystemRef<Fr>, value: u64) -> R<FpVar<Fr>> {
    let s = UInt64::new_witness(cs, || Ok(value))?;
    Boolean::le_bits_to_fp(&s.to_bits_le()?)
}
fn bounds(
    cs: ConstraintSystemRef<Fr>,
    bytes: &[B],
    value: u64,
    min: u64,
    max: u64,
    active: &Flag,
) -> R<()> {
    let lo = slack(cs.clone(), value.saturating_sub(min))?;
    let hi = slack(cs, max.saturating_sub(value))?;
    let v = field(bytes)?;
    v.conditional_enforce_equal(&(lo + Fr::from(min)), active)?;
    (v + hi).conditional_enforce_equal(&FpVar::Constant(Fr::from(max)), active)
}
struct NoteVars {
    owner: Vec<B>,
    incoming: Vec<B>,
    value: Vec<B>,
    rho: Vec<B>,
    key: Vec<B>,
    pk: Vec<B>,
    cm: Vec<B>,
}
fn note(cs: ConstraintSystemRef<Fr>, d: &[B], n: &Note) -> R<NoteVars> {
    let owner = B::new_witness_vec(cs.clone(), &n.owner)?;
    let incoming = B::new_witness_vec(cs.clone(), &n.incoming)?;
    let value = B::new_witness_vec(cs.clone(), &n.value.to_le_bytes())?;
    let rho = B::new_witness_vec(cs.clone(), &n.rho)?;
    let key = B::new_witness_vec(cs.clone(), &n.key_commitment)?;
    let pk = B::new_witness_vec(cs, &n.native_pk)?;
    let cm = digest(NOTE_TAG, d, &[&owner, &incoming, &value, &rho, &key, &pk])?;
    Ok(NoteVars {
        owner,
        incoming,
        value,
        rho,
        key,
        pk,
        cm,
    })
}
impl TransferCircuit {
    pub fn check(&self) -> R<ConstraintStats> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        self.clone().generate_constraints(cs.clone())?;
        Ok(ConstraintStats {
            constraints: cs.num_constraints(),
            instance_variables: cs.num_instance_variables(),
            witness_variables: cs.num_witness_variables(),
            satisfied: cs.is_satisfied()?,
        })
    }
}
impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R<()> {
        let auth = &self.authorization;
        let a = B::new_witness_vec(cs.clone(), &auth.bytes())?;
        let z32 = B::constant_vec(&[0; 32]);
        let z8 = B::constant_vec(&[0; 8]);
        a[..8].enforce_equal(&B::constant_vec(AUTH_MAGIC))?;
        let d = &a[8..40];
        d.enforce_equal(&B::constant_vec(&DOMAIN))?;
        for start in [76, 364] {
            a[start..start + 8].enforce_equal(&B::constant_vec(STATE_MAGIC))?;
            a[start + 8..start + 40].enforce_equal(d)?;
        }
        let mut counts = Vec::new();
        for (start, state) in [(76, &auth.prior), (364, &auth.next)] {
            bounds(
                cs.clone(),
                &a[start + 72..start + 76],
                u64::from(state.n),
                1,
                u64::from(MAX_NOTES),
                &Flag::TRUE,
            )?;
            bounds(
                cs.clone(),
                &a[start + 108..start + 112],
                u64::from(state.m),
                1,
                u64::from(MAX_NF_LEAVES),
                &Flag::TRUE,
            )?;
            let n = field(&a[start + 72..start + 76])?;
            let m = field(&a[start + 108..start + 112])?;
            let headroom = (2 * u64::from(state.n) + 1).saturating_sub(u64::from(state.m));
            (m.clone() + slack(cs.clone(), headroom)?)
                .enforce_equal(&(n.clone() * Fr::from(2u64) + Fr::from(1u64)))?;
            counts.push((n, m));
        }
        counts[1]
            .0
            .enforce_equal(&(counts[0].0.clone() + Fr::from(2u64)))?;
        counts[1]
            .1
            .enforce_equal(&(counts[0].1.clone() + Fr::from(2u64)))?;
        bounds(cs.clone(), &a[188..196], auth.reserve, 1, MAX, &Flag::TRUE)?;
        bounds(cs.clone(), &a[196..204], auth.fee, 1, MAX, &Flag::TRUE)?;
        bounds(
            cs.clone(),
            &a[476..484],
            auth.reserve_after,
            NOTE_FLOOR,
            MAX,
            &Flag::TRUE,
        )?;
        (field(&a[476..484])? + field(&a[196..204])?).enforce_equal(&field(&a[188..196])?)?;
        let mut values = Vec::new();
        let mut real_flags = Vec::new();
        let mut positions = Vec::new();
        for (slot, input) in self.inputs.iter().enumerate() {
            let real = Flag::new_witness(cs.clone(), || Ok(input.real))?;
            let n = note(cs.clone(), d, &input.note)?;
            let s = B::new_witness_vec(cs.clone(), &input.owner_secret)?;
            let k = B::new_witness_vec(cs.clone(), &input.nullifier_secret)?;
            n.owner
                .conditional_enforce_equal(&digest(OWNER_TAG, d, &[&s, &n.incoming])?, &real)?;
            n.key
                .conditional_enforce_equal(&digest(KEY_TAG, d, &[&k])?, &real)?;
            bounds(
                cs.clone(),
                &n.value,
                input.note.value,
                NOTE_FLOOR,
                MAX,
                &real,
            )?;
            for b in [&n.owner, &n.incoming, &n.rho, &n.key, &n.pk, &s, &k] {
                b.conditional_enforce_equal(&z32, &!&real)?;
            }
            n.value.conditional_enforce_equal(&z8, &!&real)?;
            let pos = B::new_witness_vec(cs.clone(), &input.position.to_le_bytes())?;
            pos[2..].enforce_equal(&B::constant_vec(&[0; 2]))?;
            pos.conditional_enforce_equal(&B::constant_vec(&[0; 4]), &!&real)?;
            let remaining = u64::from(auth.prior.n).saturating_sub(u64::from(input.position) + 1);
            (field(&pos)? + slack(cs.clone(), remaining)? + Fr::from(1u64))
                .conditional_enforce_equal(&counts[0].0, &real)?;
            let bits = pos
                .iter()
                .map(ToBitsGadget::to_bits_le)
                .collect::<R<Vec<_>>>()?
                .concat();
            // Candidate-C uses raw CM leaves. There is no old-v6 SHA256(0||CM) here.
            let mut root = n.cm.clone();
            for (level, sibling) in input.path.iter().enumerate() {
                let sibling = B::new_witness_vec(cs.clone(), sibling)?;
                sibling.conditional_enforce_equal(&z32, &!&real)?;
                let left = sibling
                    .iter()
                    .zip(&root)
                    .map(|(s, r)| bits[level].select(s, r))
                    .collect::<R<Vec<_>>>()?;
                let right = sibling
                    .iter()
                    .zip(&root)
                    .map(|(s, r)| bits[level].select(r, s))
                    .collect::<R<Vec<_>>>()?;
                root = digest(CM_NODE, &[], &[&left, &right])?;
            }
            root.conditional_enforce_equal(&a[116..148], &real)?;
            let real_nf = hmac_g(
                &k,
                &[B::constant_vec(NF_TAG), d.to_vec(), n.cm, pos.clone()].concat(),
            )?;
            let dk = B::new_witness_vec(cs.clone(), &input.dummy_key)?;
            let ds = B::new_witness_vec(cs.clone(), &input.dummy_seed)?;
            dk.conditional_enforce_equal(&z32, &real)?;
            ds.conditional_enforce_equal(&z32, &real)?;
            let dummy_nf = hmac_g(
                &dk,
                &[
                    B::constant_vec(DUMMY_TAG),
                    d.to_vec(),
                    ds,
                    vec![B::constant(slot as u8)],
                ]
                .concat(),
            )?;
            let target = &a[204 + slot * 32..236 + slot * 32];
            target.conditional_enforce_equal(&real_nf, &real)?;
            target.conditional_enforce_equal(&dummy_nf, &!&real)?;
            target.is_eq(&z32)?.enforce_equal(&Flag::FALSE)?;
            values.push(field(&n.value)?);
            real_flags.push(real);
            positions.push(pos);
        }
        (&real_flags[0] | &real_flags[1]).enforce_equal(&Flag::TRUE)?;
        positions[0]
            .is_eq(&positions[1])?
            .conditional_enforce_equal(&Flag::FALSE, &(&real_flags[0] & &real_flags[1]))?;
        a[204..236]
            .is_eq(&a[236..268])?
            .enforce_equal(&Flag::FALSE)?;
        let mut outs = Vec::new();
        let mut positives = Vec::new();
        for (slot, output) in self.outputs.iter().enumerate() {
            let n = note(cs.clone(), d, output)?;
            let positive = !n.value.is_eq(&z8)?;
            bounds(
                cs.clone(),
                &n.value,
                output.value,
                NOTE_FLOOR,
                MAX,
                &positive,
            )?;
            for b in [&n.owner, &n.incoming, &n.key, &n.pk] {
                b.conditional_enforce_equal(&z32, &!&positive)?;
            }
            n.cm.enforce_equal(&a[268 + slot * 32..300 + slot * 32])?;
            outs.push(field(&n.value)?);
            positives.push(positive);
        }
        (&positives[0] | &positives[1]).enforce_equal(&Flag::TRUE)?;
        a[268..300]
            .is_eq(&a[300..332])?
            .enforce_equal(&Flag::FALSE)?;
        let total = values[0].clone() + values[1].clone();
        let raw_total =
            u128::from(self.inputs[0].note.value) + u128::from(self.inputs[1].note.value);
        let bounded_total = raw_total.min(u128::from(u64::MAX)) as u64;
        (total.clone() + slack(cs.clone(), MAX.saturating_sub(bounded_total))?)
            .enforce_equal(&FpVar::Constant(Fr::from(MAX)))?;
        (total.clone() + slack(cs.clone(), auth.reserve.saturating_sub(bounded_total))?)
            .enforce_equal(&field(&a[188..196])?)?;
        total.enforce_equal(&(outs[0].clone() + outs[1].clone() + field(&a[196..204])?))?;
        let digest = hash_g(&a)?;
        for i in 0..2 {
            field(&digest[16 * i..16 * (i + 1)])?
                .enforce_equal(&FpVar::new_input(cs.clone(), || {
                    Ok(auth.public_inputs()[i])
                })?)?;
        }
        Ok(())
    }
}
