//! Private relation only. Native code authenticates current NF updates, empty CM
//! appends and real transaction context; no host verdict is accepted as a witness.
use crate::exact_sha256::Sha256Gadget;
use crate::*;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar,
    uint8::UInt8, uint64::UInt64,
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
};
type B = UInt8<Fr>;
type Flag = Boolean<Fr>;
type R<T> = std::result::Result<T, SynthesisError>;

#[derive(Clone)]
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
#[derive(Clone)]
pub struct ActionCircuit {
    /// Trusted public construction selects the fixed shape before private bytes.
    pub role: Role,
    pub authorization: Authorization,
    pub inputs: [InputWitness; 2],
    pub outputs: Vec<Note>,
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
fn select_bytes(real: &Flag, when_real: &[B], when_dummy: &[B]) -> R<Vec<B>> {
    if when_real.len() != when_dummy.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    when_real
        .iter()
        .zip(when_dummy)
        .map(|(r, d)| real.select(r, d))
        .collect()
}

/// Exact RFC2104/SHA256 padded inner message for both contract formulas.
/// No padding or length byte is supplied by the prover as a free witness.
fn selected_inner_bytes(
    real: &Flag,
    key: &[B],
    d: &[B],
    data: &[B],
    pos: &[B],
    slot: u8,
) -> R<Vec<B>> {
    if key.len() != 32 || d.len() != 32 || data.len() != 32 || pos.len() != 4 || slot > 1 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut inner = key
        .iter()
        .map(|b| b ^ B::constant(0x36))
        .collect::<Vec<_>>();
    inner.extend(B::constant_vec(&[0x36; 32]));
    inner.extend(select_bytes(
        real,
        &B::constant_vec(NF_TAG),
        &B::constant_vec(DUMMY_TAG),
    )?);
    inner.extend_from_slice(d);
    inner.extend_from_slice(data);
    // Common prefix is136bytes: ipad64 || tag8 || D32 || selectedCM/seed32.
    // Real adds pos4 and pads140bytes (1120bits); dummy adds slot1 and
    // pads137bytes (1096bits). Both exact inner SHA streams total192bytes.
    let real_tail = [
        pos.to_vec(),
        B::constant_vec(&[0x80]),
        B::constant_vec(&[0; 43]),
        B::constant_vec(&(140u64 * 8).to_be_bytes()),
    ]
    .concat();
    let dummy_tail = [
        B::constant_vec(&[slot, 0x80]),
        B::constant_vec(&[0; 46]),
        B::constant_vec(&(137u64 * 8).to_be_bytes()),
    ]
    .concat();
    inner.extend(select_bytes(real, &real_tail, &dummy_tail)?);
    Ok(inner)
}

fn selected_hmac_g(
    real: &Flag,
    k: &[B],
    dk: &[B],
    d: &[B],
    cm: &[B],
    ds: &[B],
    pos: &[B],
    slot: u8,
) -> R<Vec<B>> {
    let key = select_bytes(real, k, dk)?;
    let data = select_bytes(real, cm, ds)?;
    let inner = selected_inner_bytes(real, &key, d, &data, pos, slot)?;
    let inner_digest = Sha256Gadget::digest_padded_hmac_inner(&inner)?.0;
    let mut outer = key
        .iter()
        .map(|b| b ^ B::constant(0x5c))
        .collect::<Vec<_>>();
    outer.extend(B::constant_vec(&[0x5c; 32]));
    outer.extend(inner_digest);
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
impl ActionCircuit {
    pub const fn role(&self) -> Role {
        self.role
    }
    pub fn check(&self) -> R<ConstraintStats> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        // Match the actual Groth16 generator/prover, not the default None goal.
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        self.clone().generate_constraints(cs.clone())?;
        cs.finalize();
        Ok(ConstraintStats {
            constraints: cs.num_constraints(),
            instance_variables: cs.num_instance_variables(),
            witness_variables: cs.num_witness_variables(),
            satisfied: cs.is_satisfied()?,
        })
    }
}
impl ConstraintSynthesizer<Fr> for ActionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R<()> {
        let output_count = self.role.output_count();
        if self.outputs.len() != output_count {
            return Err(SynthesisError::Unsatisfiable);
        }
        let auth = &self.authorization;
        let a = B::new_witness_vec(cs.clone(), &auth.bytes())?;
        let z32 = B::constant_vec(&[0; 32]);
        let z8 = B::constant_vec(&[0; 8]);
        a[..8].enforce_equal(&B::constant_vec(AUTH_MAGIC))?;
        let d = &a[8..40];
        d.enforce_equal(&B::constant_vec(&DOMAIN))?;
        // Modes are constrained Boolean predicates of public bytes, never
        // Rust branches on witness values; one setup covers every mode.
        let terminal = a[476..484].is_eq(&z8)?;
        let continuing = !&terminal;
        let mode_terminal = a[300..301].is_eq(&B::constant_vec(&[0]))?;
        mode_terminal.enforce_equal(&terminal)?;
        // This branch depends only on the installed relation role. Auth modes
        // remain constrained flags, preserving compact mode0/mode2 matrices.
        match self.role {
            Role::Compact => {
                a[300..301]
                    .is_eq(&B::constant_vec(&[2]))?
                    .enforce_equal(&continuing)?;
            }
            Role::Wide => {
                a[300..301].enforce_equal(&B::constant_vec(&[32]))?;
                terminal.enforce_equal(&Flag::FALSE)?;
            }
        }
        a[301..304].enforce_equal(&B::constant_vec(&[0; 3]))?;
        a[308..332].enforce_equal(&B::constant_vec(&[0; 24]))?;
        let has_payout = !a[484..492].is_eq(&z8)?;
        if self.role == Role::Wide {
            has_payout.enforce_equal(&Flag::FALSE)?;
        }
        has_payout.conditional_enforce_equal(&Flag::TRUE, &terminal)?;
        a[492..528].conditional_enforce_equal(&B::constant_vec(&[0; 36]), &!&has_payout)?;
        a[492..495].conditional_enforce_equal(&B::constant_vec(&[0, 0, 0x20]), &has_payout)?;
        a[527..528].conditional_enforce_equal(&B::constant_vec(&[0xac]), &has_payout)?;
        bounds(
            cs.clone(),
            &a[484..492],
            auth.payout,
            PAYOUT_FLOOR,
            MAX,
            &has_payout,
        )?;
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
        // Integer alignment: start is a multiple of N and old_n<=start<old_n+N.
        // Counts and start are bounded16-bit integers; delta has log2(N) bits.
        // Thus the field equality cannot wrap and uniquely gives ceil(old_n/N)*N.
        let start = &a[304..308];
        let start_bits = start
            .iter()
            .map(ToBitsGadget::to_bits_le)
            .collect::<R<Vec<_>>>()?
            .concat();
        let log_n = output_count.trailing_zeros() as usize;
        for bit in start_bits
            .iter()
            .take(log_n)
            .chain(start_bits.iter().skip(16))
        {
            bit.enforce_equal(&Flag::FALSE)?;
        }
        let raw_delta = auth.cm_start.saturating_sub(auth.prior.n);
        let delta = B::new_witness(cs.clone(), || Ok(raw_delta.min(u32::from(u8::MAX)) as u8))?;
        for bit in delta.to_bits_le()?.iter().skip(log_n) {
            bit.enforce_equal(&Flag::FALSE)?;
        }
        field(start)?
            .conditional_enforce_equal(&(counts[0].0.clone() + field(&[delta])?), &continuing)?;
        start.conditional_enforce_equal(&B::constant_vec(&[0; 4]), &terminal)?;
        counts[1].0.conditional_enforce_equal(
            &(field(start)? + Fr::from(output_count as u64)),
            &continuing,
        )?;
        counts[1]
            .0
            .conditional_enforce_equal(&counts[0].0, &terminal)?;
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
            &continuing,
        )?;
        (field(&a[476..484])? + field(&a[484..492])? + field(&a[196..204])?)
            .enforce_equal(&field(&a[188..196])?)?;
        a[404..436].conditional_enforce_equal(&a[116..148], &terminal)?;
        a[332..364]
            .conditional_enforce_equal(&B::constant_vec(&terminal_cipher_hash()), &terminal)?;
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
            n.pk.as_slice()
                .is_eq(&a[495..527])?
                .conditional_enforce_equal(&Flag::FALSE, &(&real & &has_payout))?;
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
            root.as_slice()
                .conditional_enforce_equal(&a[116..148], &real)?;
            let dk = B::new_witness_vec(cs.clone(), &input.dummy_key)?;
            let ds = B::new_witness_vec(cs.clone(), &input.dummy_seed)?;
            dk.conditional_enforce_equal(&z32, &real)?;
            ds.conditional_enforce_equal(&z32, &real)?;
            let selected_nf = selected_hmac_g(&real, &k, &dk, d, &n.cm, &ds, &pos, slot as u8)?;
            let target = &a[204 + slot * 32..236 + slot * 32];
            target.enforce_equal(&selected_nf)?;
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
        let mut outs = Vec::with_capacity(output_count);
        let mut positives = Vec::with_capacity(output_count);
        let mut ordered_cms = Vec::with_capacity(output_count);
        for output in &self.outputs {
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
            // Terminal creates no delivery or CM, including no dummy rho.
            for b in [&n.owner, &n.incoming, &n.rho, &n.key, &n.pk] {
                b.conditional_enforce_equal(&z32, &terminal)?;
            }
            n.value.conditional_enforce_equal(&z8, &terminal)?;
            ordered_cms.push(n.cm);
            outs.push(field(&n.value)?);
            positives.push(positive);
        }
        let any_positive = positives.iter().fold(Flag::FALSE, |any, flag| &any | flag);
        (&any_positive | &has_payout).enforce_equal(&Flag::TRUE)?;
        let list_digest = hash_g(&ordered_cms.concat())?;
        list_digest
            .as_slice()
            .conditional_enforce_equal(&a[268..300], &continuing)?;
        a[268..300].conditional_enforce_equal(&z32, &terminal)?;
        // All physical slots, not only positive receipts:1 or496 comparisons.
        for i in 0..output_count {
            for j in i + 1..output_count {
                ordered_cms[i]
                    .is_eq(&ordered_cms[j])?
                    .conditional_enforce_equal(&Flag::FALSE, &continuing)?;
            }
        }
        let total = values[0].clone() + values[1].clone();
        let raw_total =
            u128::from(self.inputs[0].note.value) + u128::from(self.inputs[1].note.value);
        let bounded_total = raw_total.min(u128::from(u64::MAX)) as u64;
        (total.clone() + slack(cs.clone(), MAX.saturating_sub(bounded_total))?)
            .enforce_equal(&FpVar::Constant(Fr::from(MAX)))?;
        (total.clone() + slack(cs.clone(), auth.reserve.saturating_sub(bounded_total))?)
            .enforce_equal(&field(&a[188..196])?)?;
        // Bounded u64 note values and at most32 outputs keep this exact integer
        // sum below2^67, far below the BN254 modulus. No u64 accumulation occurs.
        let output_total = outs
            .into_iter()
            .fold(FpVar::Constant(Fr::from(0u64)), |sum, value| sum + value);
        total.enforce_equal(&(output_total + field(&a[484..492])? + field(&a[196..204])?))?;
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

/// Hash finalized public matrices with variable indices/coefficients/dimensions,
/// never witness/instance assignments. Caller must use the Groth16 goal/settings
/// and finalize first. Materializes one matrix copy, so heavyweight callers
/// serialize this step and release it before writing/decoding PK bytes.
pub fn matrix_fingerprint(cs: &ConstraintSystemRef<Fr>) -> R<String> {
    use ark_serialize::CanonicalSerialize;
    use sha2::{Digest, Sha256};
    fn count(h: &mut Sha256, value: usize) -> R<()> {
        h.update(
            u64::try_from(value)
                .map_err(|_| SynthesisError::Unsatisfiable)?
                .to_le_bytes(),
        );
        Ok(())
    }
    let matrices = cs.to_matrices()?;
    let mut h = Sha256::new();
    h.update(b"KPX4/GR1CS-MATRIX/v1\0");
    for value in [
        cs.num_constraints(),
        cs.num_instance_variables(),
        cs.num_witness_variables(),
    ] {
        count(&mut h, value)?;
    }
    count(&mut h, matrices.len())?;
    for (label, group) in matrices {
        count(&mut h, label.len())?;
        h.update(label.as_bytes());
        count(&mut h, group.len())?;
        for matrix in group {
            count(&mut h, matrix.len())?;
            for row in matrix {
                count(&mut h, row.len())?;
                for (coefficient, index) in row {
                    let mut bytes = [0u8; 32];
                    coefficient
                        .serialize_compressed(bytes.as_mut_slice())
                        .map_err(|_| SynthesisError::Unsatisfiable)?;
                    h.update(bytes);
                    count(&mut h, index)?;
                }
            }
        }
    }
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod selected_hmac_tests {
    use super::*;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::SynthesisMode;

    fn pattern(seed: u8) -> H {
        std::array::from_fn(|i| seed.wrapping_add((i as u8).wrapping_mul(37)))
    }
    fn host_message(real: bool, d: &H, cm: &H, ds: &H, pos: u32, slot: u8) -> Vec<u8> {
        if real {
            [
                NF_TAG.as_slice(),
                d.as_slice(),
                cm.as_slice(),
                pos.to_le_bytes().as_slice(),
            ]
            .concat()
        } else {
            [DUMMY_TAG.as_slice(), d.as_slice(), ds.as_slice(), &[slot]].concat()
        }
    }
    // Independent RFC2104 + FIPS180-4 host construction: append one bit,
    // enough zeros to the56B boundary, then the original bit length.
    fn host_inner(key: &H, message: &[u8]) -> Vec<u8> {
        let mut bytes = key.iter().map(|b| b ^ 0x36).collect::<Vec<_>>();
        bytes.extend_from_slice(&[0x36; 32]);
        bytes.extend_from_slice(message);
        let bits = (bytes.len() as u64) * 8;
        bytes.push(0x80);
        while bytes.len() % 64 != 56 {
            bytes.push(0);
        }
        bytes.extend_from_slice(&bits.to_be_bytes());
        bytes
    }
    fn vars(cs: ConstraintSystemRef<Fr>, bytes: &[u8]) -> Vec<B> {
        B::new_witness_vec(cs, bytes).unwrap()
    }

    #[test]
    fn exact_inner_bytes_and_original_hmac_known_answers() {
        let (k, dk, cm, ds, d) = (pattern(3), pattern(19), pattern(71), pattern(143), DOMAIN);
        for slot in 0u8..2 {
            let mut shape = None;
            for (real, pos) in [
                (false, 0u32),
                (true, 0),
                (true, 0x3412_cdab),
                (true, u32::MAX),
            ] {
                let cs = ConstraintSystem::<Fr>::new_ref();
                let flag = Flag::new_witness(cs.clone(), || Ok(real)).unwrap();
                let (kg, dkg, dg, cmg, dsg, pg) = (
                    vars(cs.clone(), &k),
                    vars(cs.clone(), &dk),
                    vars(cs.clone(), &d),
                    vars(cs.clone(), &cm),
                    vars(cs.clone(), &ds),
                    vars(cs.clone(), &pos.to_le_bytes()),
                );
                let key = select_bytes(&flag, &kg, &dkg).unwrap();
                let data = select_bytes(&flag, &cmg, &dsg).unwrap();
                let padded = selected_inner_bytes(&flag, &key, &dg, &data, &pg, slot).unwrap();
                let expected_key = if real { &k } else { &dk };
                let message = host_message(real, &d, &cm, &ds, pos, slot);
                let expected_padded = host_inner(expected_key, &message);
                assert_eq!(expected_padded.len(), 192);
                assert_eq!(padded.value().unwrap(), expected_padded);
                padded
                    .enforce_equal(&B::constant_vec(&expected_padded))
                    .unwrap();
                let actual = selected_hmac_g(&flag, &kg, &dkg, &dg, &cmg, &dsg, &pg, slot).unwrap();
                let expected = if real {
                    nullifier(&d, &k, &cm, pos)
                } else {
                    dummy_nullifier(&d, &dk, &ds, slot)
                };
                actual.enforce_equal(&B::constant_vec(&expected)).unwrap();
                assert_eq!(actual.value().unwrap(), expected.to_vec());
                assert!(cs.is_satisfied().unwrap());
                let current = (cs.num_constraints(), cs.num_witness_variables());
                if let Some(shape) = shape {
                    assert_eq!(current, shape, "same witness-selector shape");
                } else {
                    shape = Some(current);
                }
            }
        }
    }

    #[test]
    fn malformed_padding_or_length_cannot_match_original_hmac() {
        let (k, dk, cm, ds, d) = (pattern(3), pattern(19), pattern(71), pattern(143), DOMAIN);
        for real in [false, true] {
            for corrupt_length in [false, true] {
                let cs = ConstraintSystem::<Fr>::new_ref();
                let flag = Flag::new_witness(cs.clone(), || Ok(real)).unwrap();
                let (kg, dkg, dg, cmg, dsg, pg) = (
                    vars(cs.clone(), &k),
                    vars(cs.clone(), &dk),
                    vars(cs.clone(), &d),
                    vars(cs.clone(), &cm),
                    vars(cs.clone(), &ds),
                    vars(cs.clone(), &0x3412_cdabu32.to_le_bytes()),
                );
                let key = select_bytes(&flag, &kg, &dkg).unwrap();
                let data = select_bytes(&flag, &cmg, &dsg).unwrap();
                let mut padded = selected_inner_bytes(&flag, &key, &dg, &data, &pg, 1).unwrap();
                let index = if corrupt_length {
                    191
                } else if real {
                    140
                } else {
                    137
                };
                padded[index] = &padded[index] ^ B::constant(1);
                let inner = Sha256Gadget::digest_padded_hmac_inner(&padded).unwrap().0;
                let mut outer = key
                    .iter()
                    .map(|b| b ^ B::constant(0x5c))
                    .collect::<Vec<_>>();
                outer.extend(B::constant_vec(&[0x5c; 32]));
                outer.extend(inner);
                let actual = hash_g(&outer).unwrap();
                let expected = if real {
                    nullifier(&d, &k, &cm, 0x3412_cdab)
                } else {
                    dummy_nullifier(&d, &dk, &ds, 1)
                };
                actual.enforce_equal(&B::constant_vec(&expected)).unwrap();
                assert!(
                    !cs.is_satisfied().unwrap(),
                    "real={real} length={corrupt_length}"
                );
            }
        }
    }

    #[test]
    fn malformed_selector_field_assignment_is_rejected() {
        for real in [false, true] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            cs.set_mode(SynthesisMode::Prove {
                construct_matrices: true,
                generate_lc_assignments: false,
            });
            let selector = Flag::new_witness(cs.clone(), || Ok(real)).unwrap();
            let selected = select_bytes(
                &selector,
                &B::constant_vec(&[0x33]),
                &B::constant_vec(&[0x55]),
            )
            .unwrap();
            assert_eq!(
                selected.value().unwrap(),
                vec![if real { 0x33 } else { 0x55 }]
            );
            let index = match selector {
                Flag::Var(ref v) => v.variable().index().unwrap(),
                _ => unreachable!(),
            };
            cs.borrow_mut().unwrap().assignments.witness_assignment[index] = Fr::from(2u64);
            cs.finalize();
            assert!(!cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn padded_inner_requires_exact_three_blocks() {
        for len in [0usize, 64, 128, 191, 193, 256] {
            assert!(matches!(
                Sha256Gadget::<Fr>::digest_padded_hmac_inner(&B::constant_vec(&vec![0; len])),
                Err(SynthesisError::Unsatisfiable)
            ));
        }
    }
}
