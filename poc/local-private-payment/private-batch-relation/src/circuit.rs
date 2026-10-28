//! Actual private constraints for RFC-0030. Public CM/NF successor validation,
//! six genuine Output proofs and native projection binding are MANDATORY in the
//! selected proved R0 wrapper/covenant, never caller-supplied validity flags.
use crate::{
    BatchCircuit, BatchLayout, ColumnRange, OwnerColumns, COMPONENT_INSTANCES, MAX, NOTE_FLOOR, OUTPUTS, OWNERS, cv,
    gadgets::*,
    wire::{EFFECT_TAG, INTENT_TAG, intent_bytes},
    joint_ark::JointArk,
    joint_trace::PreparedJoint,
    trace::{Lc, TraceBuilder},
};
use ark_bn254::Fr;
use ark_ed_on_bn254::constraints::EdwardsVar;
use ark_ff::{AdditiveGroup, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, groups::CurveVar,
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use sha2::{Digest, Sha256};

fn digest_fields(digest: &[u8; 32]) -> [Fr; 2] {
    [
        Fr::from_le_bytes_mod_order(&digest[..16]),
        Fr::from_le_bytes_mod_order(&digest[16..]),
    ]
}
fn nonzero(bytes: &[B]) -> R<()> {
    bytes
        .is_eq(&B::constant_vec(&vec![0; bytes.len()]))?
        .enforce_equal(&Boolean::FALSE)
}
fn bind_digest(bytes: &[B], edges: &[FpVar<Fr>; 2]) -> R<()> {
    let d = hash(bytes)?;
    for i in 0..2 {
        number(&d[16 * i..16 * (i + 1)])?.enforce_equal(&edges[i])?;
    }
    Ok(())
}
fn witness(cs: ConstraintSystemRef<Fr>, bytes: &[u8]) -> R<Vec<B>> {
    B::new_witness_vec(cs, bytes)
}
fn physical_bits(cs:&ConstraintSystemRef<Fr>,bytes:&[B])->R<Vec<usize>> {
    bits(bytes)?.iter().map(|b| {
        let variable=b.variable();
        if !variable.is_witness() {return Err(ark_relations::gr1cs::SynthesisError::Unsatisfiable);}
        variable.get_variable_index(cs.num_instance_variables()).ok_or(ark_relations::gr1cs::SynthesisError::Unsatisfiable)
    }).collect()
}

impl BatchCircuit {
    pub fn generate_with_layout(self, cs: ConstraintSystemRef<Fr>) -> R<BatchLayout> {
        self.generate_internal(cs,None,None,true)
    }
    /// Generate recipes using a PUBLIC structural fixture only. All private
    /// owner columns are declared separately by the hash-bound layout; the
    /// prepared effects come exclusively from joint shared construction.
    pub fn generate_with_trace(self,cs:ConstraintSystemRef<Fr>,trace:&mut TraceBuilder,prepared:&PreparedJoint)->R<BatchLayout> {
        self.generate_internal(cs,Some(trace),Some(prepared),true)
    }
    /// Source/setup seam only: owner edges become the first198 witnesses.
    /// Their physical columns stay3..200 exactly as compose::join requires.
    pub(crate) fn generate_internalized(self,cs:ConstraintSystemRef<Fr>)->R<BatchLayout>{
        self.generate_internal(cs,None,None,false)
    }
    fn generate_internal(self, cs: ConstraintSystemRef<Fr>,trace:Option<&mut TraceBuilder>,prepared:Option<&PreparedJoint>,component_edges:bool) -> R<BatchLayout> {
        let mut joint=JointArk::new(trace);
        // Exact component prefix: ONE, global digest2, owner0/1/2(digest2, AK64).
        // compose::join internalizes all198 owner edges; only global2 stay public.
        let public = digest_fields(&self.effects.digest());
        let global = [
            FpVar::new_input(cs.clone(), || Ok(public[0]))?,
            FpVar::new_input(cs.clone(), || Ok(public[1]))?,
        ];
        let mut owner_edges = Vec::with_capacity(OWNERS);
        for owner in &self.witness.owners {
            let rows = [owner.outputs[0].tuple, owner.outputs[1].tuple];
            let bytes = intent_bytes(
                &self.effects.context,
                &owner.input_nf,
                &owner.input_cv,
                owner.fee_sompi,
                &owner.intent_nonce,
                &rows,
            );
            let d: [u8; 32] = Sha256::digest(bytes).into();
            let fields = digest_fields(&d);
            let digest = [
                if component_edges {FpVar::new_input(cs.clone(), || Ok(fields[0]))?} else {FpVar::new_witness(cs.clone(),||Ok(fields[0]))?},
                if component_edges {FpVar::new_input(cs.clone(), || Ok(fields[1]))?} else {FpVar::new_witness(cs.clone(),||Ok(fields[1]))?},
            ];
            let mut key = Vec::with_capacity(64);
            for byte in owner.authorization_key {
                key.push(if component_edges {FpVar::new_input(cs.clone(), || Ok(Fr::from(byte as u64)))?}else{FpVar::new_witness(cs.clone(),||Ok(Fr::from(byte as u64)))?});
            }
            owner_edges.push((digest, key));
        }
        if cs.num_instance_variables() != if component_edges {COMPONENT_INSTANCES}else{3} {
            return Err(ark_relations::gr1cs::SynthesisError::Unsatisfiable);
        }
        let raw = self.effects.bytes();
        let s = witness(cs.clone(), &raw)?;
        let effect_bit_columns=physical_bits(&cs,&s)?;
        if let Some(p)=prepared {joint.assign_bytes(&s,&p.effect_bytes)?;}
        s[..8].enforce_equal(&B::constant_vec(EFFECT_TAG))?;
        for (index, value) in [
            &self.profile.chain_genesis,
            &self.profile.pool_lineage,
            &self.profile.wallet_profile,
            &self.profile.domain,
            &self.profile.service_policy,
        ]
        .iter()
        .enumerate()
        {
            s[8 + 32 * index..40 + 32 * index].enforce_equal(&B::constant_vec(value.as_slice()))?;
        }
        joint.nonzero(&s[168..200])?;
        let domain = &s[104..136];
        let old_anchor = &s[204..236];
        let old_cm_count = number(&s[268..272])?;
        let old_nf_count = number(&s[272..276])?;
        joint.nonzero(&s[268..272])?;
        joint.nonzero(&s[272..276])?;
        joint.bound(
            &bits(&s[268..272])?,
            [(1u64 << 16) - OUTPUTS as u64],
        )?;
        joint.bound(
            &bits(&s[272..276])?,
            [(1u64 << 17) - OWNERS as u64],
        )?;
        number(&s[348..352])?.enforce_equal(&(&old_cm_count + Fr::from(OUTPUTS as u64)))?;
        number(&s[352..356])?.enforce_equal(&(&old_nf_count + Fr::from(OWNERS as u64)))?;
        joint.bounded_u64(&s[276..284], NOTE_FLOOR, MAX)?;
        joint.bounded_u64(&s[356..364], NOTE_FLOOR, MAX)?;
        joint.bounded_u64(&s[364..372], 1, MAX)?;
        (number(&s[356..364])? + number(&s[364..372])?).enforce_equal(&number(&s[276..284])?)?;

        let mut private_inputs = Vec::with_capacity(OWNERS);
        let mut private_outputs = Vec::with_capacity(OUTPUTS);
        let mut fee_sum = FpVar::Constant(Fr::ZERO);
        let mut selected_value = FpVar::Constant(Fr::ZERO);
        let mut private_deltas=Vec::with_capacity(OWNERS);
        let mut owner_local_columns=[ColumnRange{start:0,end:0};OWNERS];
        let mut owner_fields=Vec::with_capacity(OWNERS);
        let column=|cs:&ConstraintSystemRef<Fr>| cs.num_instance_variables()+cs.num_witness_variables();
        let initial_joint_columns=ColumnRange{start:COMPONENT_INSTANCES,end:column(&cs)};
        for (index, owner) in self.witness.owners.iter().enumerate() {
            let start_column=column(&cs);
            let key = witness(cs.clone(), &owner.authorization_key)?;
            for byte in 0..64 {
                number(&key[byte..byte + 1])?.enforce_equal(&owner_edges[index].1[byte])?;
            }
            let note = witness(cs.clone(), &owner.note.bytes())?;
            let cm = tagged(auth::NOTE_TAG, domain, &[&note])?;
            nonzero(&cm)?;
            note[..32].enforce_equal(&tagged(
                auth::AUTH_OWNER_TAG,
                domain,
                &[&key, &note[32..64]],
            )?)?;
            let nk = witness(cs.clone(), &owner.nullifier_secret)?;
            note[104..136].enforce_equal(&tagged(auth::KEY_TAG, domain, &[&nk])?)?;
            let position = witness(cs.clone(), &owner.position.to_le_bytes())?;
            less_than(&bits(&position)?, &bits(&s[268..272])?)?.enforce_equal(&Boolean::TRUE)?;
            membership(&cm, &position, &owner.path, cs.clone())?
                .as_slice()
                .enforce_equal(old_anchor)?;
            let nf = witness(cs.clone(), &owner.input_nf)?;
            nonzero(&nf)?;
            nullifier(domain, &nk, &cm, &position)?
                .as_slice()
                .enforce_equal(&nf)?;
            let cv = witness(cs.clone(), &owner.input_cv)?;
            let blind = witness(cs.clone(), &owner.blinding)?;
            let mut own_cv_difference = commitment(&note[64..72], &blind, &cv)?;
            let input_value = number(&note[64..72])?;
            selected_value += &input_value;
            let fee = witness(cs.clone(), &owner.fee_sompi.to_le_bytes())?;
            bounded_u64(&fee, 0, MAX)?;
            let mut own_output_value = FpVar::Constant(Fr::ZERO);
            let mut tuples = Vec::with_capacity(2);
            let mut tuple_columns=Vec::with_capacity(2);
            for output in &owner.outputs {
                let tuple = witness(cs.clone(), &output.tuple)?;
                tuple_columns.push(physical_bits(&cs,&tuple)?);
                nonzero(&tuple[..32])?;
                tuple[..32]
                    .is_eq(&B::constant_vec(&Sha256::digest(b"KPX1CME\0")))?
                    .enforce_equal(&Boolean::FALSE)?;
                let n = witness(cs.clone(), &output.note.bytes())?;
                tagged(auth::NOTE_TAG, domain, &[&n])?
                    .as_slice()
                    .enforce_equal(&tuple[..32])?;
                let r = witness(cs.clone(), &output.blinding)?;
                own_cv_difference -= commitment(&n[64..72], &r, &tuple[32..96])?;
                hash(&tuple[96..360])?
                    .as_slice()
                    .enforce_equal(&tuple[360..392])?;
                own_output_value += number(&n[64..72])?;
                tuples.push(tuple.clone());
                private_outputs.push(tuple);
            }
            let f = number(&fee)?;
            fee_sum += &f;
            // Three bounded u64 operands sum to at most3*MAX <2^64 <<Fr.
            // No owner can pay another owner's deficit or change its fee.
            input_value.enforce_equal(&(own_output_value + f))?;
            let private_delta=witness(cs.clone(),&owner.private_delta)?;
            let delta_bits=scalar_bits(&private_delta)?;
            private_deltas.push(Boolean::le_bits_to_fp(&delta_bits)?);
            let mut local_fee_delta=EdwardsVar::zero();
            let parameters=cv::parameters();
            local_fee_delta.precomputed_base_scalar_mul_le(bits(&fee)?.iter().zip(parameters.generators[0].iter()))?;
            local_fee_delta.precomputed_base_scalar_mul_le(delta_bits[..251].iter().zip(parameters.randomness_generator.iter()))?;
            own_cv_difference.enforce_equal(&local_fee_delta)?;
            let mut intent = B::constant_vec(INTENT_TAG);
            intent.extend_from_slice(&s[8..284]);
            intent.extend_from_slice(&nf);
            intent.extend_from_slice(&cv);
            intent.extend_from_slice(&fee);
            intent.extend(witness(cs.clone(), &owner.intent_nonce)?);
            for tuple in tuples {
                intent.extend(tuple);
            }
            bind_digest(&intent, &owner_edges[index].0)?;
            let mut row = nf;
            row.extend(cv);
            private_inputs.push(row);
            owner_local_columns[index]=ColumnRange{start:start_column,end:column(&cs)};
            owner_fields.push(OwnerColumns {
                input_nf_bits:physical_bits(&cs,&private_inputs[index][..32])?,
                input_cv_bits:physical_bits(&cs,&private_inputs[index][32..96])?,
                output_tuple_bits:tuple_columns.try_into().map_err(|_|ark_relations::gr1cs::SynthesisError::Unsatisfiable)?,
                fee_bits:physical_bits(&cs,&fee)?,
                private_delta_bits:physical_bits(&cs,&private_delta)?,
                input_value_bits:physical_bits(&cs,&note[64..72])?,
            });
        }
        let joint_start=column(&cs);
        // In the general u64 contract three fees need66 bits. Here each is
        // additionally bounded by Native MAX, and total has its own nativeu64
        // encoding/range, so this exact (<2^66) equality cannot wrap Fr.
        let fee_bits=owner_fields.iter().map(|o:&OwnerColumns|o.fee_bits.iter().copied().map(Lc::wire).collect()).collect::<Vec<_>>();
        joint.fee_sum(&fee_sum,&fee_bits)?;
        fee_sum.enforce_equal(&number(&s[364..372])?)?;
        let input_sum = self
            .witness
            .owners
            .iter()
            .map(|o| o.note.value as u128)
            .sum::<u128>();
        // Fixed wrapping generation avoids branching on a private underflow.
        // The constrained bounded equality below rejects every wrapped case.
        let remainder = self.effects.context.old_reserve.wrapping_sub(input_sum as u64);
        let remainder = witness(cs.clone(), &remainder.to_le_bytes())?;
        if let Some(p)=prepared {joint.assign_bytes(&remainder,&p.remainder_bits.chunks(8).map(|b|b.to_vec()).collect::<Vec<_>>())?;}
        joint.bounded_u64(&remainder, 0, MAX)?;
        (selected_value + number(&remainder)?).enforce_equal(&number(&s[276..284])?)?;

        joint.delta_sum(cs.clone(),&private_deltas,&s[372..404],self.witness.delta_quotient,prepared.map(|p|p.delta_quotient_bits.as_slice()).unwrap_or(&[]))?;
        let public_inputs = (0..OWNERS)
            .map(|i| s[404 + 96 * i..500 + 96 * i].to_vec())
            .collect::<Vec<_>>();
        let public_outputs = (0..OUTPUTS)
            .map(|i| s[692 + 520 * i..1212 + 520 * i].to_vec())
            .collect::<Vec<_>>();
        let u = joint.permutation(cs.clone(), &self.witness.input_permutation,prepared.map(|p|p.input_permutation.as_slice()).unwrap_or(&[]))?;
        let v = joint.permutation(cs.clone(), &self.witness.output_permutation,prepared.map(|p|p.output_permutation.as_slice()).unwrap_or(&[]))?;
        joint.route(&private_inputs, &public_inputs, &u)?;
        joint.route(&private_outputs, &public_outputs, &v)?;
        for i in 1..OWNERS {
            joint.less_than(
                &bits(&public_inputs[i - 1][..32])?,
                &bits(&public_inputs[i][..32])?,
            )?
            .enforce_equal(&Boolean::TRUE)?;
        }
        for a in 0..OWNERS {
            for b in a + 1..OWNERS {
                joint.bytes_eq(&public_inputs[a][..32],&public_inputs[b][..32])?
                    .enforce_equal(&Boolean::FALSE)?;
            }
        }
        for a in 0..OUTPUTS {
            for b in a + 1..OUTPUTS {
                joint.bytes_eq(&public_outputs[a][..32],&public_outputs[b][..32])?
                    .enforce_equal(&Boolean::FALSE)?;
            }
        }
        // Includes every tuple/proof/ciphertext byte and all publicstatepaths.
        // The provedR0 wrapper must ALSO validate those paths and realproofs.
        joint.bind_digest(&s, &global)?;
        Ok(BatchLayout{effect_bit_columns,initial_joint_columns,owner_local_columns,
            owner_fields:owner_fields.try_into().map_err(|_|ark_relations::gr1cs::SynthesisError::Unsatisfiable)?,
            final_joint_columns:ColumnRange{start:joint_start,end:column(&cs)}})
    }
}

impl ConstraintSynthesizer<Fr> for BatchCircuit {
    fn generate_constraints(self,cs:ConstraintSystemRef<Fr>)->R<()> {self.generate_with_layout(cs).map(|_|())}
}
