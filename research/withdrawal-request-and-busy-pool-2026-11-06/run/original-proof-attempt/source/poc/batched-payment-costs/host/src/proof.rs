//! Full existing wallet relation with digest-packed public inputs, no new keys.
use crate::circuit::WalletCircuit;
use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
pub use kpi_private_note_wallet::protocol::{H, hash};
use kpi_private_note_wallet::{
    ProofVerifier,
    circuit::Witness,
    protocol::{Delivery, EXIT, Operation, Statement},
};
use rand::rngs::OsRng;
pub type Authorization = Operation;
pub fn serialize<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut b = vec![];
    v.serialize_compressed(&mut b).unwrap();
    b
}
pub fn fields(s: &Statement) -> Vec<Fr> {
    hash(&s.bytes())
        .chunks(16)
        .map(Fr::from_le_bytes_mod_order)
        .collect()
}
pub struct Engine {
    pub pk: ProvingKey<Bn254>,
    pub vk: VerifyingKey<Bn254>,
    pub proofs: usize,
    pub constraints: usize,
}
impl Engine {
    pub fn setup(sample: WalletCircuit) -> Self {
        let (constraints, valid) = sample.check().unwrap();
        assert!(valid);
        let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(sample, &mut OsRng)
            .unwrap();
        Self {
            vk: pk.vk.clone(),
            pk,
            proofs: 0,
            constraints,
        }
    }
    pub fn id(&self) -> H {
        hash(&serialize(&self.vk))
    }
    pub fn prove(
        &mut self,
        mut statement: Statement,
        witness: Witness,
        deliveries: [Delivery; 2],
    ) -> Operation {
        statement.verifier = self.id();
        for (i, d) in deliveries.iter().enumerate() {
            statement.outputs[i] = d.commitment;
            statement.delivery[i] = if d.ciphertext.is_empty() {
                [0; 32]
            } else {
                hash(&d.ciphertext)
            };
        }
        let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
            WalletCircuit {
                statement: statement.clone(),
                witness,
            },
            &self.pk,
            &mut OsRng,
        )
        .unwrap();
        let op = Operation {
            statement,
            deliveries,
            proof: serialize(&proof),
        };
        assert!(self.verify(&op));
        self.proofs += 1;
        op
    }
    pub fn authorize(&mut self, witness: &Witness, context: H, anchor: H) -> Operation {
        let mut s = Statement::new(EXIT, self.id(), anchor);
        s.nullifier = kpi_private_note_wallet::protocol::nullifier(&witness.secret, &witness.input);
        s.exit_value = witness.input.value;
        s.exit_destination = context;
        self.prove(s, witness.clone(), [Delivery::absent(), Delivery::absent()])
    }
    pub fn verify(&self, op: &Operation) -> bool {
        verify(&self.vk, op)
    }
}
pub fn verify(vk: &VerifyingKey<Bn254>, op: &Operation) -> bool {
    if op.check_public(hash(&serialize(vk))).is_err() || op.proof.len() != 128 {
        return false;
    }
    let mut rest = op.proof.as_slice();
    let Ok(p) = ark_groth16::Proof::<Bn254>::deserialize_compressed(&mut rest) else {
        return false;
    };
    rest.is_empty()
        && serialize(&p) == op.proof
        && !p.a.is_zero()
        && !p.b.is_zero()
        && !p.c.is_zero()
        && Groth16::<Bn254>::verify_proof(
            &ark_groth16::prepare_verifying_key(vk),
            &p,
            &fields(&op.statement),
        )
        .unwrap_or(false)
}
impl ProofVerifier for Engine {
    fn id(&self) -> H {
        self.id()
    }
    fn verify(&self, op: &Operation) -> Result<(), String> {
        if self.verify(op) {
            Ok(())
        } else {
            Err("invalid packed wallet proof".into())
        }
    }
}
