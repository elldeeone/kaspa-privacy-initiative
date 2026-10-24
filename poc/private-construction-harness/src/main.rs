//! Public unsafe API/curve controls. Never interpreted as a valid transaction.
use std::collections::BTreeMap;
use std::convert::Infallible;

use jubjub::{ExtendedPoint, Scalar};
use rand::{rngs::StdRng, SeedableRng};
use rand_core::{Rng, TryCryptoRng, TryRng};
use redjubjub::{Binding, SigningKey, SpendAuth};
use sapling::circuit::{Output as OutputCircuit, Spend as SpendCircuit};
use sapling::keys::EphemeralSecretKey;
use sapling::pczt::{Bundle as PcztBundle, Output as PcztOutput, Spend as PcztSpend};
use sapling::prover::{OutputProver, SpendProver};
use sapling::value::{CommitmentSum, NoteValue, ValueCommitTrapdoor, ValueCommitment};
use sapling::{Diversifier, MerklePath, PaymentAddress, ProofGenerationKey, Rseed};
use serde_json::{json, Value};

const INPUT_VALUES: [u64; 3] = [1_000_000_000; 3];
const OUTPUT_VALUES: [u64; 6] = [
    600_000_000,
    390_000_000,
    600_000_000,
    390_000_000,
    600_000_000,
    390_000_000,
];
const INPUT_RCV: [u64; 3] = [10139, 30727, 91193];
const OUTPUT_RCV: [u64; 6] = [
    505963,
    122949823,
    2147483647,
    32416190071,
    982451653,
    961748941,
];
const FEE: u64 = 10_000_000;
const PERMUTATION: [usize; 6] = [4, 1, 5, 2, 0, 3];
const TEST_DIGEST: [u8; 32] = [0x34; 32];
const MOCK_NONPROOF: [u8; 192] = [0; 192];

fn trapdoor(scalar: Scalar) -> ValueCommitTrapdoor {
    ValueCommitTrapdoor::from_bytes(scalar.to_bytes()).unwrap()
}

fn commitment(value: u64, blind: Scalar) -> ValueCommitment {
    ValueCommitment::derive(NoteValue::from_raw(value), trapdoor(blind))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone)]
struct PublicOutput {
    id: usize,
    cv: ValueCommitment,
}

/// Attack knowledge is deliberately only public points, fee, and beta*R.
/// The caller's fixture openings and true pair are not parameters.
fn subset_attack(
    input: &ValueCommitment,
    outputs: &[PublicOutput],
    fee: u64,
    beta_point: Option<&ExtendedPoint>,
) -> Result<Vec<[usize; 2]>, &'static str> {
    let target = beta_point.ok_or("AttackInputMissing")?;
    let fee_point = commitment(fee, Scalar::zero());
    let mut matches = Vec::new();
    for a in 0..outputs.len() {
        for b in a + 1..outputs.len() {
            let candidate = input.as_inner().clone()
                - outputs[a].cv.as_inner().clone()
                - outputs[b].cv.as_inner().clone()
                - fee_point.as_inner().clone();
            if &candidate == target {
                let mut ids = [outputs[a].id, outputs[b].id];
                ids.sort();
                matches.push(ids);
            }
        }
    }
    Ok(matches)
}

struct PanicRng;
impl TryRng for PanicRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        panic!("unexpected RNG use")
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        panic!("unexpected RNG use")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Infallible> {
        panic!("unexpected RNG use")
    }
}
impl TryCryptoRng for PanicRng {}

struct NeverProver;
impl SpendProver for NeverProver {
    type Proof = ();
    fn prepare_circuit(
        _: ProofGenerationKey,
        _: Diversifier,
        _: Rseed,
        _: NoteValue,
        _: Scalar,
        _: ValueCommitTrapdoor,
        _: bls12_381::Scalar,
        _: MerklePath,
    ) -> Option<SpendCircuit> {
        panic!("unexpected circuit preparation")
    }
    fn create_proof<R: Rng>(&self, _: SpendCircuit, _: &mut R) {
        panic!("unexpected proof generation")
    }
    fn encode_proof(_: ()) -> [u8; 192] {
        panic!("unexpected proof encoding")
    }
}
impl OutputProver for NeverProver {
    type Proof = ();
    fn prepare_circuit(
        _: &EphemeralSecretKey,
        _: PaymentAddress,
        _: Scalar,
        _: NoteValue,
        _: ValueCommitTrapdoor,
    ) -> OutputCircuit {
        panic!("unexpected output circuit preparation")
    }
    fn create_proof<R: Rng>(&self, _: OutputCircuit, _: &mut R) {
        panic!("unexpected proof generation")
    }
    fn encode_proof(_: ()) -> [u8; 192] {
        panic!("unexpected proof encoding")
    }
}

fn public_test_signing_key(owner: usize) -> SigningKey<SpendAuth> {
    SigningKey::from_bytes(&Scalar::from(41 + owner as u64).to_bytes()).unwrap()
}

fn redacted_bundle(
    inputs: &[ValueCommitment],
    outputs: &[PublicOutput],
    delta: Scalar,
) -> PcztBundle {
    let spends = inputs
        .iter()
        .enumerate()
        .map(|(i, cv)| {
            let sk = public_test_signing_key(i);
            let rk: [u8; 32] = redjubjub::VerificationKey::from(&sk).into();
            let mut rng = StdRng::from_seed([0x50 + i as u8; 32]);
            let sig: [u8; 64] = sk.sign(&mut rng, &TEST_DIGEST).into();
            PcztSpend::parse(
                cv.to_bytes(),
                [0x10 + i as u8; 32],
                rk,
                Some(MOCK_NONPROOF),
                Some(sig),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                BTreeMap::new(),
            )
            .expect("public canonical spend parser preflight")
        })
        .collect();
    let outputs = outputs
        .iter()
        .map(|output| {
            PcztOutput::parse(
                output.cv.to_bytes(),
                [0; 32],
                [0; 32],
                vec![0; 580],
                vec![0; 80],
                Some(MOCK_NONPROOF),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                BTreeMap::new(),
            )
            .expect("public canonical output parser preflight")
        })
        .collect();
    PcztBundle::parse(
        spends,
        outputs,
        (FEE * 3) as i128,
        [0; 32],
        Some(delta.to_bytes()),
    )
    .expect("redacted record and external canonical binding key parser preflight")
}

fn binding_key(
    inputs: &[ValueCommitment],
    outputs: &[PublicOutput],
    balance: i64,
) -> redjubjub::VerificationKey<Binding> {
    let ins: CommitmentSum = inputs.iter().cloned().sum();
    let outs: CommitmentSum = outputs.iter().map(|output| output.cv.clone()).sum();
    (ins - outs).into_bvk(balance)
}

fn main() {
    let inputs: Vec<_> = INPUT_VALUES
        .iter()
        .zip(INPUT_RCV)
        .map(|(&v, r)| commitment(v, Scalar::from(r)))
        .collect();
    let outputs: Vec<_> = OUTPUT_VALUES
        .iter()
        .zip(OUTPUT_RCV)
        .enumerate()
        .map(|(id, (&v, r))| PublicOutput {
            id,
            cv: commitment(v, Scalar::from(r)),
        })
        .collect();
    let permuted: Vec<_> = PERMUTATION.iter().map(|&i| outputs[i].clone()).collect();
    let mut attack_rows = Vec::new();
    let mut delta = Scalar::zero();
    for i in 0..3 {
        let beta = Scalar::from(INPUT_RCV[i])
            - Scalar::from(OUTPUT_RCV[2 * i])
            - Scalar::from(OUTPUT_RCV[2 * i + 1]);
        delta += beta;
        let target = commitment(0, beta);
        let expected = vec![[2 * i, 2 * i + 1]];
        let actual = subset_attack(&inputs[i], &outputs, FEE, Some(target.as_inner())).unwrap();
        let shuffled = subset_attack(&inputs[i], &permuted, FEE, Some(target.as_inner())).unwrap();
        let wrong_beta = commitment(0, beta + Scalar::from(1u64));
        let beta_mismatch =
            subset_attack(&inputs[i], &outputs, FEE, Some(wrong_beta.as_inner())).unwrap();
        let fee_mismatch =
            subset_attack(&inputs[i], &outputs, FEE + 1, Some(target.as_inner())).unwrap();
        let missing = subset_attack(&inputs[i], &outputs, FEE, None).unwrap_err();
        assert_eq!(actual, expected);
        assert_eq!(shuffled, expected);
        assert!(beta_mismatch.is_empty());
        assert!(fee_mismatch.is_empty());
        assert_eq!(missing, "AttackInputMissing");
        let eligible = (0..6)
            .flat_map(|a| (a + 1..6).map(move |b| (a, b)))
            .filter(|&(a, b)| OUTPUT_VALUES[a] + OUTPUT_VALUES[b] + FEE == INPUT_VALUES[i])
            .count();
        assert_eq!(eligible, 9);
        attack_rows.push(json!({"owner_input_id":i,"candidate_pairs":15,"oracle_value_eligible_pairs":eligible,
            "point_equation_matches":actual,"permuted_matches":shuffled,"wrong_beta_matches":beta_mismatch,
            "wrong_fee_matches":fee_mismatch,"missing_beta":missing}));
    }

    let mut redacted = redacted_bundle(&inputs, &outputs, delta);
    assert!(redacted
        .spends()
        .iter()
        .all(|spend| spend.zkproof().is_some() && spend.rcv().is_none()));
    assert!(redacted
        .outputs()
        .iter()
        .all(|output| output.zkproof().is_some() && output.rcv().is_none()));
    let prover_error = redacted
        .create_proofs(&NeverProver, &NeverProver, PanicRng)
        .unwrap_err();
    assert!(matches!(
        prover_error,
        sapling::pczt::ProverError::MissingProofGenerationKey
    ));
    let finalizer_error = redacted.finalize_io(TEST_DIGEST, PanicRng).unwrap_err();
    assert!(matches!(
        finalizer_error,
        sapling::pczt::IoFinalizerError::MissingValueCommitTrapdoor
    ));

    let malformed = PcztBundle::parse(vec![], vec![], 0, [0; 32], Some([0xff; 32])).unwrap_err();
    assert!(matches!(
        malformed,
        sapling::pczt::ParseError::InvalidBindingSignatureSigningKey
    ));
    let mut rng = StdRng::from_seed([0x62; 32]);
    let bound = redacted
        .extract::<i64>()
        .unwrap()
        .unwrap()
        .apply_binding_signature(TEST_DIGEST, &mut rng)
        .expect("actual SpendAuth signatures match common test digest");
    let bvk = binding_key(&inputs, &outputs, (FEE * 3) as i64);
    let sig = &bound.authorization().binding_sig;
    assert!(bvk.verify(&TEST_DIGEST, sig).is_ok());
    let mut other_digest = TEST_DIGEST;
    other_digest[0] ^= 1;
    assert!(bvk.verify(&other_digest, sig).is_err());
    assert!(binding_key(&inputs, &outputs, (FEE * 3 + 1) as i64)
        .verify(&TEST_DIGEST, sig)
        .is_err());

    let wrong_delta = redacted_bundle(&inputs, &outputs, delta + Scalar::from(1u64))
        .extract::<i64>()
        .unwrap()
        .unwrap()
        .apply_binding_signature(TEST_DIGEST, &mut rng)
        .expect("extraction/signing does not itself compare binding key to public commitments");
    assert!(bvk
        .verify(&TEST_DIGEST, &wrong_delta.authorization().binding_sig)
        .is_err());
    let wrong_digest_extraction = redacted_bundle(&inputs, &outputs, delta)
        .extract::<i64>()
        .unwrap()
        .unwrap()
        .apply_binding_signature(other_digest, &mut rng);
    assert!(wrong_digest_extraction.is_none());

    let result: Value = json!({
        "schema":"kpi-existing-construction-api-and-curve-controls/v1",
        "classification":"PUBLIC_UNSAFE_FIXTURE_NO_GENUINE_G16_OR_VALID_TRANSACTION",
        "selected_sapling_commit":"88a7946b4a3066787776e11f0a502654167e022d",
        "source_values_and_blindings_are_public":true,
        "attack_routine_receives_no_amount_openings_or_true_pairs":true,
        "partition_certificate_controls":attack_rows,
        "input_cv_hex":inputs.iter().map(|cv| hex(&cv.to_bytes())).collect::<Vec<_>>(),
        "output_cv_hex":outputs.iter().map(|output| hex(&output.cv.to_bytes())).collect::<Vec<_>>(),
        "api_controls":{"redacted_proof_bearing_records_parsed":true,
            "actual_prover_error":format!("{prover_error:?}"),"actual_finalizer_error":format!("{finalizer_error:?}"),
            "mock_prover_or_panic_rng_reached":false,"noncanonical_external_key_error":format!("{malformed:?}"),
            "public_proof_bytes_are_non_genuine_placeholders":true},
        "standard_binding_only_controls":{"external_correct_delta_assembled_and_verified":true,
            "external_wrong_delta_assembled_but_binding_rejected":true,"wrong_value_balance_rejected":true,
            "wrong_digest_binding_rejected":true,"wrong_digest_spendauth_extraction_rejected":true},
        "new_curve_circuit_setup_proof_VM_GPU_or_network_transaction":false,
        "value_shuffle_or_masked_alternative_executed":false,
        "native_KAS_full_transaction_or_privacy_qualification":false
    });
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}
