//! Only fresh setup and FOUR initial proofs. No owner DRAIN/prover workflow.
use super::profile::{self, Profile};
use crate::{
    Result, native,
    protocol::{H, Note, Wallet, hash},
    two_input::{
        self, Authorization, Bundle,
        circuit::{Circuit, Input},
        tree::PublicState,
    },
};
use ark_bn254::Bn254;
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_serialize::CanonicalSerialize;
use kaspa_consensus_core::tx::TransactionOutput;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Instant,
};

const EXPECTED_CONSTRAINTS: usize = 4_372_824;

fn wallet(label: &str) -> Wallet {
    Wallet {
        spending: profile::label_hash(&format!("wallet/{label}/spending")),
        viewing: profile::label_hash(&format!("wallet/{label}/viewing")),
        native: profile::label_hash(&format!("wallet/{label}/native")),
    }
}
pub(crate) fn fresh(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    File::open(path.parent().ok_or("file parent")?)?.sync_all()?;
    Ok(())
}
fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    fresh(path, &serde_json::to_vec_pretty(value)?)
}
fn read<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn compressed(x: &impl CanonicalSerialize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    x.serialize_compressed(&mut v)?;
    Ok(v)
}
fn file_hash(path: &Path) -> Result<(String, u64)> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut h = Sha256::new();
    let mut buf = [0; 65536];
    let mut count = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        count += n as u64;
    }
    Ok((hex::encode(h.finalize()), count))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedInput {
    real: bool,
    note: Note,
    secret: H,
    position: u32,
    path: Vec<H>,
    dummy_key: H,
    dummy_seed: H,
}
impl SavedInput {
    fn from_input(x: Input) -> Self {
        Self {
            real: x.real,
            note: x.note,
            secret: x.secret,
            position: x.position,
            path: x.path,
            dummy_key: x.dummy_key,
            dummy_seed: x.dummy_seed,
        }
    }
    fn input(&self) -> Input {
        Input {
            real: self.real,
            note: self.note.clone(),
            secret: self.secret,
            position: self.position,
            path: self.path.clone(),
            dummy_key: self.dummy_key,
            dummy_seed: self.dummy_seed,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    label: String,
    bundle: Bundle,
    inputs: [SavedInput; 2],
    outputs: [Note; 2],
}
impl Statement {
    fn circuit(&self) -> Result<Circuit> {
        Ok(Circuit {
            auth: self.bundle.auth()?,
            inputs: self.inputs.each_ref().map(SavedInput::input),
            outputs: self.outputs.clone(),
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub initial_note: Note,
    pub initial_state: PublicState,
    pub pre_pair_state: PublicState,
    statements: Vec<Statement>,
}

// Producer output-consistency only. This is not an owner scanner or workflow.
fn check_recipient_delivery(statements: &[Statement]) -> Result<()> {
    if statements.len() != 4 {
        return Err("four recipient matrices".into());
    }
    let alice = wallet("alice");
    let bob = wallet("bob");
    let recipients = [
        [&alice, &alice],
        [&bob, &bob],
        [&bob, &alice],
        [&alice, &bob],
    ];
    let d = profile::domain();
    for (statement, recipients) in statements.iter().zip(recipients) {
        let auth = statement.bundle.auth()?;
        for (slot, recipient) in recipients.into_iter().enumerate() {
            let cipher = hex::decode(&statement.bundle.ciphertexts[slot])?;
            let received = recipient.decrypt(&d, &cipher, &auth.outputs[slot])?;
            if received.plaintext(&d) != statement.outputs[slot].plaintext(&d)
                || received.commitment(&d) != auth.outputs[slot]
            {
                return Err("initial fixture recipient plaintext/CM mismatch".into());
            }
        }
    }
    Ok(())
}

fn selected(w: &Wallet, n: &Note, position: u32, state: &PublicState) -> Result<Input> {
    Ok(Input {
        real: true,
        note: n.clone(),
        secret: w.spending,
        position,
        path: state.cm_tree()?.path(position)?,
        dummy_key: [0; 32],
        dummy_seed: [0; 32],
    })
}
fn statement(
    label: &str,
    state: &PublicState,
    inputs: Vec<Input>,
    outputs: [Note; 2],
    mode: u8,
    fund: Option<&native::Utxo>,
) -> Result<Statement> {
    if inputs.len() > 2 {
        return Err("initial fixture input count".into());
    }
    let ins: [Input; 2] =
        std::array::from_fn(|i| inputs.get(i).cloned().unwrap_or_else(Input::padding));
    let d = profile::domain();
    let ciphers = [outputs[0].encrypt(&d)?, outputs[1].encrypt(&d)?];
    let a = Authorization {
        domain: d,
        count: if mode == 0 {
            0
        } else {
            state.commitments.len() as u32
        },
        anchor: if mode == 0 {
            [0; 32]
        } else {
            state.cm_tree()?.root()
        },
        nfs: std::array::from_fn(|i| {
            if mode == 0 {
                [0; 32]
            } else if ins[i].real {
                crate::compact::nullifier(
                    &d,
                    &ins[i].secret,
                    &ins[i].note.commitment(&d),
                    ins[i].position,
                )
            } else {
                two_input::dummy_nf(&d, &ins[i].dummy_key, &ins[i].dummy_seed, i as u8)
            }
        }),
        outputs: outputs.each_ref().map(|n| n.commitment(&d)),
        mode,
        payout: 0,
        fee: 40_000_000,
        spk: [0; 36],
        deposit: fund.map_or(0, |u| u.amount),
        funding: if let Some(u) = fund {
            [hex::decode(&u.txid)?, u.index.to_le_bytes().to_vec()]
                .concat()
                .try_into()
                .map_err(|_| "funding point")?
        } else {
            [0; 36]
        },
        funding_spk: if let Some(u) = fund {
            hex::decode(&u.spk)?.try_into().map_err(|_| "funding spk")?
        } else {
            [0; 36]
        },
        bootstrap: if mode != 0 && state.nullifiers.len() == 1 {
            ins.iter().map(|x| x.note.value).sum()
        } else {
            0
        },
        cipher_hash: hash(&ciphers.concat()),
    };
    Ok(Statement {
        label: label.into(),
        bundle: Bundle {
            authorization: hex::encode(a.bytes()),
            proof: hex::encode([0; 128]),
            ciphertexts: ciphers.map(hex::encode),
        },
        inputs: ins.map(SavedInput::from_input),
        outputs,
    })
}

/// Lightweight generation/freeze only; setup and circuit synthesis are separate.
pub fn prepare(out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    fs::set_permissions(out, fs::Permissions::from_mode(0o700))?;
    for sub in ["public", "producer"] {
        fs::create_dir(out.join(sub))?;
    }
    let d = profile::domain();
    let alice = wallet("alice");
    let bob = wallet("bob");
    let initial = alice.receive(&d).note(800_000_000)?;
    let initial_state = PublicState::initial(initial.commitment(&d))?;
    let boot_notes = [
        alice.receive(&d).note(400_000_000)?,
        alice.receive(&d).note(360_000_000)?,
    ];
    let bootstrap = statement(
        "bootstrap",
        &initial_state,
        vec![selected(&alice, &initial, 0, &initial_state)?],
        boot_notes.clone(),
        1,
        None,
    )?;
    let (after_boot, _) = initial_state.witness(&bootstrap.bundle.auth()?)?;
    let funding_key = bob.funding_key(&d, 0);
    let funding_spk = native::p2pk(&funding_key)?;
    let bob_seed = native::Utxo {
        txid: hex::encode(profile::label_hash("supplied-bob-seed-outpoint")),
        index: 0,
        amount: 1_040_000_000,
        spk: hex::encode(native::encode_spk(&funding_spk)),
        daa: 0,
        is_coinbase: false,
    };
    let (bob_parent, entries) = native::ordinary(
        &bob_seed,
        &funding_key,
        vec![TransactionOutput::new(940_000_000, funding_spk)],
    )?;
    let bob_funding_fee = native::validate(&bob_parent, &entries)?;
    let bob_fund = native::Utxo::output(&bob_parent, 0, 0);
    let alice_seed = native::Utxo {
        txid: hex::encode(profile::label_hash("supplied-alice-seed-outpoint")),
        index: 0,
        amount: 1_000_000_000,
        spk: hex::encode(native::encode_spk(&native::p2pk(
            &alice.funding_key(&d, 0),
        )?)),
        daa: 0,
        is_coinbase: false,
    };
    let bob_notes = [
        bob.receive(&d).note(450_000_000)?,
        bob.receive(&d).note(450_000_000)?,
    ];
    let admit = statement(
        "admit",
        &after_boot,
        vec![],
        bob_notes.clone(),
        0,
        Some(&bob_fund),
    )?;
    let (pre_pair_state, _) = after_boot.witness(&admit.bundle.auth()?)?;
    let alice_spend = statement(
        "bundle-0",
        &pre_pair_state,
        vec![
            selected(&alice, &boot_notes[0], 1, &pre_pair_state)?,
            selected(&alice, &boot_notes[1], 2, &pre_pair_state)?,
        ],
        [
            bob.receive(&d).note(400_000_000)?,
            alice.receive(&d).note(320_000_000)?,
        ],
        1,
        None,
    )?;
    let bob_spend = statement(
        "bundle-1",
        &pre_pair_state,
        vec![
            selected(&bob, &bob_notes[0], 3, &pre_pair_state)?,
            selected(&bob, &bob_notes[1], 4, &pre_pair_state)?,
        ],
        [
            alice.receive(&d).note(500_000_000)?,
            bob.receive(&d).note(360_000_000)?,
        ],
        1,
        None,
    )?;
    let nfs: BTreeSet<_> = alice_spend
        .bundle
        .auth()?
        .nfs
        .into_iter()
        .chain(bob_spend.bundle.auth()?.nfs)
        .collect();
    if nfs.len() != 4 || nfs.contains(&[0; 32]) || nfs.iter().any(|nf| pre_pair_state.spent(nf)) {
        return Err("four fresh REAL paired nullifiers".into());
    }
    let plan = Plan {
        initial_note: initial.clone(),
        initial_state,
        pre_pair_state,
        statements: vec![bootstrap, admit, alice_spend, bob_spend],
    };
    check_recipient_delivery(&plan.statements)?;
    save(&out.join("producer/plan.json"), &plan)?;
    save(&out.join("producer/alice-public-test-wallet.json"), &alice)?;
    save(&out.join("producer/bob-public-test-wallet.json"), &bob)?;
    save(
        &out.join("public/supplied-seeds.json"),
        &vec![alice_seed, bob_seed],
    )?;
    save(
        &out.join("public/bob-funding.json"),
        &native::tx_json(&bob_parent),
    )?;
    save(&out.join("public/initial-state.json"), &plan.initial_state)?;
    save(
        &out.join("public/pre-pair-state.json"),
        &plan.pre_pair_state,
    )?;
    save(
        &out.join("public/constants.json"),
        &json!({"scope":"PUBLIC DO_NOT_FUND INITIAL FOUR PROOFS ONLY","domain":hex::encode(d),"pool_id":hex::encode(profile::pool_id()),"initial_commitment":hex::encode(initial.commitment(&d)),"initial_value_sompi":"800000000","admit_sompi":"940000000","pre_pair_reserve_sompi":"1660000000","post_pair_reserve_sompi":"1580000000","aggregate_pair_fee_sompi":"80000000","pool_fees_through_pair_sompi":"160000000","symbolic_full_lifecycle_only":{"inputs":"1740000000","payouts":"1500000000","fees":"240000000"},"owner_workflow_implemented":false,"chain_acceptance_verified":false,"bob_funding_fee_sompi":bob_funding_fee.to_string()}),
    )?;
    save(
        &out.join("public/prepare-manifest.json"),
        &json!({"plan_sha256":file_hash(&out.join("producer/plan.json"))?.0,"statements":4,"setup_rng":"OsRng not serialized","wallet_seeds":"PUBLIC deterministic labels; no real funds","owner_proofs":0,"native_pool_transactions":0,"scope":"partial initial fixture, not a completed owner lifecycle","amounts_are_integer_sompi":true,"recipient_matrix":[["Alice","Alice"],["Bob","Bob"],["Bob","Alice"],["Alice","Bob"]],"recipient_delivery_checked":true,"ownership":[{"label":"bootstrap","inputs":["Alice800000000"],"outputs":["Alice400000000","Alice360000000"],"fee":"40000000"},{"label":"admit","deposit":"940000000","outputs":["Bob450000000","Bob450000000"],"fee":"40000000"},{"label":"bundle-0","inputs":["Alice400000000","Alice360000000"],"outputs":["Bob400000000","Alice320000000"],"fee":"40000000"},{"label":"bundle-1","inputs":["Bob450000000","Bob450000000"],"outputs":["Alice500000000","Bob360000000"],"fee":"40000000"}]}),
    )?;
    Ok(())
}

pub fn setup_inner(out: &Path) -> Result<()> {
    let started = Instant::now();
    let manifest: Value = read(&out.join("public/prepare-manifest.json"))?;
    if manifest["plan_sha256"] != file_hash(&out.join("producer/plan.json"))?.0 {
        return Err("prepared plan changed".into());
    }
    let plan: Plan = read(&out.join("producer/plan.json"))?;
    if plan.statements.len() != 4 {
        return Err("exactly four initial statements".into());
    }
    check_recipient_delivery(&plan.statements)?;
    let first = plan.statements[0].circuit()?;
    eprintln!("stage=fresh-OsRng-setup");
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(first, &mut OsRng)?;
    let vk = compressed(&pk.vk)?;
    if vk.len() != 328 || pk.vk.gamma_abc_g1.len() != 3 {
        return Err("fresh v6 VK dimensions/arity".into());
    }
    fresh(&out.join("public/verification-key.bin"), &vk)?;
    save(
        &out.join("public/verification-profile.json"),
        &json!({"format":profile::FORMAT,"domain":hex::encode(profile::domain()),"pool_id":hex::encode(profile::pool_id()),"vk_sha256":hex::encode(hash(&vk)),"vk_bytes":vk.len(),"relation":profile::RELATION,"phase":"VK_READY_BEFORE_PUBLIC_PK_AND_PROOFS","phase_complete":true,"setup":"fresh OsRng UNTRUSTED TEST; no toxic scalars retained"}),
    )?;
    eprintln!(
        "stage=PUBLIC-VK-READY path={}",
        out.join("public/verification-key.bin").display()
    );
    let pk_path = out.join("public/proving-key.bin");
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&pk_path)?;
    let mut writer = BufWriter::with_capacity(1 << 20, file);
    pk.serialize_compressed(&mut writer)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    File::open(out.join("public"))?.sync_all()?;
    let (pk_sha256, pk_bytes) = file_hash(&pk_path)?;
    let profile = Profile {
        format: profile::FORMAT.into(),
        relation: profile::RELATION.into(),
        domain: profile::domain(),
        pool_id: profile::pool_id(),
        initial_commitment: plan.initial_note.commitment(&profile::domain()),
        initial_value_sompi: "800000000".into(),
        vk_sha256: hex::encode(hash(&vk)),
        pk_sha256,
        pk_bytes,
    };
    profile.validate(&vk)?;
    save(&out.join("public/profile.json"), &profile)?;
    eprintln!("stage=PUBLIC-PROFILE-PK-READY");
    let prepared = prepare_verifying_key(&pk.vk);
    let mut records = Vec::new();
    for (i, s) in plan.statements.iter().enumerate() {
        let c = s.circuit()?;
        let (constraints, satisfied) = c.check()?;
        if !satisfied || constraints != EXPECTED_CONSTRAINTS {
            return Err(format!(
                "statement {i} constraints/satisfaction: {constraints}/{satisfied}"
            )
            .into());
        }
        eprintln!("stage=prove-initial index={i} label={}", s.label);
        let proof =
            Groth16::<Bn254>::create_random_proof_with_reduction(c.clone(), &pk, &mut OsRng)?;
        if !Groth16::<Bn254>::verify_proof(&prepared, &proof, &c.auth.inputs())? {
            return Err("fresh initial proof rejected".into());
        }
        let proof_bytes = compressed(&proof)?;
        if proof_bytes.len() != 128 {
            return Err("proof128".into());
        }
        let mut bundle = s.bundle.clone();
        bundle.proof = hex::encode(&proof_bytes);
        save(&out.join(format!("public/{}.json", s.label)), &bundle)?;
        let raw = [c.auth.bytes(), proof_bytes, bundle.ciphers()?].concat();
        if raw.len() != 875 {
            return Err("bundle875".into());
        }
        fresh(&out.join(format!("public/{}.bin", s.label)), &raw)?;
        records.push(json!({"label":s.label,"sha256":hex::encode(hash(&raw)),"constraints":constraints,"genuine_arkworks_0_6_verified":true,"recipient_delivery_checked":true,"count":c.auth.count,"mode":c.auth.mode,"fee_sompi":c.auth.fee.to_string(),"real_inputs":c.inputs.iter().filter(|x|x.real).count(),"output_values_sompi":s.outputs.each_ref().map(|n|n.value.to_string())}));
    }
    save(
        &out.join("public/initial-proofs-manifest.json"),
        &json!({"profile":profile,"proofs":records,"proof_count":4,"owner_drain_proof_count":0,"setup_scalars_or_rng_state_retained":false,"public_pk_retained":true,"native_pool_transactions":0,"chain_acceptance_verified":false,"owner_lifecycle_complete":false,"seconds":started.elapsed().as_secs_f64()}),
    )?;
    Ok(())
}

pub fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("kpi_s7_lifecycle_fixture prepare|setup-inner NEW_OR_PREPARED_DIR".into());
    }
    match args[0].as_str() {
        "prepare" => prepare(Path::new(&args[1])),
        "setup-inner" => setup_inner(Path::new(&args[1])),
        _ => Err("unknown fixture stage; no owner or replay workflow exists".into()),
    }
}
