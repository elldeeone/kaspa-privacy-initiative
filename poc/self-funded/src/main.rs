//! Explicit local preparation commands. Broadcasting is isolated in run.mjs.
use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey, prepare_verifying_key};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kpi_self_funded::{
    Result,
    circuit::SpendCircuit,
    covenant,
    native::{self, Utxo},
    protocol::*,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};

fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut b = serde_json::to_vec_pretty(value)?;
    b.push(b'\n');
    write(path, &b)
}
fn directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn file_hash(path: &Path) -> Result<String> {
    let mut r = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
fn compressed<T: CanonicalSerialize>(x: &T) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    x.serialize_compressed(&mut b)?;
    Ok(b)
}
fn decode<T: CanonicalDeserialize>(path: &Path) -> Result<T> {
    let mut f = BufReader::new(fs::File::open(path)?);
    let result = T::deserialize_compressed(&mut f)?;
    let mut byte = [0u8; 1];
    if f.read(&mut byte)? != 0 {
        return Err("trailing cryptographic parameter bytes".into());
    }
    Ok(result)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    pk_sha256: String,
    vk_sha256: String,
    constraints: usize,
    setup_ms: u128,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    network: String,
    genesis: String,
    domain: H,
    initial_state: State,
    alice: Receive,
    bob: Receive,
    alice_address: String,
    bob_address: String,
    reserve_address: String,
    parameters: Parameters,
}
fn manifest(public: &Path) -> Result<(Manifest, Vec<u8>)> {
    let m: Manifest = read(&public.join("manifest.json"))?;
    if m.network != "testnet-10" || m.genesis != GENESIS_HEX {
        return Err("manifest is not TN10".into());
    }
    let vk = fs::read(public.join("vk.bin"))?;
    if vk.len() != 328 || hex::encode(hash(&vk)) != m.parameters.vk_sha256 {
        return Err("verification-key identity mismatch".into());
    }
    Ok((m, vk))
}
fn sample() -> SpendCircuit {
    let d = hash(b"KPI/self-funded/unfunded-circuit-fixture");
    let a = Wallet {
        spending: [1; 32],
        viewing: [2; 32],
        native: [3; 32],
    };
    let b = Wallet {
        spending: [4; 32],
        viewing: [5; 32],
        native: [6; 32],
    };
    let input = a.receive(&d).note(RESERVE).unwrap();
    let fee = fee(1);
    let outputs = [
        b.receive(&d).note(PAYMENT).unwrap(),
        a.receive(&d).note(RESERVE - PAYMENT - fee).unwrap(),
    ];
    let old = State {
        commitments: vec![input.commitment(&d)],
        nullifiers: vec![],
    };
    let next = old.spend(&d, &a.spending, &input, &outputs).unwrap();
    let t = Transition {
        domain: d,
        old,
        txid: [7; 32],
        index: 0,
        reserve_in: RESERVE,
        reserve_out: RESERVE - fee,
        payout: 0,
        payout_spk: vec![0; 36],
        payload: payload(
            1,
            &next,
            &[
                outputs[0].encrypt(&d).unwrap(),
                outputs[1].encrypt(&d).unwrap(),
            ],
        )
        .unwrap(),
    };
    SpendCircuit {
        public: t.inputs(),
        transition: t,
        secret: a.spending,
        input,
        outputs,
        fee,
    }
}
fn fee(mode: u8) -> u64 {
    let (overhead, spk_mass) = match mode {
        1 => (334, 370),
        2 => (386, 730),
        3 => (333, 360),
        _ => panic!("internal spend mode"),
    };
    100 * (covenant::REDEEM_LEN as u64
        + PAYLOAD_LEN as u64
        + overhead
        + spk_mass
        + 100 * u64::from(covenant::BUDGET))
}
fn setup(dir: &Path) -> Result<Value> {
    directory(dir)?;
    let circuit = sample();
    let started = Instant::now();
    eprintln!("checking complete circuit relation");
    let (constraints, satisfied) = circuit.check()?;
    if !satisfied {
        return Err("positive circuit fixture unsatisfied".into());
    }
    eprintln!("generating fresh experimental parameters ({constraints} constraints)");
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut OsRng)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("pk.bin"))?;
    let mut writer = BufWriter::new(file);
    pk.serialize_compressed(&mut writer)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    let vk = compressed(&pk.vk)?;
    if vk.len() != 328 {
        return Err("VK arity/encoding".into());
    }
    write(&dir.join("vk.bin"), &vk)?;
    let params = Parameters {
        pk_sha256: file_hash(&dir.join("pk.bin"))?,
        vk_sha256: hex::encode(hash(&vk)),
        constraints,
        setup_ms: started.elapsed().as_millis(),
    };
    save(&dir.join("parameters.json"), &params)?;
    Ok(
        json!({"setup":params,"pk_bytes":fs::metadata(dir.join("pk.bin"))?.len(),"vk_bytes":vk.len(),"scope":"fresh single-party experimental setup, no funding"}),
    )
}
fn init(params: &Path, root: &Path) -> Result<Value> {
    directory(root)?;
    for sub in ["public", "alice", "bob"] {
        directory(&root.join(sub))?;
    }
    let public = root.join("public");
    let parameters: Parameters = read(&params.join("parameters.json"))?;
    for name in ["pk.bin", "vk.bin"] {
        fs::copy(params.join(name), public.join(name))?;
    }
    if file_hash(&public.join("pk.bin"))? != parameters.pk_sha256
        || file_hash(&public.join("vk.bin"))? != parameters.vk_sha256
    {
        return Err("parameter copy checksum".into());
    }
    let d = new_domain();
    let alice = Wallet::fresh();
    let bob = Wallet::fresh();
    let input = alice.receive(&d).note(RESERVE)?;
    let old = State {
        commitments: vec![input.commitment(&d)],
        nullifiers: vec![],
    };
    let vk = fs::read(public.join("vk.bin"))?;
    let redeem = covenant::redeem(&d, &old, &vk)?;
    let m = Manifest {
        network: "testnet-10".into(),
        genesis: GENESIS_HEX.into(),
        domain: d,
        initial_state: old,
        alice: alice.receive(&d),
        bob: bob.receive(&d),
        alice_address: native::address(&native::p2pk(&alice.native)?)?,
        bob_address: native::address(&native::p2pk(&bob.native)?)?,
        reserve_address: native::address(&kaspa_txscript::pay_to_script_hash_script(&redeem))?,
        parameters,
    };
    save(&root.join("alice/wallet.json"), &alice)?;
    save(&root.join("alice/genesis-note.json"), &input)?;
    save(&root.join("bob/wallet.json"), &bob)?;
    save(&public.join("manifest.json"), &m)?;
    Ok(
        json!({"network":m.network,"domain":hex::encode(d),"reserve_address":m.reserve_address,"alice_address":m.alice_address,"bob_address":m.bob_address,"redeem_bytes":redeem.len()}),
    )
}
fn save_transaction(
    public: &Path,
    label: &str,
    tx: &kaspa_consensus_core::tx::Transaction,
    entry: &kaspa_consensus_core::tx::UtxoEntry,
    allow_low_fee: bool,
    extra: Value,
) -> Result<Value> {
    let consensus_fee = native::validate(tx, entry)?;
    let units = native::meter(tx, entry)?;
    let metrics = native::metrics(tx, entry)?;
    let policy = native::policy(tx, entry);
    if !allow_low_fee {
        policy.as_ref().map_err(|e| e.to_string())?;
    } else if policy.is_ok() {
        return Err("low-fee negative unexpectedly passes policy".into());
    }
    let raw = native::tx_json(tx);
    let restored = native::parse_tx(&raw)?;
    if native::validate(&restored, entry)? != consensus_fee {
        return Err("native round-trip fee mismatch".into());
    }
    let result = json!({"label":label,"txid":tx.id().to_string(),"full_hash":kaspa_consensus_core::hashing::tx::hash(tx).to_string(),"metrics":metrics,"used_script_units":units,"full_validation":true,"relay_policy":policy.is_ok(),"policy_error":policy.err().map(|e|e.to_string()),"extra":extra,"scope":"local native Full validation against explicit UTXO, not chain acceptance"});
    save(&public.join(format!("{label}.json")), &raw)?;
    save(&public.join(format!("{label}.metrics.json")), &result)?;
    Ok(result)
}
fn fund(root: &Path, input_file: &Path, key_file: &Path) -> Result<Value> {
    let public = root.join("public");
    let (m, vk) = manifest(&public)?;
    let input: Utxo = read(input_file)?;
    let key: H = hex::decode(fs::read_to_string(key_file)?.trim())?
        .try_into()
        .map_err(|_| "funding key length")?;
    let spk = kaspa_txscript::pay_to_script_hash_script(&covenant::redeem(
        &m.domain,
        &m.initial_state,
        &vk,
    )?);
    let (tx, entry) = native::funding(&input, &key, spk, 100)?;
    save(&public.join("source-utxo.json"), &input)?;
    let report = save_transaction(&public, "funding", &tx, &entry, false, json!({}))?;
    Ok(report)
}
fn chain(public: &Path, through: &str, vk: &[u8], m: &Manifest) -> Result<(Utxo, State)> {
    let source: Utxo = read(&public.join("source-utxo.json"))?;
    let mut current = source;
    let mut state = m.initial_state.clone();
    for label in ["funding", "payment", "bob-exit"] {
        let raw: Value = read(&public.join(format!("{label}.json")))?;
        let tx = native::parse_tx(&raw)?;
        if tx.inputs.len() != 1 || tx.inputs[0].previous_outpoint != current.outpoint()? {
            return Err("broken canonical instance lineage".into());
        }
        native::validate(&tx, &current.entry()?)?;
        native::policy(&tx, &current.entry()?)?;
        if label != "funding" {
            state = parse_payload(&tx.payload)?.1;
        } else if tx.outputs[0].value != RESERVE {
            return Err("genesis reserve value".into());
        }
        current = Utxo::output(&tx, 0, 0);
        let expected =
            kaspa_txscript::pay_to_script_hash_script(&covenant::redeem(&m.domain, &state, vk)?);
        if current.spk != hex::encode(native::encode_spk(&expected)) {
            return Err("state/VK/domain and native reserve disagree".into());
        }
        if label == through {
            return Ok((current, state));
        }
    }
    Err("unknown continuing state label".into())
}
fn prove(
    public: &Path,
    circuit: SpendCircuit,
    label: &str,
    low: bool,
    output: &Path,
) -> Result<Value> {
    let (m, vk_bytes) = manifest(public)?;
    if file_hash(&public.join("pk.bin"))? != m.parameters.pk_sha256 {
        return Err("proving parameter checksum".into());
    }
    let pk: ProvingKey<Bn254> = decode(&public.join("pk.bin"))?;
    if compressed(&pk.vk)? != vk_bytes {
        return Err("proving and verifying keys disagree".into());
    }
    let started = Instant::now();
    eprintln!("proving {label}");
    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(circuit.clone(), &pk, &mut OsRng)?;
    let prove_ms = started.elapsed().as_millis();
    if !Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&pk.vk), &proof, &circuit.public)? {
        return Err("new proof failed standalone verification".into());
    }
    let bytes = compressed(&proof)?;
    if bytes.len() != 128 {
        return Err("proof length".into());
    }
    let (tx, entry) = native::proof_tx(&circuit.transition, &vk_bytes, &bytes)?;
    let report = save_transaction(
        output,
        label,
        &tx,
        &entry,
        low,
        json!({"proving_ms":prove_ms,"proof_bytes":bytes.len(),"vk_bytes":vk_bytes.len()}),
    )?;
    Ok(report)
}
fn pay(root: &Path, label: &str, low: bool) -> Result<Value> {
    let public = root.join("public");
    let (m, vk) = manifest(&public)?;
    let (utxo, old) = chain(&public, "funding", &vk, &m)?;
    let wallet: Wallet = read(&root.join("alice/wallet.json"))?;
    let input: Note = read(&root.join("alice/genesis-note.json"))?;
    let fee = fee(1) - u64::from(low);
    let outputs = [
        m.bob.note(PAYMENT)?,
        m.alice.note(
            input
                .value
                .checked_sub(PAYMENT)
                .and_then(|v| v.checked_sub(fee))
                .ok_or("payment balance")?,
        )?,
    ];
    let next = old.spend(&m.domain, &wallet.spending, &input, &outputs)?;
    let t = Transition {
        domain: m.domain,
        old,
        txid: hex::decode(&utxo.txid)?.try_into().map_err(|_| "txid")?,
        index: utxo.index,
        reserve_in: utxo.amount,
        reserve_out: utxo.amount.checked_sub(fee).ok_or("native fee")?,
        payout: 0,
        payout_spk: vec![0; 36],
        payload: payload(
            1,
            &next,
            &[
                outputs[0].encrypt(&m.domain)?,
                outputs[1].encrypt(&m.domain)?,
            ],
        )?,
    };
    let c = SpendCircuit {
        public: t.inputs(),
        transition: t,
        secret: wallet.spending,
        input,
        outputs,
        fee,
    };
    prove(&public, c, label, low, &public)
}
fn exit(public: &Path, key: &Path, through: &str, label: &str, output: &Path) -> Result<Value> {
    let (m, vk) = manifest(public)?;
    let (utxo, old) = chain(public, through, &vk, &m)?;
    let wallet: Wallet = read(key)?;
    let payment: Value = read(&public.join("payment.json"))?;
    let payment = native::parse_tx(&payment)?;
    let (_, payment_state, ciphertexts) = parse_payload(&payment.payload)?;
    let mut found = Vec::new();
    for (i, ciphertext) in ciphertexts.iter().enumerate() {
        if let Ok(note) = wallet.decrypt(&m.domain, ciphertext, &payment_state.commitments[i + 1]) {
            found.push(note);
        }
    }
    if found.len() != 1 {
        return Err("expected exactly one authenticated received note".into());
    }
    let input = found.remove(0);
    let reserve_out = utxo
        .amount
        .checked_sub(input.value)
        .ok_or("note exceeds native reserve")?;
    let mode = if reserve_out == 0 { 3 } else { 2 };
    let fee = fee(mode);
    let payout = input
        .value
        .checked_sub(fee)
        .filter(|v| *v > 0)
        .ok_or("note cannot pay exit fee")?;
    let next = old.spend(&m.domain, &wallet.spending, &input, &[])?;
    let t = Transition {
        domain: m.domain,
        old,
        txid: hex::decode(&utxo.txid)?.try_into().map_err(|_| "txid")?,
        index: utxo.index,
        reserve_in: utxo.amount,
        reserve_out,
        payout,
        payout_spk: native::encode_spk(&native::p2pk(&wallet.native)?),
        payload: payload(mode, &next, &[vec![0; 185], vec![0; 185]])?,
    };
    let c = SpendCircuit {
        public: t.inputs(),
        transition: t,
        secret: wallet.spending,
        input,
        outputs: [Note::dummy(), Note::dummy()],
        fee,
    };
    prove(public, c, label, false, output)
}
fn validate_file(tx_file: &Path, utxo_file: &Path) -> Result<Value> {
    let raw: Value = read(tx_file)?;
    let tx = native::parse_tx(&raw)?;
    let u: Utxo = read(utxo_file)?;
    if tx.inputs.len() != 1 || tx.inputs[0].previous_outpoint != u.outpoint()? {
        return Err("supplied UTXO outpoint mismatch".into());
    }
    let e = u.entry()?;
    native::validate(&tx, &e)?;
    Ok(
        json!({"txid":tx.id().to_string(),"metrics":native::policy(&tx,&e)?,"script_units":native::meter(&tx,&e)?}),
    )
}

fn controls(public: &Path) -> Result<Value> {
    use kaspa_consensus_core::tx::{Transaction, TransactionInput, TransactionOutput, UtxoEntry};
    let mut results = Vec::new();
    let mut reject =
        |label: &str, name: &str, mut tx: Transaction, entry: UtxoEntry| -> Result<()> {
            tx.finalize();
            native::set_mass(&tx, &entry)?;
            let error = native::validate(&tx, &entry)
                .err()
                .ok_or_else(|| format!("native accepted {label}: {name}"))?;
            results.push(
            json!({"transaction":label,"mutation":name,"rejected":true,"error":error.to_string()}),
        );
            Ok(())
        };
    for (label, predecessor) in [
        ("payment", "funding"),
        ("bob-exit", "payment"),
        ("alice-exit", "bob-exit"),
    ] {
        let tx = native::parse_tx(&read(&public.join(format!("{label}.json")))?)?;
        let prior = native::parse_tx(&read(&public.join(format!("{predecessor}.json")))?)?;
        let entry = Utxo::output(&prior, 0, 0).entry()?;
        native::validate(&tx, &entry)?;
        let mut bad = tx.clone();
        bad.inputs[0].signature_script[2] ^= 1;
        reject(label, "corrupt proof", bad, entry.clone())?;
        let mut bad = tx.clone();
        bad.inputs[0].previous_outpoint.transaction_id = kaspa_hashes::Hash::from_bytes([42; 32]);
        reject(
            label,
            "proof bound to another predecessor",
            bad,
            entry.clone(),
        )?;
        let mut bad = tx.clone();
        bad.inputs[0].sequence -= 1;
        reject(label, "noncanonical sequence", bad, entry.clone())?;
        let mut bad = tx.clone();
        bad.outputs[0].value -= 1;
        reject(label, "changed native amount", bad, entry.clone())?;
        let mut bad = tx.clone();
        bad.payload[268] ^= 1;
        reject(
            label,
            "changed ciphertext or exit padding",
            bad,
            entry.clone(),
        )?;
        let mut bad = tx.clone();
        bad.payload[12] ^= 1;
        reject(label, "changed state", bad, entry.clone())?;
        let mut bad = tx.clone();
        bad.outputs[0].value -= 10_000_000;
        bad.outputs
            .push(TransactionOutput::new(10_000_000, native::p2pk(&[17; 32])?));
        reject(label, "extra native output", bad, entry.clone())?;
        let mut bad = tx.clone();
        let i = &bad.inputs[0];
        bad.inputs[0] = TransactionInput::new_with_compute_budget(
            i.previous_outpoint.clone(),
            i.signature_script.clone(),
            i.sequence,
            100,
        );
        reject(
            label,
            "insufficient committed script budget",
            bad,
            entry.clone(),
        )?;
        let mut bad = tx.clone();
        bad.inputs[0].signature_script.insert(0, 0);
        reject(label, "noncanonical witness framing", bad, entry.clone())?;
        let mut bad = tx.clone();
        let i = if label == "bob-exit" { 1 } else { 0 };
        bad.outputs[i].script_public_key = native::p2pk(&[17; 32])?;
        reject(
            label,
            if label == "payment" {
                "wrong successor covenant"
            } else {
                "diverted payout"
            },
            bad,
            entry.clone(),
        )?;
        // Rebuild a valid P2SH wrapper around modified immutable code. The
        // old proof must still fail even when the wrapper itself matches.
        for name in ["foreign domain", "altered verifier bytes"] {
            let mut bad = tx.clone();
            let mut redeem = bad.inputs[0].signature_script[133..].to_vec();
            if name == "altered verifier bytes" {
                let vk = fs::read(public.join("vk.bin"))?;
                let pos = redeem
                    .windows(vk.len())
                    .position(|x| x == vk)
                    .ok_or("VK absent from redeem")?;
                redeem[pos] ^= 1;
            } else {
                redeem[1] ^= 1;
            }
            bad.inputs[0].signature_script[133..].copy_from_slice(&redeem);
            let mut other = entry.clone();
            other.script_public_key = kaspa_txscript::pay_to_script_hash_script(&redeem);
            if label != "alice-exit" {
                let mut successor = redeem.clone();
                successor[37..296].copy_from_slice(&bad.payload[9..268]);
                bad.outputs[0].script_public_key =
                    kaspa_txscript::pay_to_script_hash_script(&successor);
            }
            reject(label, name, bad, other)?;
        }
    }
    Ok(
        json!({"positive_transactions":3,"native_rejections":results.len(),"cases":results,"scope":"local native Full validation; no broadcasts"}),
    )
}

fn run() -> Result<Value> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let p =
        |i: usize| -> Result<PathBuf> { Ok(PathBuf::from(args.get(i).ok_or("missing argument")?)) };
    match args.first().map(String::as_str){
        Some("setup")=>setup(&p(1)?),Some("init")=>init(&p(1)?,&p(2)?),
        Some("fund")=>fund(&p(1)?,&p(2)?,&p(3)?),
        Some("pay")=>pay(&p(1)?,"payment",false),Some("pay-low-fee")=>pay(&p(1)?,"low-fee",true),Some("pay-alternative")=>pay(&p(1)?,"alternative",false),
        Some("exit")=>exit(&p(1)?,&p(2)?,args.get(3).ok_or("missing prior label")?,args.get(4).ok_or("missing output label")?,&p(5)?),
        Some("validate")=>validate_file(&p(1)?,&p(2)?),Some("controls")=>controls(&p(1)?),
        _=>Err("commands: setup PARAMS | init PARAMS TRIAL | fund TRIAL UTXO KEYFILE | pay TRIAL | pay-low-fee TRIAL | pay-alternative TRIAL | exit PUBLIC WALLET PRIOR LABEL OUTPUT | validate TX UTXO".into()),
    }
}
fn main() {
    match run() {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(e) => {
            eprintln!("self-funded trial: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;
    fn check(c: &SpendCircuit) -> bool {
        c.check().unwrap().1
    }
    #[test]
    fn complete_relation_rejects_adversarial_witnesses() {
        let c = sample();
        assert!(check(&c));
        let mut cases: Vec<(&str, SpendCircuit)> = Vec::new();
        let mut x = c.clone();
        x.secret[0] ^= 1;
        cases.push(("wrong spending authority", x));
        let mut x = c.clone();
        x.input.value = 0;
        cases.push(("zero-valued input", x));
        let mut x = c.clone();
        x.outputs[1].value = u64::MAX;
        cases.push(("u64 output overflow", x));
        let mut x = c.clone();
        x.fee = 0;
        cases.push(("zero private fee", x));
        let mut x = c.clone();
        x.fee += 1;
        cases.push(("private/native fee mismatch", x));
        let mut x = c.clone();
        x.transition.reserve_in -= 1;
        x.transition.reserve_out -= 1; // Keep native conservation valid.
        x.public = x.transition.inputs();
        cases.push(("underbacked genesis", x));
        let mut x = c.clone();
        x.transition.old.commitments[0] = [9; 32];
        x.public = x.transition.inputs();
        cases.push(("non-member input", x));
        let mut x = c.clone();
        x.transition.old.nullifiers.push(nullifier(
            &x.transition.domain,
            &x.secret,
            &x.input.commitment(&x.transition.domain),
        ));
        // Preserve the old spentness entry and append the attempted duplicate.
        // Count and persistence are correct; duplicate/spentness must reject it.
        x.transition.payload[11] = 2;
        let nf = x.transition.old.nullifiers[0];
        x.transition.payload[172..204].copy_from_slice(&nf);
        x.public = x.transition.inputs();
        cases.push(("already-nullified input", x));
        let mut x = c.clone();
        x.transition.payload[9 + 131] ^= 1;
        x.public = x.transition.inputs();
        cases.push(("wrong inserted nullifier", x));
        let mut x = c.clone();
        x.transition.payload[9 + 3] ^= 1;
        x.public = x.transition.inputs();
        cases.push(("old commitment overwritten", x));
        let mut x = c.clone();
        x.transition.payload[9 + 3 + 96] = 1;
        x.public = x.transition.inputs();
        cases.push(("nonzero unused slot", x));
        let mut x = c.clone();
        x.transition.domain[0] ^= 1;
        x.public = x.transition.inputs();
        cases.push(("foreign pool domain", x));
        let mut x = c.clone();
        x.transition.payload[8] = 4;
        x.public = x.transition.inputs();
        cases.push(("unknown mode", x));
        let mut x = c.clone();
        x.transition.payload[268] ^= 1;
        cases.push(("ciphertext not bound to public digest", x));
        let mut x = c.clone();
        x.transition.txid[0] ^= 1;
        cases.push(("stale predecessor public digest", x));
        let mut x = c.clone();
        let mut high = [0; 17];
        high[16] = 1;
        x.public[0] = ark_bn254::Fr::from_le_bytes_mod_order(&high);
        cases.push(("public limb exceeds 128 bits", x));
        for (name, x) in cases {
            eprintln!("circuit negative: {name}");
            assert!(!check(&x), "accepted {name}");
        }
    }
    fn exit_sample() -> SpendCircuit {
        let payment = sample();
        let old = parse_payload(&payment.transition.payload).unwrap().1;
        let input = payment.outputs[0].clone();
        let secret = [4; 32];
        let next = old
            .spend(&payment.transition.domain, &secret, &input, &[])
            .unwrap();
        let transition = Transition {
            domain: payment.transition.domain,
            old,
            txid: [8; 32],
            index: 0,
            reserve_in: payment.transition.reserve_out,
            reserve_out: payment.transition.reserve_out - input.value,
            payout: input.value - fee(2),
            payout_spk: native::encode_spk(&native::p2pk(&[6; 32]).unwrap()),
            payload: payload(2, &next, &[vec![0; 185], vec![0; 185]]).unwrap(),
        };
        SpendCircuit {
            public: transition.inputs(),
            transition,
            secret,
            input,
            outputs: [Note::dummy(), Note::dummy()],
            fee: fee(2),
        }
    }
    #[test]
    fn exits_enforce_backing_and_terminal_exhaustion() {
        let exit = exit_sample();
        assert!(check(&exit));
        let mut invalid = exit.clone();
        invalid.transition.payout += 1;
        invalid.transition.reserve_out -= 1;
        invalid.public = invalid.transition.inputs();
        assert!(
            !check(&invalid),
            "unauthorized payout with native balance preserved"
        );
        let mut invalid = exit.clone();
        invalid.transition.payload[8] = 3;
        invalid.public = invalid.transition.inputs();
        assert!(!check(&invalid), "nonfinal terminal exit");
        let payment = sample();
        let d = payment.transition.domain;
        let bob = payment.outputs[0].clone();
        let alice = payment.outputs[1].clone();
        let old = parse_payload(&payment.transition.payload).unwrap().1;
        let old = old.spend(&d, &[4; 32], &bob, &[]).unwrap();
        let next = old.spend(&d, &[1; 32], &alice, &[]).unwrap();
        let transition = Transition {
            domain: d,
            old,
            txid: [9; 32],
            index: 0,
            reserve_in: alice.value,
            reserve_out: 0,
            payout: alice.value - fee(3),
            payout_spk: native::encode_spk(&native::p2pk(&[3; 32]).unwrap()),
            payload: payload(3, &next, &[vec![0; 185], vec![0; 185]]).unwrap(),
        };
        let terminal = SpendCircuit {
            public: transition.inputs(),
            transition,
            secret: [1; 32],
            input: alice,
            outputs: [Note::dummy(), Note::dummy()],
            fee: fee(3),
        };
        assert!(check(&terminal));
        let mut invalid = terminal.clone();
        // Add another unspent commitment consistently to old/new state. The
        // whole-note balance still holds but terminal exhaustion must fail.
        invalid.transition.old.commitments.push([21; 32]);
        invalid.transition.payload[10] = 4;
        invalid.transition.payload[108..140].copy_from_slice(&[21; 32]);
        invalid.public = invalid.transition.inputs();
        assert!(
            !check(&invalid),
            "terminal leaves an outstanding commitment"
        );
        let mut invalid = terminal.clone();
        invalid.transition.reserve_in += 1;
        invalid.transition.reserve_out = 1;
        invalid.public = invalid.transition.inputs();
        assert!(!check(&invalid), "terminal strands native reserve");
    }
    #[test]
    fn confidential_delivery_and_state_encoding() {
        let d = new_domain();
        let a = Wallet::fresh();
        let b = Wallet::fresh();
        let note = a.receive(&d).note(1234).unwrap();
        let cm = note.commitment(&d);
        let encrypted = note.encrypt(&d).unwrap();
        assert_eq!(encrypted.len(), 185);
        assert_eq!(a.decrypt(&d, &encrypted, &cm).unwrap().value, 1234);
        assert!(b.decrypt(&d, &encrypted, &cm).is_err());
        assert!(a.decrypt(&random(), &encrypted, &cm).is_err());
        assert!(a.decrypt(&d, &encrypted, &random()).is_err());
        let s = State {
            commitments: vec![cm],
            nullifiers: vec![],
        };
        assert_eq!(State::parse(&s.bytes()).unwrap(), s);
        let mut malformed = s.bytes();
        malformed[35] = 1;
        assert!(State::parse(&malformed).is_err());
        let spent = s.spend(&d, &a.spending, &note, &[]).unwrap();
        assert!(spent.spend(&d, &a.spending, &note, &[]).is_err());
    }
    #[test]
    fn native_preconditions_reject_malformed_amounts_without_panicking() {
        let wallet = Wallet::fresh();
        let spk = native::p2pk(&wallet.native).unwrap();
        let source = Utxo {
            txid: hex::encode([3; 32]),
            index: 0,
            amount: 20_000_000_000,
            spk: hex::encode(native::encode_spk(&spk)),
            daa: 0,
            is_coinbase: false,
        };
        let (tx, entry) = native::funding(&source, &wallet.native, spk, 100).unwrap();
        assert!(native::validate(&tx, &entry).is_ok());
        let mut bad = tx.clone();
        bad.outputs[0].value = 0;
        assert!(native::set_mass(&bad, &entry).is_err());
        let mut bad = tx.clone();
        bad.outputs[0].value = MAX_SOMPI;
        bad.outputs[1].value = MAX_SOMPI;
        assert!(native::metrics(&bad, &entry).is_err());
        let mut bad = tx.clone();
        bad.inputs.clear();
        assert!(native::meter(&bad, &entry).is_err());
        let mut raw = native::tx_json(&tx);
        raw["outputs"][0]["value"] = json!("01");
        assert!(native::parse_tx(&raw).is_err());
        let mut raw = native::tx_json(&tx);
        raw["id"] = json!(hex::encode([0; 32]));
        assert!(native::parse_tx(&raw).is_err());
        let mut raw = native::tx_json(&tx);
        raw["unexpected"] = json!(true);
        assert!(native::parse_tx(&raw).is_err());
    }
}
