use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey, prepare_verifying_key};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kaspa_consensus_core::tx::{Transaction, TransactionOutput, UtxoEntry};
use kpi_shared_pool::{
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
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};

fn read<T: DeserializeOwned>(p: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
fn write(p: &Path, b: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    Ok(())
}
fn save(p: &Path, v: &impl Serialize) -> Result<()> {
    let mut b = serde_json::to_vec_pretty(v)?;
    b.push(b'\n');
    write(p, &b)
}
fn dir(p: &Path) -> Result<()> {
    fs::create_dir(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn file_hash(p: &Path) -> Result<String> {
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut b = [0u8; 65536];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
fn compressed<T: CanonicalSerialize>(x: &T) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    x.serialize_compressed(&mut b)?;
    Ok(b)
}
fn decode<T: CanonicalDeserialize>(p: &Path) -> Result<T> {
    let mut f = BufReader::new(fs::File::open(p)?);
    let x = T::deserialize_compressed(&mut f)?;
    let mut b = [0];
    if f.read(&mut b)? != 0 {
        return Err("trailing parameter bytes".into());
    }
    Ok(x)
}
fn emit(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string(v)?);
    std::io::stdout().flush()?;
    Ok(())
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
    receivers: Vec<Receive>,
    funding_scripts: Vec<String>,
    parameters: Parameters,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletFile {
    wallet: Wallet,
    genesis_note: Option<Note>,
}
fn manifest(p: &Path) -> Result<(Manifest, Vec<u8>)> {
    let m: Manifest = read(&p.join("manifest.json"))?;
    let vk = fs::read(p.join("vk.bin"))?;
    check_genesis(&m.initial_state)?;
    if m.receivers.len() != 4 || m.funding_scripts.len() != 4 {
        return Err("four-wallet descriptor shape".into());
    }
    if m.network != "testnet-10"
        || m.genesis != GENESIS_HEX
        || vk.len() != 328
        || hex::encode(hash(&vk)) != m.parameters.vk_sha256
    {
        return Err("manifest network/VK identity".into());
    }
    Ok((m, vk))
}
pub(crate) fn check_genesis(state: &State) -> Result<()> {
    state.check()?;
    if state.commitments.len() != 1 || !state.nullifiers.is_empty() {
        return Err("initial descriptor must have one commitment and no nullifiers".into());
    }
    Ok(())
}
fn setup(p: &Path) -> Result<Value> {
    dir(p)?;
    let circuit = crate::fixtures::sample()?;
    let start = Instant::now();
    let (constraints, ok) = circuit.check()?;
    if !ok {
        return Err("positive circuit unsatisfied".into());
    }
    eprintln!("setup: {constraints} constraints");
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut OsRng)?;
    let mut f = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(p.join("pk.bin"))?,
    );
    pk.serialize_compressed(&mut f)?;
    f.flush()?;
    f.get_ref().sync_all()?;
    let vk = compressed(&pk.vk)?;
    write(&p.join("vk.bin"), &vk)?;
    let params = Parameters {
        pk_sha256: file_hash(&p.join("pk.bin"))?,
        vk_sha256: hex::encode(hash(&vk)),
        constraints,
        setup_ms: start.elapsed().as_millis(),
    };
    save(&p.join("parameters.json"), &params)?;
    Ok(
        json!({"parameters":params,"pk_bytes":fs::metadata(p.join("pk.bin"))?.len(),"vk_bytes":vk.len()}),
    )
}
fn init(params: &Path, root: &Path) -> Result<Value> {
    dir(root)?;
    dir(&root.join("public"))?;
    let public = root.join("public");
    let parameters: Parameters = read(&params.join("parameters.json"))?;
    for n in ["pk.bin", "vk.bin"] {
        fs::copy(params.join(n), public.join(n))?;
    }
    if file_hash(&public.join("pk.bin"))? != parameters.pk_sha256
        || file_hash(&public.join("vk.bin"))? != parameters.vk_sha256
    {
        return Err("parameter checksum".into());
    }
    let domain = new_domain();
    let wallets = (0..4).map(|_| Wallet::fresh()).collect::<Vec<_>>();
    let note = wallets[0].receive(&domain).note(RESERVE)?;
    let state = State {
        commitments: vec![note.commitment(&domain)],
        nullifiers: vec![],
    };
    let scripts = wallets
        .iter()
        .map(|w| Ok(hex::encode(native::encode_spk(&native::p2pk(&w.native)?))))
        .collect::<Result<Vec<_>>>()?;
    let m = Manifest {
        network: "testnet-10".into(),
        genesis: GENESIS_HEX.into(),
        domain,
        initial_state: state,
        receivers: wallets.iter().map(|w| w.receive(&domain)).collect(),
        funding_scripts: scripts,
        parameters,
    };
    for (i, wallet) in wallets.into_iter().enumerate() {
        let p = root.join(format!("wallet{i}"));
        dir(&p)?;
        save(
            &p.join("wallet.json"),
            &WalletFile {
                wallet,
                genesis_note: if i == 0 { Some(note.clone()) } else { None },
            },
        )?;
    }
    save(&public.join("manifest.json"), &m)?;
    Ok(json!({"network":m.network,"domain":hex::encode(domain),"wallets":4,"funded":false}))
}
fn save_tx(
    output: &Path,
    step: u32,
    tx: &Transaction,
    entries: &[UtxoEntry],
    extra: Value,
) -> Result<Value> {
    let fee = native::validate(tx, entries)?;
    let metrics = native::policy(tx, entries)?;
    let units = native::meter(tx, entries)?;
    let raw = native::tx_json(tx);
    let restored = native::parse_tx(&raw)?;
    if native::validate(&restored, entries)? != fee {
        return Err("native round trip".into());
    }
    let report = json!({"step":step,"txid":tx.id().to_string(),"full_hash":kaspa_consensus_core::hashing::tx::hash(tx).to_string(),"metrics":metrics,"script_units":units,"full_validation":true,"relay_policy":true,"extra":extra,"scope":"local native Full validation against explicit context"});
    save(&output.join(format!("{step:04}.json")), &raw)?;
    save(&output.join(format!("{step:04}.metrics.json")), &report)?;
    Ok(report)
}
fn fund(root: &Path, input: &Path, key: &Path) -> Result<Value> {
    let public = root.join("public");
    let (m, vk) = manifest(&public)?;
    let source: Utxo = read(input)?;
    let secret: H = hex::decode(fs::read_to_string(key)?.trim())?
        .try_into()
        .map_err(|_| "funding key length")?;
    let targets = m
        .funding_scripts
        .iter()
        .map(|s| {
            Ok(TransactionOutput::new(
                1_200_000_000,
                native::decode_spk(s)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let (allocation, entries) = native::ordinary(&source, &secret, targets)?;
    save(&public.join("source-utxo.json"), &source)?;
    let a = save_tx(&public, 0, &allocation, &entries, json!({}))?;
    let alice: WalletFile = read(&root.join("wallet0/wallet.json"))?;
    let reserve = kaspa_txscript::pay_to_script_hash_script(&covenant::redeem(
        &m.domain,
        &m.initial_state,
        &vk,
    )?);
    let (genesis, entries) = native::ordinary(
        &Utxo::output(&allocation, 0, 0),
        &alice.wallet.native,
        vec![TransactionOutput::new(RESERVE, reserve)],
    )?;
    let b = save_tx(&public, 1, &genesis, &entries, json!({}))?;
    Ok(json!({"allocation":a,"genesis":b}))
}
fn key(u: &Utxo) -> String {
    format!("{}:{}", u.txid, u.index)
}
struct History {
    reserve: Option<Utxo>,
    state: State,
    ledger: BTreeMap<String, Utxo>,
}
fn history(public: &Path, through: u32, m: &Manifest, vk: &[u8]) -> Result<History> {
    if through < 1 {
        return Err("history must include genesis".into());
    }
    let source: Utxo = read(&public.join("source-utxo.json"))?;
    let mut ledger = BTreeMap::from([(key(&source), source)]);
    let mut state = m.initial_state.clone();
    let mut reserve: Option<Utxo> = None;
    for n in 0..=through {
        let tx = native::parse_tx(&read(&public.join(format!("{n:04}.json")))?)?;
        if n >= 2
            && tx.inputs.first().map(|i| i.previous_outpoint.clone())
                != reserve.as_ref().map(Utxo::outpoint).transpose()?
        {
            return Err("broken reserve lineage".into());
        }
        let mut entries = Vec::new();
        for i in &tx.inputs {
            let k = format!(
                "{}:{}",
                i.previous_outpoint.transaction_id, i.previous_outpoint.index
            );
            entries.push(
                ledger
                    .remove(&k)
                    .ok_or("missing or already spent history input")?
                    .entry()?,
            );
        }
        native::validate(&tx, &entries)?;
        native::policy(&tx, &entries)?;
        for i in 0..tx.outputs.len() {
            let u = Utxo::output(&tx, i, 0);
            ledger.insert(key(&u), u);
        }
        if n == 0 {
            continue;
        }
        let mode = if n == 1 {
            if tx.outputs[0].value != RESERVE {
                return Err("genesis backing".into());
            }
            1
        } else {
            let (mode, next, _) = parse_payload(&tx.payload)?;
            state = next;
            mode
        };
        reserve = if mode == 3 {
            None
        } else {
            Some(Utxo::output(&tx, 0, 0))
        };
        if let Some(u) = &reserve {
            let spk = kaspa_txscript::pay_to_script_hash_script(&covenant::redeem(
                &m.domain, &state, vk,
            )?);
            if u.spk != hex::encode(native::encode_spk(&spk)) {
                return Err("state/rules/domain mismatch".into());
            }
        }
    }
    Ok(History {
        reserve,
        state,
        ledger,
    })
}
// Bounded-trial wallet acceptance policy at 100 sompi/gram. The circuit
// deliberately does not promise spendability under arbitrary future fee rates.
const MIN_NATIVE_PAYOUT: u64 = 10_000_000; // 0.1 tKAS; avoids native storage dust.
pub(crate) fn accept_note_value(value: u64) -> Result<()> {
    let minimum = native::fee_for(2)?.max(native::fee_for(3)?) + MIN_NATIVE_PAYOUT;
    if value < minimum {
        return Err("note cannot cover configured full-exit fee and minimum payout".into());
    }
    Ok(())
}
pub(crate) fn partition_notes(notes: Vec<(H, Note)>) -> (Vec<(H, Note)>, Vec<(H, Note)>) {
    notes
        .into_iter()
        .partition(|(_, n)| accept_note_value(n.value).is_ok())
}
fn scan(
    public: &Path,
    through: u32,
    m: &Manifest,
    w: &WalletFile,
    h: &History,
) -> Result<(Vec<(H, Note)>, Vec<(H, Note)>)> {
    let mut found = Vec::new();
    if let Some(n) = &w.genesis_note {
        let cm = n.commitment(&m.domain);
        if m.initial_state.commitments == vec![cm] {
            found.push((cm, n.clone()));
        } else {
            return Err("private genesis note mismatch".into());
        }
    }
    let mut count = 1;
    for step in 2..=through {
        let tx = native::parse_tx(&read(&public.join(format!("{step:04}.json")))?)?;
        let (mode, state, ciphers) = parse_payload(&tx.payload)?;
        let n = output_count(mode)?;
        if state.commitments.len() != count + n {
            return Err("scan append count".into());
        }
        for i in 0..n {
            let cm = state.commitments[count + i];
            if let Ok(note) = w.wallet.decrypt(&m.domain, &ciphers[i], &cm) {
                found.push((cm, note));
            }
        }
        count += n;
    }
    found.retain(|(cm, _)| {
        !h.state
            .nullifiers
            .contains(&nullifier(&m.domain, &w.wallet.spending, cm))
    });
    Ok(partition_notes(found))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    through: u32,
    kind: String,
    spend_cm: Option<String>,
    recipient: Option<Receive>,
    amount: Option<String>,
    deposit_index: Option<u32>,
}
fn operate(
    public: &Path,
    out: &Path,
    m: &Manifest,
    vk: &[u8],
    pk: &ProvingKey<Bn254>,
    w: &WalletFile,
    r: Request,
) -> Result<Value> {
    let h = history(public, r.through, m, vk)?;
    let (notes, rejected) = scan(public, r.through, m, w, &h)?;
    if r.kind == "scan" {
        return Ok(
            json!({"notes":notes.iter().map(|(cm,n)|json!({"cm":hex::encode(cm),"value":n.value.to_string()})).collect::<Vec<_>>(),"rejected_notes":rejected.iter().map(|(cm,n)|json!({"cm":hex::encode(cm),"value":n.value.to_string(),"reason":"below configured self-funded exit floor"})).collect::<Vec<_>>()}),
        );
    }
    let reserve = h.reserve.ok_or("pool already drained")?;
    let step = r.through + 1;
    let mut external = None;
    let mut input = Note::dummy();
    let mut outputs = [Note::dummy(), Note::dummy()];
    let mode;
    let fee;
    let payout;
    let reserve_out;
    let mut next = h.state.clone();
    if r.kind == "deposit" {
        mode = 0;
        fee = native::fee_for(mode)?;
        payout = 0;
        let allocation = native::parse_tx(&read(&public.join("0000.json"))?)?;
        let index = r.deposit_index.ok_or("deposit index")?;
        if index as usize >= allocation.outputs.len() {
            return Err("deposit index range".into());
        }
        let u = Utxo::output(&allocation, index as usize, 0);
        if !h.ledger.contains_key(&key(&u))
            || u.spk != hex::encode(native::encode_spk(&native::p2pk(&w.wallet.native)?))
        {
            return Err("deposit not owned/unspent".into());
        }
        let credit = u
            .amount
            .checked_sub(fee)
            .filter(|v| *v > 0)
            .ok_or("deposit fee exceeds input")?;
        outputs[0] = w.wallet.receive(&m.domain).note(credit)?;
        next.commitments.push(outputs[0].commitment(&m.domain));
        next.check()?;
        reserve_out = reserve
            .amount
            .checked_add(credit)
            .ok_or("reserve overflow")?;
        external = Some(u);
    } else {
        let cm: H = hex::decode(r.spend_cm.as_ref().ok_or("spend commitment")?)?
            .try_into()
            .map_err(|_| "commitment length")?;
        input = notes
            .iter()
            .find(|(c, _)| *c == cm)
            .ok_or("not an owned unspent note")?
            .1
            .clone();
        let requested = r.amount.as_deref().map(str::parse::<u64>).transpose()?;
        if r.kind == "transfer" {
            mode = 1;
            fee = native::fee_for(mode)?;
            payout = 0;
            let amount = requested.ok_or("payment amount")?;
            outputs[0] = r.recipient.ok_or("recipient")?.note(amount)?;
            let change = input
                .value
                .checked_sub(amount)
                .and_then(|v| v.checked_sub(fee))
                .filter(|v| *v > 0)
                .ok_or("private balance")?;
            outputs[1] = w.wallet.receive(&m.domain).note(change)?;
            reserve_out = reserve.amount.checked_sub(fee).ok_or("reserve balance")?;
        } else if r.kind == "partial" {
            mode = 4;
            fee = native::fee_for(mode)?;
            payout = requested.filter(|v| *v > 0).ok_or("partial payout")?;
            let change = input
                .value
                .checked_sub(payout)
                .and_then(|v| v.checked_sub(fee))
                .filter(|v| *v > 0)
                .ok_or("partial private balance")?;
            outputs[0] = w.wallet.receive(&m.domain).note(change)?;
            reserve_out = reserve
                .amount
                .checked_sub(payout)
                .and_then(|v| v.checked_sub(fee))
                .ok_or("partial native balance")?;
        } else if r.kind == "full" {
            mode = if input.value == reserve.amount { 3 } else { 2 };
            fee = native::fee_for(mode)?;
            payout = input
                .value
                .checked_sub(fee)
                .filter(|v| *v > 0)
                .ok_or("whole note exit fee")?;
            reserve_out = reserve
                .amount
                .checked_sub(input.value)
                .ok_or("whole native balance")?;
        } else {
            return Err("unknown operation".into());
        }
        next = h.state.spend(
            &m.domain,
            &w.wallet.spending,
            &input,
            &outputs[..output_count(mode)?],
        )?;
    }
    for note in &outputs[..output_count(mode)?] {
        accept_note_value(note.value)?;
    }
    if mode >= 2 && payout < MIN_NATIVE_PAYOUT {
        return Err("payout below trial storage-dust floor".into());
    }
    let mut ciphers = [vec![0; 185], vec![0; 185]];
    for i in 0..output_count(mode)? {
        ciphers[i] = outputs[i].encrypt(&m.domain)?;
    }
    let transition = Transition {
        domain: m.domain,
        old: h.state,
        txid: hex::decode(&reserve.txid)?
            .try_into()
            .map_err(|_| "reserve id")?,
        index: reserve.index,
        reserve_in: reserve.amount,
        reserve_out,
        payout,
        payout_spk: if mode >= 2 {
            native::encode_spk(&native::p2pk(&w.wallet.payout_key(&m.domain, step))?)
        } else {
            vec![0; 36]
        },
        deposit: if let Some(u) = &external {
            native::deposit_bytes(u)?
        } else {
            vec![0; 84]
        },
        payload: payload(mode, &next, &ciphers)?,
    };
    let circuit = SpendCircuit {
        public: transition.inputs(),
        transition,
        secret: w.wallet.spending,
        input: input.clone(),
        outputs: outputs.clone(),
        fee,
    };
    let start = Instant::now();
    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(circuit.clone(), pk, &mut OsRng)?;
    let ms = start.elapsed().as_millis();
    if !Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&pk.vk), &proof, &circuit.public)? {
        return Err("new proof failed".into());
    }
    let (mut tx, entries) = native::proof_tx(
        &circuit.transition,
        vk,
        &compressed(&proof)?,
        external.as_ref(),
    )?;
    if mode == 0 {
        native::sign(&mut tx, &entries, 1, &w.wallet.native)?;
    }
    let report = save_tx(
        out,
        step,
        &tx,
        &entries,
        json!({"proving_ms":ms,"proof_bytes":128,"vk_bytes":328}),
    )?;
    let truth = json!({"step":step,"mode":mode,"spent_cm":if mode==0{None}else{Some(hex::encode(input.commitment(&m.domain)))},"input_value":input.value.to_string(),"outputs":outputs[..output_count(mode)?].iter().map(|n|json!({"cm":hex::encode(n.commitment(&m.domain)),"value":n.value.to_string(),"owner":hex::encode(n.owner)})).collect::<Vec<_>>()});
    save(&out.join(format!("{step:04}.private.json")), &truth)?;
    Ok(json!({"report":report,"truth":truth}))
}
fn wallet_session(public: &Path, wallet: &Path, out: &Path) -> Result<()> {
    let (m, vk) = manifest(public)?;
    let w: WalletFile = read(wallet)?;
    if file_hash(&public.join("pk.bin"))? != m.parameters.pk_sha256 {
        return Err("PK checksum".into());
    }
    let start = Instant::now();
    eprintln!("validating public proving parameters");
    let pk: ProvingKey<Bn254> = decode(&public.join("pk.bin"))?;
    if compressed(&pk.vk)? != vk {
        return Err("PK/VK mismatch".into());
    }
    emit(&json!({"ready":true,"parameter_load_ms":start.elapsed().as_millis()}))?;
    for line in std::io::stdin().lock().lines() {
        let r: Request = serde_json::from_str(&line?)?;
        let result = operate(public, out, &m, &vk, &pk, &w, r)?;
        emit(&result)?;
    }
    Ok(())
}
fn validate_file(tx: &Path, context: &Path) -> Result<Value> {
    let t = native::parse_tx(&read(tx)?)?;
    let us: Vec<Utxo> = read(context)?;
    if us.len() != t.inputs.len() {
        return Err("context arity".into());
    }
    for (u, i) in us.iter().zip(&t.inputs) {
        if u.outpoint()? != i.previous_outpoint {
            return Err("context outpoint".into());
        }
    }
    let es = us.iter().map(Utxo::entry).collect::<Result<Vec<_>>>()?;
    native::validate(&t, &es)?;
    Ok(json!({"metrics":native::policy(&t,&es)?,"units":native::meter(&t,&es)?}))
}
pub fn run() -> Result<()> {
    let a = std::env::args().skip(1).collect::<Vec<_>>();
    let p = |i| -> Result<PathBuf> { Ok(PathBuf::from(a.get(i).ok_or("missing argument")?)) };
    let value=match a.first().map(String::as_str){Some("fees")=>json!({"fees":(0..5).map(|mode|native::fee_for(mode)).collect::<Result<Vec<_>>>()?,"minimum_native_payout":MIN_NATIVE_PAYOUT}),Some("setup")=>setup(&p(1)?)?,Some("init")=>init(&p(1)?,&p(2)?)?,Some("fund")=>fund(&p(1)?,&p(2)?,&p(3)?)?,Some("wallet-session")=>return wallet_session(&p(1)?,&p(2)?,&p(3)?),Some("validate")=>validate_file(&p(1)?,&p(2)?)?,Some("controls")=>controls(&p(1)?,a.get(2).ok_or("last step")?.parse()?)?,_=>return Err("setup PARAMS | init PARAMS ROOT | fund ROOT UTXO KEYFILE | wallet-session PUBLIC WALLET OUT | validate TX CONTEXT".into())};
    emit(&value)
}

fn controls(public: &Path, through: u32) -> Result<Value> {
    use kaspa_consensus_core::tx::TransactionInput;
    let (m, vk) = manifest(public)?;
    history(public, through, &m, &vk)?;
    let source: Utxo = read(&public.join("source-utxo.json"))?;
    let mut ledger = BTreeMap::from([(key(&source), source)]);
    let mut seen = std::collections::BTreeSet::new();
    let mut results = Vec::new();
    for step in 0..=through {
        let tx = native::parse_tx(&read(&public.join(format!("{step:04}.json")))?)?;
        let entries = tx
            .inputs
            .iter()
            .map(|i| {
                ledger
                    .remove(&format!(
                        "{}:{}",
                        i.previous_outpoint.transaction_id, i.previous_outpoint.index
                    ))
                    .ok_or("control history input")
                    .and_then(|u| u.entry().map_err(|_| "control entry"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        native::validate(&tx, &entries)?;
        for i in 0..tx.outputs.len() {
            let u = Utxo::output(&tx, i, 0);
            ledger.insert(key(&u), u);
        }
        if step < 2 {
            continue;
        }
        let mode = tx.payload[8];
        if !seen.insert(mode) {
            continue;
        }
        let mut reject = |name: &str, mut bad: Transaction, es: Vec<UtxoEntry>| -> Result<()> {
            bad.finalize();
            native::set_mass(&bad, &es)?;
            let error = native::validate(&bad, &es)
                .err()
                .ok_or_else(|| format!("native accepted mode {mode}: {name}"))?;
            let reserve_error = if matches!(
                name,
                "changed deposit outpoint" | "changed deposit amount" | "changed deposit owner"
            ) {
                Some(
                    native::script_units_at(&bad, &es, 0)
                        .err()
                        .ok_or("reserve input accepted deposit binding mutation")?
                        .to_string(),
                )
            } else {
                None
            };
            results.push(json!({"mode":mode,"step":step,"mutation":name,"rejected":true,"error":error.to_string(),"reserve_input_only_error":reserve_error}));
            Ok(())
        };
        let mut bad = tx.clone();
        bad.inputs[0].signature_script[2] ^= 1;
        reject("corrupt proof", bad, entries.clone())?;
        let mut bad = tx.clone();
        bad.inputs[0].previous_outpoint.transaction_id = kaspa_hashes::Hash::from_bytes([42; 32]);
        reject("wrong reserve outpoint", bad, entries.clone())?;
        let mut bad = tx.clone();
        bad.inputs[0].sequence -= 1;
        reject("noncanonical reserve sequence", bad, entries.clone())?;
        let mut bad = tx.clone();
        bad.outputs[0].value -= 1;
        reject("changed native amount", bad, entries.clone())?;
        let mut bad = tx.clone();
        bad.payload[CIPHER_START] ^= 1;
        reject("changed ciphertext or padding", bad, entries.clone())?;
        let mut bad = tx.clone();
        bad.payload[12] ^= 1;
        reject("changed state", bad, entries.clone())?;
        let mut bad = tx.clone();
        bad.outputs[0].value -= 1_000_000;
        bad.outputs
            .push(TransactionOutput::new(1_000_000, native::p2pk(&[17; 32])?));
        reject("extra native output", bad, entries.clone())?;
        let mut bad = tx.clone();
        let i = &bad.inputs[0];
        bad.inputs[0] = TransactionInput::new_with_compute_budget(
            i.previous_outpoint.clone(),
            i.signature_script.clone(),
            i.sequence,
            100,
        );
        reject("insufficient committed script budget", bad, entries.clone())?;
        let mut bad = tx.clone();
        bad.inputs[0].signature_script.insert(0, 0);
        reject("noncanonical witness", bad, entries.clone())?;
        let mut bad = tx.clone();
        let index = if mode == 2 || mode == 4 { 1 } else { 0 };
        bad.outputs[index].script_public_key = native::p2pk(&[17; 32])?;
        reject("diverted payout or successor", bad, entries.clone())?;
        for name in ["foreign domain", "altered verifier bytes"] {
            let mut bad = tx.clone();
            let mut redeem = bad.inputs[0].signature_script[133..].to_vec();
            if name == "foreign domain" {
                redeem[1] ^= 1;
            } else {
                let pos = redeem
                    .windows(vk.len())
                    .position(|x| x == vk)
                    .ok_or("VK absent")?;
                redeem[pos] ^= 1;
            }
            bad.inputs[0].signature_script[133..].copy_from_slice(&redeem);
            let mut es = entries.clone();
            es[0].script_public_key = kaspa_txscript::pay_to_script_hash_script(&redeem);
            if mode != 3 {
                let mut successor = redeem.clone();
                successor[37..37 + STATE_LEN].copy_from_slice(&bad.payload[9..CIPHER_START]);
                bad.outputs[0].script_public_key =
                    kaspa_txscript::pay_to_script_hash_script(&successor);
            }
            reject(name, bad, es)?;
        }
        if mode == 0 {
            let mut bad = tx.clone();
            bad.inputs[1].previous_outpoint.index += 1;
            reject("changed deposit outpoint", bad, entries.clone())?;
            let mut es = entries.clone();
            es[1].amount += 1;
            reject("changed deposit amount", tx.clone(), es)?;
            let mut es = entries.clone();
            es[1].script_public_key = native::p2pk(&[17; 32])?;
            reject("changed deposit owner", tx.clone(), es)?;
            let mut bad = tx.clone();
            bad.inputs[1].signature_script[2] ^= 1;
            reject("invalid depositor signature", bad, entries.clone())?;
            let mut bad = tx.clone();
            bad.inputs[1].sequence -= 1;
            reject("noncanonical deposit sequence", bad, entries.clone())?;
        }
    }
    Ok(
        json!({"positive_modes":seen,"native_rejections":results.len(),"cases":results,"scope":"local native Full validation against explicit context; no broadcasts"}),
    )
}
