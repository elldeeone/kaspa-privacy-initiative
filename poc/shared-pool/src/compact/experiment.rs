//! Bounded experiment harness. Private files stay outside the repository.
use super::{circuit::AuthorizationCircuit, *};
use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey, prepare_verifying_key};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};

pub fn read<T: DeserializeOwned>(p: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
pub fn write(p: &Path, b: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    Ok(())
}
pub fn save(p: &Path, v: &impl Serialize) -> Result<()> {
    write(p, &serde_json::to_vec_pretty(v)?)
}
fn dir(p: &Path) -> Result<()> {
    fs::create_dir(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
pub(super) fn compressed<T: CanonicalSerialize>(v: &T) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    v.serialize_compressed(&mut b)?;
    Ok(b)
}
pub(super) fn decode<T: CanonicalDeserialize>(p: &Path) -> Result<T> {
    let mut f = BufReader::new(fs::File::open(p)?);
    let v = T::deserialize_compressed(&mut f)?;
    if f.read(&mut [0u8; 1])? != 0 {
        return Err("trailing parameter bytes".into());
    }
    Ok(v)
}
pub(super) fn file_hash(p: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
fn emit(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string(v)?);
    std::io::stdout().flush()?;
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fees {
    pub transfer: u64,
    pub exit: u64,
}
pub fn fees() -> Result<Fees> {
    let d=[9;32]; let vk=[0;328]; let mut values=Vec::new();
    for mode in [1,2,3] {
        let mut old=PublicState::initial([1;32])?;
        let base=|old:&PublicState,mode:u8,payout:u64| -> Result<Authorization> {Ok(Authorization {
            domain:d,count:old.commitments.len() as u32,anchor:old.cm_tree()?.root(),nullifier:[4;32],
            outputs:if mode==1 {[[5;32],[6;32]]}else{[[0;32];2]},mode,payout,fee:1,
            spk:if mode==1 {[0;36]}else{native::encode_spk(&native::p2pk(&[7;32])?).try_into().unwrap()},
            bootstrap:0,cipher_hash:hash(&[0;370])})};
        if mode==2 {let a=base(&old,1,0)?; old=old.witness(&a)?.0;}
        let mut a=base(&old,if mode==1 {1}else{2},if mode==1 {0}else if mode==3 {RESERVE-1}else{100_000_000})?;
        a.nullifier=[8;32];
        let u=native::Utxo{txid:hex::encode([8;32]),index:0,amount:RESERVE,spk:hex::encode(native::encode_spk(&pay_to_script_hash_script(&covenant::redeem(&d,&old.compact()?,&vk)?))),daa:0,is_coinbase:false};
        let bundle=Bundle {authorization:hex::encode(a.bytes()),proof:hex::encode([0;128]),ciphertexts:[hex::encode([0;185]),hex::encode([0;185])]};
        let (tx,entries)=settle(&d,&old,&u,&vk,&bundle)?;
        values.push(native::metrics(&tx,&entries)?["mining_mass"].as_u64().ok_or("mass")?*100);
    }
    let f=Fees {transfer:values[0],exit:values[1].max(values[2])};
    if f.exit+PAYOUT_FLOOR>NOTE_FLOOR {return Err(format!("note floor {} cannot cover exit {} and payout {}",NOTE_FLOOR,f.exit,PAYOUT_FLOOR).into());}
    Ok(f)
}
pub fn authorization(
    wallet: &Wallet,
    input: &Note,
    old: &PublicState,
    position: u32,
    outputs: [Note; 2],
    domain: H,
    fee: u64,
    payout: u64,
    spk: [u8; 36],
    bootstrap: u64,
) -> Result<(AuthorizationCircuit, Bundle)> {
    let mode = if payout == 0 { 1 } else { 2 };
    let ciphertexts = if mode == 1 {
        [outputs[0].encrypt(&domain)?, outputs[1].encrypt(&domain)?]
    } else {
        [vec![0; 185], vec![0; 185]]
    };
    let auth = Authorization {
        domain,
        count: old.commitments.len().try_into()?,
        anchor: old.cm_tree()?.root(),
        nullifier: nullifier(&domain, &wallet.spending, &input.commitment(&domain), position),
        outputs: if mode == 1 {
            [
                outputs[0].commitment(&domain),
                outputs[1].commitment(&domain),
            ]
        } else {
            [[0; 32]; 2]
        },
        mode,
        payout,
        fee,
        spk,
        bootstrap,
        cipher_hash: hash(&ciphertexts.concat()),
    };
    let bundle = Bundle {
        authorization: hex::encode(auth.bytes()),
        proof: String::new(),
        ciphertexts: ciphertexts.map(hex::encode),
    };
    let circuit = AuthorizationCircuit {
        public: auth.inputs(),
        auth,
        path: old.cm_tree()?.path(position)?,
        position,
        secret: wallet.spending,
        input: input.clone(),
        outputs,
    };
    Ok((circuit, bundle))
}
pub fn fixture() -> Result<(AuthorizationCircuit, Bundle)> {
    let d = hash(b"KPI/compact/unfunded-fixture/v1");
    let w = Wallet::fresh();
    let n = w.receive(&d).note(RESERVE)?;
    let old = PublicState::initial(n.commitment(&d))?;
    let f = fees()?;
    authorization(
        &w,
        &n,
        &old,
        0,
        [
            w.receive(&d).note(PAYMENT)?,
            w.receive(&d).note(RESERVE - PAYMENT - f.transfer)?,
        ],
        d,
        f.transfer,
        0,
        [0; 36],
        RESERVE,
    )
}
pub(super) fn prove(
    pk: &ProvingKey<Bn254>,
    c: AuthorizationCircuit,
    mut bundle: Bundle,
) -> Result<(Bundle, u128)> {
    let now = Instant::now();
    let inputs = c.public;
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(c, pk, &mut OsRng)?;
    if !Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&pk.vk), &proof, &inputs)? {
        return Err("local authorization proof rejected".into());
    }
    bundle.proof = hex::encode(compressed(&proof)?);
    Ok((bundle, now.elapsed().as_millis()))
}
fn setup(p: &Path) -> Result<Value> {
    dir(p)?;
    let (c, _) = fixture()?;
    let (constraints, ok) = c.check()?;
    if !ok {
        return Err("positive authorization relation unsatisfied".into());
    }
    eprintln!("compact setup: {constraints} constraints");
    let start = Instant::now();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(c, &mut OsRng)?;
    let mut out = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(p.join("pk.bin"))?,
    );
    pk.serialize_compressed(&mut out)?;
    out.flush()?;
    out.get_ref().sync_all()?;
    write(&p.join("vk.bin"), &compressed(&pk.vk)?)?;
    let v = json!({"relation":"kpi-compact-authorization-v1","constraints":constraints,"setup_ms":start.elapsed().as_millis(),
        "pk_sha256":file_hash(&p.join("pk.bin"))?,"vk_sha256":file_hash(&p.join("vk.bin"))?,"pk_bytes":fs::metadata(p.join("pk.bin"))?.len(),"fees":fees()?});
    save(&p.join("parameters.json"), &v)?;
    Ok(v)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub network: String,
    pub genesis: String,
    pub reserve: u64,
    pub domain: H,
    pub initial_state: PublicState,
    pub receivers: Vec<Receive>,
    pub parameters: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateWallet {
    pub wallet: Wallet,
    pub initial_note: Option<Note>,
}
pub(super) fn manifest(public: &Path) -> Result<(Manifest, Vec<u8>)> {
    let m: Manifest = read(&public.join("manifest.json"))?;
    let vk = fs::read(public.join("vk.bin"))?;
    m.initial_state.compact()?;
    if m.network != "testnet-10"
        || m.genesis != GENESIS_HEX
        || m.reserve < PAYMENT + 2*NOTE_FLOOR || m.reserve > MAX_SOMPI
        || m.receivers.len() != 3
        || m.initial_state.commitments.len() != 1
        || m.initial_state.nullifiers != vec![tree::NfLeaf::default()]
        || vk.len() != 328
        || m.parameters["vk_sha256"] != hex::encode(hash(&vk))
    {
        return Err("manifest identity/genesis/VK".into());
    }
    Ok((m, vk))
}
fn init(params: &Path, root: &Path, reserve: u64) -> Result<Value> {
    if reserve < PAYMENT + 2*NOTE_FLOOR || reserve > MAX_SOMPI {return Err("initial reserve range".into());}
    dir(root)?;
    let public = root.join("public");
    dir(&public)?;
    let parameters: Value = read(&params.join("parameters.json"))?;
    for name in ["pk.bin", "vk.bin"] {
        if fs::hard_link(params.join(name), public.join(name)).is_err() {
            fs::copy(params.join(name), public.join(name))?;
        }
        let key = format!("{}_sha256", name.trim_end_matches(".bin"));
        if parameters[&key] != file_hash(&public.join(name))? {
            return Err("parameter checksum".into());
        }
    }
    let domain = hash(
        &[
            b"KPI/ANCHORED/TN10/v1\0".as_slice(),
            &hex::decode(GENESIS_HEX)?,
            &random(),
        ]
        .concat(),
    );
    let wallets = [Wallet::fresh(), Wallet::fresh(), Wallet::fresh()];
    let initial = wallets[0].receive(&domain).note(reserve)?;
    let m = Manifest {
        network: "testnet-10".into(),
        genesis: GENESIS_HEX.into(),
        reserve,
        domain,
        initial_state: PublicState::initial(initial.commitment(&domain))?,
        receivers: wallets.iter().map(|w| w.receive(&domain)).collect(),
        parameters,
    };
    for (i, wallet) in wallets.into_iter().enumerate() {
        let p = root.join(format!("wallet{i}"));
        dir(&p)?;
        save(
            &p.join("wallet.json"),
            &PrivateWallet {
                wallet,
                initial_note: if i == 0 { Some(initial.clone()) } else { None },
            },
        )?;
    }
    save(&public.join("manifest.json"), &m)?;
    Ok(json!({"domain":hex::encode(domain),"network":"testnet-10","funded":false}))
}
pub(super) fn save_tx(
    public: &Path,
    step: u32,
    tx: &Transaction,
    entries: &[UtxoEntry],
    extra: Value,
) -> Result<Value> {
    native::validate(tx, entries)?;
    let metrics = native::policy(tx, entries)?;
    let units = native::meter(tx, entries)?;
    let raw = native::tx_json(tx);
    native::validate(&native::parse_tx(&raw)?, entries)?;
    save(&public.join(format!("{step:04}.json")), &raw)?;
    let v = json!({"txid":tx.id().to_string(),"full_hash":kaspa_consensus_core::hashing::tx::hash(tx).to_string(),"metrics":metrics,"script_units":units,"native_full":true,"policy":true,"extra":extra});
    save(&public.join(format!("{step:04}.metrics.json")), &v)?;
    Ok(v)
}
fn fund(root: &Path, input: &Path, key: &Path) -> Result<Value> {
    let public = root.join("public");
    let (m, vk) = manifest(&public)?;
    let source: native::Utxo = read(input)?;
    let secret: H = hex::decode(fs::read_to_string(key)?.trim())?
        .try_into()
        .map_err(|_| "funding scalar length")?;
    let (tx, entries) = native::ordinary(
        &source,
        &secret,
        vec![TransactionOutput::new(
            m.reserve,
            pay_to_script_hash_script(&covenant::redeem(&m.domain, &m.initial_state.compact()?, &vk)?),
        )],
    )?;
    save(&public.join("source-utxo.json"), &source)?;
    save_tx(&public, 0, &tx, &entries, json!({"kind":"funding"}))
}
pub struct History {
    pub state: PublicState,
    pub reserve: Option<native::Utxo>,
    pub transactions: Vec<Transaction>,
}
pub(super) fn history(public: &Path, through: u32, m: &Manifest, vk: &[u8]) -> Result<History> {
    let source: native::Utxo = read(&public.join("source-utxo.json"))?;
    let initial = native::parse_tx(&read(&public.join("0000.json"))?)?;
    if initial.inputs.len() != 1
        || initial.inputs[0].previous_outpoint != source.outpoint()?
        || initial.outputs.len() != 2
        || initial.outputs[0].value != m.reserve
        || initial.outputs[0].script_public_key
            != pay_to_script_hash_script(&covenant::redeem(&m.domain, &m.initial_state.compact()?, vk)?)
    {
        return Err("funding lineage".into());
    }
    native::validate(&initial, &[source.entry()?])?;
    let mut reserve = Some(native::Utxo::output(&initial, 0, 0));
    let mut state = m.initial_state.clone();
    let mut transactions = vec![initial];
    for step in 1..=through {
        let tx = native::parse_tx(&read(&public.join(format!("{step:04}.json")))?)?;
        let prior = reserve.as_ref().ok_or("history after terminal")?;
        if tx.inputs.len() != 1 || tx.inputs[0].previous_outpoint != prior.outpoint()? {
            return Err("reserve lineage".into());
        }
        native::validate(&tx, &[prior.entry()?])?;
        native::policy(&tx, &[prior.entry()?])?;
        let (a, next) = parse_payload(&tx.payload)?;
        let (expanded,witness)=state.witness(&a)?;
        if a.domain != m.domain || expanded.compact()? != next || tx.payload[P_WITNESS..]!=witness {
            return Err("public state reconstruction".into());
        }
        reserve = if next.cm_count == next.nf_count {
            None
        } else {
            Some(native::Utxo::output(&tx, 0, 0))
        };
        state = expanded;
        transactions.push(tx);
    }
    Ok(History {
        state,
        reserve,
        transactions,
    })
}
#[derive(Clone)]
pub(super) struct Positioned { pub position:u32, pub note:Note }
pub(super) fn scan(h: &History, m: &Manifest, w: &PrivateWallet) -> Result<Vec<Positioned>> {
    let mut notes = Vec::new();
    if let Some(n) = &w.initial_note {
        if n.commitment(&m.domain) != m.initial_state.commitments[0] {
            return Err("initial note identity".into());
        }
        notes.push(Positioned {position:0,note:n.clone()});
    }
    let mut next_position=1u32;
    for tx in &h.transactions[1..] {
        let (a, _) = parse_payload(&tx.payload)?;
        if a.mode == 1 {
            for i in 0..2 {
                if let Ok(n) = w.wallet.decrypt(
                    &m.domain,
                    &tx.payload[P_CIPHER + 185 * i..P_CIPHER + 185 * (i + 1)],
                    &a.outputs[i],
                ) {
                    if n.value < NOTE_FLOOR || n.value > MAX_SOMPI {
                        return Err("unspendable delivered note".into());
                    }
                    notes.push(Positioned {position:next_position+i as u32,note:n});
                }
            }
            next_position+=2;
        }
    }
    notes.retain(|n| {
        !h.state.spent(&nullifier(
            &m.domain,
            &w.wallet.spending,
            &n.note.commitment(&m.domain),
            n.position,
        ))
    });
    Ok(notes)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    through: u32,
    kind: String,
    label: String,
    amount: Option<String>,
    recipient: Option<usize>,
}
fn authorize(
    public: &Path,
    w: &PrivateWallet,
    out: &Path,
    pk: &ProvingKey<Bn254>,
    request: Request,
) -> Result<Value> {
    if request.label.is_empty()
        || !request
            .label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("request label".into());
    }
    let (m, vk) = manifest(public)?;
    if compressed(&pk.vk)? != vk {
        return Err("prover VK mismatch".into());
    }
    let h = history(public, request.through, &m, &vk)?;
    let mut notes = scan(&h, &m, w)?;
    if request.kind == "scan" {
        return Ok(json!({"unspent_notes":notes.len(),"reserve_remains":h.reserve.is_some()}));
    }
    if request.kind=="transfer" {notes.sort_by_key(|n|std::cmp::Reverse(n.note.value));}
    let selected = notes.first().ok_or("no spendable note")?;
    let input=&selected.note;
    let f = fees()?;
    let (outputs, fee, payout, spk) = match request.kind.as_str() {
        "transfer" => {
            let value: u64 = request.amount.ok_or("amount")?.parse()?;
            let change = input
                .value
                .checked_sub(value)
                .and_then(|v| v.checked_sub(f.transfer))
                .ok_or("private transfer overdraw")?;
            if value < NOTE_FLOOR || change < NOTE_FLOOR {
                return Err("private transfer note floor".into());
            }
            let recipient = m
                .receivers
                .get(request.recipient.ok_or("recipient")?)
                .ok_or("recipient index")?;
            (
                [
                    recipient.note(value)?,
                    w.wallet.receive(&m.domain).note(change)?,
                ],
                f.transfer,
                0,
                [0; 36],
            )
        }
        "exit" => {
            let value = input
                .value
                .checked_sub(f.exit)
                .filter(|v| *v >= PAYOUT_FLOOR)
                .ok_or("exit payout floor")?;
            let spk = native::encode_spk(&native::p2pk(
                &w.wallet.payout_key(&m.domain, request.through),
            )?)
            .try_into()
            .map_err(|_| "P2PK length")?;
            ([Note::dummy(), Note::dummy()], f.exit, value, spk)
        }
        _ => return Err("authorization kind".into()),
    };
    let (c, b) = authorization(
        &w.wallet,
        input,
        &h.state,
        selected.position,
        outputs,
        m.domain,
        fee,
        payout,
        spk,
        if request.through == 0 { m.reserve } else { 0 },
    )?;
    let (b, ms) = prove(pk, c, b)?;
    let (tx, entries) = settle(
        &m.domain,
        &h.state,
        h.reserve.as_ref().ok_or("terminal")?,
        &vk,
        &b,
    )?;
    native::validate(&tx, &entries)?;
    native::policy(&tx, &entries)?;
    save(&out.join(format!("{}.bundle.json", request.label)), &b)?;
    Ok(
        json!({"label":request.label,"proof_sha256":hex::encode(hash(&hex::decode(&b.proof)?)),"authorization_sha256":hex::encode(hash(&hex::decode(&b.authorization)?)),"proving_ms":ms,"native_preflight":true}),
    )
}
fn wallet_session(public: &Path, key: &Path, out: &Path) -> Result<()> {
    let (m, vk) = manifest(public)?;
    let start = Instant::now();
    if file_hash(&public.join("pk.bin"))? != m.parameters["pk_sha256"].as_str().ok_or("PK hash")? {
        return Err("PK checksum".into());
    }
    let pk: ProvingKey<Bn254> = decode(&public.join("pk.bin"))?;
    if compressed(&pk.vk)? != vk {
        return Err("PK/VK mismatch".into());
    }
    let w: PrivateWallet = read(key)?;
    emit(&json!({"ready":true,"parameter_load_ms":start.elapsed().as_millis()}))?;
    for line in std::io::stdin().lock().lines() {
        let request = serde_json::from_str(&line?)?;
        emit(&authorize(public, &w, out, &pk, request)?)?;
    }
    Ok(())
}
fn rebase(public: &Path, through: u32, bundle: &Path, out: &Path) -> Result<Value> {
    let start = Instant::now();
    let (m, vk) = manifest(public)?;
    let h = history(public, through, &m, &vk)?;
    let b: Bundle = read(bundle)?;
    let (tx, entries) = settle(
        &m.domain,
        &h.state,
        h.reserve.as_ref().ok_or("terminal pool")?,
        &vk,
        &b,
    )?;
    let ms = start.elapsed().as_micros();
    save_tx(
        out,
        through + 1,
        &tx,
        &entries,
        json!({"public_rebuild_us":ms,"no_proving_key_loaded":true,"no_private_inputs":true,
        "proof_sha256":hex::encode(hash(&hex::decode(&b.proof)?)),"authorization_sha256":hex::encode(hash(&hex::decode(&b.authorization)?))}),
    )
}
fn offline(params:&Path,root:&Path,payments:u32)->Result<Value> {
    init(params,root,RESERVE)?;
    let public=root.join("public");let (m,vk)=manifest(&public)?;
    let key=random();let source=native::Utxo {txid:hex::encode(random()),index:0,amount:RESERVE+10_000_000_000,spk:hex::encode(native::encode_spk(&native::p2pk(&key)?)),daa:0,is_coinbase:false};
    save(&root.join("synthetic-source.json"),&source)?;write(&root.join("synthetic-funding.key"),hex::encode(key).as_bytes())?;
    fund(root,&root.join("synthetic-source.json"),&root.join("synthetic-funding.key"))?;
    let start=Instant::now(); let pk:ProvingKey<Bn254>=decode(&params.join("pk.bin"))?;let load=start.elapsed().as_millis();
    let wallets=(0..3).map(|i|read::<PrivateWallet>(&root.join(format!("wallet{i}/wallet.json")))).collect::<Result<Vec<_>>>()?;
    let request=|through,kind:&str,label:String,amount:Option<u64>,recipient|Request {through,kind:kind.into(),label,amount:amount.map(|v|v.to_string()),recipient:Some(recipient)};
    let mut proofs=Vec::new();
    proofs.push(authorize(&public,&wallets[0],&public,&pk,request(0,"transfer","bootstrap".into(),Some(PAYMENT),1))?);
    rebase(&public,0,&public.join("bootstrap.bundle.json"),&public)?;
    proofs.push(authorize(&public,&wallets[1],&public,&pk,request(1,"exit","bob".into(),None,0))?);
    let original:Bundle=read(&public.join("bob.bundle.json"))?;
    for i in 1..=payments {
        let label=format!("payment-{i}");
        proofs.push(authorize(&public,&wallets[0],&public,&pk,request(i,"transfer",label.clone(),Some(NOTE_FLOOR),2))?);
        rebase(&public,i,&public.join(format!("{label}.bundle.json")),&public)?;
        if [1,10,100].contains(&i){eprintln!("compact offline payment {i}/100 native validated");}
    }
    let rebased=rebase(&public,payments+1,&public.join("bob.bundle.json"),&public)?;
    let tx=native::parse_tx(&read(&public.join(format!("{:04}.json",payments+2)))?)?;
    if tx.inputs[0].signature_script[2..130]!=hex::decode(&original.proof)? || tx.payload[P_AUTH..P_CIPHER]!=hex::decode(&original.authorization)? {return Err("Bob proof changed".into());}
    let mut through=payments+2;
    for owner in [2,0] {loop {
        let h=history(&public,through,&m,&vk)?;
        if scan(&h,&m,&wallets[owner])?.is_empty(){break;}
        let label=format!("cleanup-{through}");
        proofs.push(authorize(&public,&wallets[owner],&public,&pk,request(through,"exit",label.clone(),None,0))?);
        rebase(&public,through,&public.join(format!("{label}.bundle.json")),&public)?;through+=1;
        if through%25==0 {eprintln!("compact offline cleanup through {through}");}
    }}
    let h=history(&public,through,&m,&vk)?;
    if h.reserve.is_some() {return Err("offline reserve remains".into());}
    for w in &wallets {if !scan(&h,&m,w)?.is_empty(){return Err("offline claims remain".into());}}
    let controls=super::controls::run(&public)?;save(&root.join("native-controls.json"),&controls)?;
    let v=json!({"offline_pass":payments==100,"smoke_pass":true,"broadcast":false,"transactions":through+1,"payments_after_bob_authorization":payments,"private_proofs":proofs.len(),"bob_original_proof_reused":true,
        "binary_sha256":file_hash(&std::env::current_exe()?)?,"vk_sha256":hex::encode(hash(&vk)),"additional_rebase_proofs":0,"parameter_load_ms":load,"proofs":proofs,"bob_rebased":rebased,"fees":fees()?,"native_rejections":controls["native_rejections"],"all_claims_drained":true,"scope":"synthetic explicit UTXOs; not chain acceptance or real-world anonymity"});
    save(&root.join("offline-result.json"),&v)?;Ok(v)
}
pub fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let p = |i| -> Result<PathBuf> { Ok(PathBuf::from(args.get(i).ok_or("missing argument")?)) };
    let n = |i: usize| -> Result<u32> { Ok(args.get(i).ok_or("missing count")?.parse()?) };
    let v=match args.first().map(String::as_str) {
        Some("fees")=>json!({"fees":fees()?,"note_floor":NOTE_FLOOR,"payout_floor":PAYOUT_FLOOR}),
        Some("setup")=>setup(&p(1)?)?,Some("init")=>init(&p(1)?,&p(2)?,args.get(3).map(|s|s.parse()).transpose()?.unwrap_or(RESERVE))?,
        Some("fund")=>fund(&p(1)?,&p(2)?,&p(3)?)?,
        Some("wallet-session")=>return wallet_session(&p(1)?,&p(2)?,&p(3)?),
        Some("rebase")=>rebase(&p(1)?,n(2)?,&p(3)?,&p(4)?)?,
        Some("offline")=>offline(&p(1)?,&p(2)?,100)?,
        Some("smoke")=>offline(&p(1)?,&p(2)?,2)?,
        Some("controls")=>super::controls::run(&p(1)?)?,
        Some("validate")=>{let tx=native::parse_tx(&read(&p(1)?)?)?;let us:Vec<native::Utxo>=read(&p(2)?)?;
            let entries=us.iter().map(native::Utxo::entry).collect::<Result<Vec<_>>>()?;
            for (i,u) in tx.inputs.iter().zip(&us) {if i.previous_outpoint!=u.outpoint()? {return Err("context outpoint mismatch".into());}}
            native::validate(&tx,&entries)?;json!({"metrics":native::policy(&tx,&entries)?,"script_units":native::meter(&tx,&entries)?,"native_full":true})},
        _=>return Err("fees | setup PARAMS | init PARAMS ROOT | fund ROOT UTXO KEY | wallet-session PUBLIC WALLET OUT | rebase PUBLIC THROUGH BUNDLE OUT | validate TX CONTEXT".into()),
    };
    emit(&v)
}
