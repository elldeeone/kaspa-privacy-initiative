//! Offline synthetic UTXOs with genuine proofs and native validation.
mod study;
use super::*;
use crate::compact::experiment::{read, save, write};
use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey, prepare_verifying_key};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use circuit::{Circuit, Input};
use rand::rngs::OsRng;
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufReader, BufWriter, Write},
    path::Path,
    time::Instant,
};
use tree::PublicState;
pub(super) fn compressed<T: CanonicalSerialize>(v: &T) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    v.serialize_compressed(&mut b)?;
    Ok(b)
}
pub(super) fn output(w: &Wallet, d: &H, v: u64) -> Result<Note> {
    if v == 0 {
        let w = Wallet::fresh();
        let mut n = w.receive(d).note(1)?;
        n.value = 0;
        Ok(n)
    } else {
        w.receive(d).note(v)
    }
}
pub(super) fn selected(w: &Wallet, n: &Note, pos: u32, s: &PublicState) -> Result<Input> {
    Ok(Input {
        real: true,
        note: n.clone(),
        secret: w.spending,
        position: pos,
        path: s.cm_tree()?.path(pos)?,
        dummy_key: [0; 32],
        dummy_seed: [0; 32],
    })
}
pub(super) fn authorize(
    d: H,
    s: &PublicState,
    ins: Vec<Input>,
    outs: [Note; 2],
    mode: u8,
    payout: u64,
    spk: [u8; 36],
    fund: Option<&native::Utxo>,
) -> Result<(Circuit, Bundle)> {
    if ins.len() > 2 {
        return Err("input count".into());
    }
    let inputs = std::array::from_fn(|i| ins.get(i).cloned().unwrap_or_else(Input::padding));
    let ciphers = if mode == 2 {
        [vec![0; 185], vec![0; 185]]
    } else {
        [outs[0].encrypt(&d)?, outs[1].encrypt(&d)?]
    };
    let nfs = std::array::from_fn(|i| {
        if mode == 0 {
            [0; 32]
        } else if inputs[i].real {
            crate::compact::nullifier(
                &d,
                &inputs[i].secret,
                &inputs[i].note.commitment(&d),
                inputs[i].position,
            )
        } else {
            dummy_nf(&d, &inputs[i].dummy_key, &inputs[i].dummy_seed, i as u8)
        }
    });
    let a = Authorization {
        domain: d,
        count: if mode == 0 {
            0
        } else {
            s.commitments.len() as u32
        },
        anchor: if mode == 0 {
            [0; 32]
        } else {
            s.cm_tree()?.root()
        },
        nfs,
        outputs: if mode == 2 {
            [[0; 32]; 2]
        } else {
            outs.each_ref().map(|n| n.commitment(&d))
        },
        mode,
        payout,
        fee: FEE,
        spk,
        deposit: fund.map_or(0, |u| u.amount),
        funding: if let Some(u) = fund {
            [hex::decode(&u.txid)?, u.index.to_le_bytes().to_vec()]
                .concat()
                .try_into()
                .unwrap()
        } else {
            [0; 36]
        },
        funding_spk: if let Some(u) = fund {
            hex::decode(&u.spk)?.try_into().unwrap()
        } else {
            [0; 36]
        },
        bootstrap: if mode != 0 && s.nullifiers.len() == 1 {
            inputs.iter().map(|i| i.note.value).sum()
        } else {
            0
        },
        cipher_hash: hash(&ciphers.concat()),
    };
    let bundle = Bundle {
        authorization: hex::encode(a.bytes()),
        proof: hex::encode([0; 128]),
        ciphertexts: ciphers.map(hex::encode),
    };
    Ok((
        Circuit {
            auth: a,
            inputs,
            outputs: outs,
        },
        bundle,
    ))
}
pub(super) fn prove(pk: &ProvingKey<Bn254>, c: Circuit, mut b: Bundle) -> Result<Bundle> {
    let t = Instant::now();
    let inputs = c.auth.inputs();
    let p = Groth16::<Bn254>::create_random_proof_with_reduction(c, pk, &mut OsRng)?;
    if !Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&pk.vk), &p, &inputs)? {
        return Err("generated proof rejected".into());
    }
    b.proof = hex::encode(compressed(&p)?);
    eprintln!("proof {} ms", t.elapsed().as_millis());
    Ok(b)
}
fn fixture() -> Result<(Circuit, Bundle)> {
    let d = [9; 32];
    let w = Wallet::fresh();
    let n = output(&w, &d, 2_000_000_000)?;
    let s = PublicState::initial(n.commitment(&d))?;
    authorize(
        d,
        &s,
        vec![selected(&w, &n, 0, &s)?],
        [output(&w, &d, 900_000_000)?, output(&w, &d, 1_060_000_000)?],
        1,
        0,
        [0; 36],
        None,
    )
}
fn setup(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    fs::create_dir(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let (c, _) = fixture()?;
    let (count, ok) = c.check()?;
    if !ok {
        return Err("fixture unsatisfied".into());
    }
    eprintln!("setup {count} constraints");
    let t = Instant::now();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(c, &mut OsRng)?;
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("pk.bin"))?;
    let mut out = BufWriter::new(f);
    pk.serialize_compressed(&mut out)?;
    out.flush()?;
    write(&dir.join("vk.bin"), &compressed(&pk.vk)?)?;
    save(
        &dir.join("setup.json"),
        &json!({"constraints":count,"setup_ms":t.elapsed().as_millis(),"pk_bytes":fs::metadata(dir.join("pk.bin"))?.len(),"vk_sha256":hex::encode(hash(&compressed(&pk.vk)?)),"single_party_experimental_setup":true}),
    )?;
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
struct ExitRequest {
    domain: H,
    state: PublicState,
    reserve: native::Utxo,
    vk: String,
    bundle: Bundle,
}
fn exit_request(r: &ExitRequest) -> Result<Value> {
    let (tx, e, _) = settle(
        &r.domain,
        &r.state,
        &r.reserve,
        &hex::decode(&r.vk)?,
        &r.bundle,
        None,
    )?;
    native::validate(&tx, &e)?;
    native::policy(&tx, &e)?;
    Ok(native::tx_json(&tx))
}
#[derive(Clone)]
struct Ledger {
    domain: H,
    state: PublicState,
    reserve: native::Utxo,
    vk: Vec<u8>,
    rows: Vec<Value>,
    fees: u64,
    payouts: u64,
    credits: u64,
    controls: Vec<Value>,
}
impl Ledger {
    fn accept(&mut self, b: &Bundle, external: Option<(&native::Utxo, &H)>) -> Result<()> {
        let (tx, e, next) = settle(
            &self.domain,
            &self.state,
            &self.reserve,
            &self.vk,
            b,
            external.map(|x| x.0),
        )?;
        let mut tx = tx;
        if let Some((_, k)) = external {
            native::sign(&mut tx, &e, 1, k)?;
        }
        let fee = native::validate(&tx, &e)?;
        if self.rows.is_empty()
            || (b.auth()?.mode == 0 && !self.rows.iter().any(|r| r["mode"] == 0))
            || b.auth()?.payout > 0
        {
            self.controls.push(
                json!({"mode":b.auth()?.mode,"mutations_rejected":native_mutations(&tx,&e)?}),
            );
        }
        let mass = native::policy(&tx, &e)?;
        let units = native::meter(&tx, &e)?;
        let a = b.auth()?;
        if fee != a.fee {
            return Err("actual fee differs".into());
        }
        self.fees += fee;
        self.payouts += a.payout;
        self.credits += external.map_or(0, |x| x.0.amount);
        self.rows.push(json!({"mode":a.mode,"payout_sompi":a.payout,"fee_sompi":fee,"metrics":mass,"script_units":units,"authorization_hash":hex::encode(hash(&a.bytes())),"proof_hash":hex::encode(hash(&hex::decode(&b.proof)?)),"tx":native::tx_json(&tx)}));
        self.state = next;
        if tx.outputs.len() == 1 && a.mode == 2 {
            self.reserve.amount = 0;
        } else {
            self.reserve = native::Utxo::output(&tx, 0, 0);
        }
        if self.credits != self.reserve.amount + self.payouts + self.fees {
            return Err("public accounting".into());
        }
        Ok(())
    }
}
fn fallback(
    pk: &ProvingKey<Bn254>,
    d: H,
    s: &PublicState,
    w: &Wallet,
    n: &Note,
    pos: u32,
) -> Result<Bundle> {
    let spk = native::encode_spk(&native::p2pk(&w.payout_key(&d, pos))?)
        .try_into()
        .unwrap();
    let (c, b) = authorize(
        d,
        s,
        vec![selected(w, n, pos, s)?],
        [Note::dummy(), Note::dummy()],
        2,
        n.value - FEE,
        spk,
        None,
    )?;
    prove(pk, c, b)
}
pub(super) struct Preparation {
    pub domain: H,
    pub wallets: Vec<Wallet>,
    pub initial: Note,
    pub sources: Vec<native::Utxo>,
    pub reserve: native::Utxo,
}
pub(super) fn demo(params: &Path, out: &Path, prepared: Option<Preparation>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir(out)?;
    fs::set_permissions(out, fs::Permissions::from_mode(0o700))?;
    let start = Instant::now();
    let pk = ProvingKey::<Bn254>::deserialize_compressed(BufReader::new(fs::File::open(
        params.join("pk.bin"),
    )?))?;
    let vk = compressed(&pk.vk)?;
    eprintln!("parameters loaded {} ms", start.elapsed().as_millis());
    let wallets: Vec<_> = prepared
        .as_ref()
        .map(|p| p.wallets.clone())
        .unwrap_or_else(|| (0..4).map(|_| Wallet::fresh()).collect());
    let fresh_domain = hash(
        &[
            b"KPI/COMPACT/TN10/v6\0".as_slice(),
            &hex::decode(crate::protocol::GENESIS_HEX)?,
            &random(),
            &hash(&vk),
            &NOTE_FLOOR.to_le_bytes(),
            &FEE.to_le_bytes(),
        ]
        .concat(),
    );
    let d = prepared.as_ref().map_or(fresh_domain, |p| p.domain);
    let initial = match &prepared {
        Some(p) => p.initial.clone(),
        None => output(&wallets[0], &d, 2_000_000_000)?,
    };
    let state = PublicState::initial(initial.commitment(&d))?;
    let reserve = match &prepared {
        Some(p) => p.reserve.clone(),
        None => native::Utxo {
            txid: hex::encode(random()),
            index: 0,
            amount: initial.value,
            spk: hex::encode(native::encode_spk(&reserve_spk(&d, &state, &vk)?)),
            daa: 0,
            is_coinbase: false,
        },
    };
    let mut l = Ledger {
        domain: d,
        state,
        reserve,
        vk,
        rows: vec![],
        fees: 0,
        payouts: 0,
        credits: initial.value,
        controls: vec![],
    };
    let outs = [
        output(&wallets[0], &d, 900_000_000)?,
        output(&wallets[0], &d, 1_060_000_000)?,
    ];
    let (c, b) = authorize(
        d,
        &l.state,
        vec![selected(&wallets[0], &initial, 0, &l.state)?],
        outs.clone(),
        1,
        0,
        [0; 36],
        None,
    )?;
    l.accept(&prove(&pk, c, b)?, None)?;
    // Wallet ownership/plaintexts stay in this private working directory only.
    let mut notes = vec![(0usize, 1u32, outs[0].clone()), (0, 2, outs[1].clone())];
    let mut saved = Vec::new();
    for (owner, pos, n) in &notes {
        saved.push((
            *owner,
            *pos,
            n.clone(),
            fallback(&pk, d, &l.state, &wallets[*owner], n, *pos)?,
        ));
    }
    for owner in 1..4 {
        let u = match &prepared {
            Some(p) => p.sources[owner].clone(),
            None => native::Utxo {
                txid: hex::encode(random()),
                index: 0,
                amount: 1_000_000_000 + owner as u64 * 100_000_000,
                spk: hex::encode(native::encode_spk(&native::p2pk(&wallets[owner].native)?)),
                daa: 0,
                is_coinbase: false,
            },
        };
        let os = [
            output(&wallets[owner], &d, u.amount - FEE)?,
            output(&wallets[owner], &d, 0)?,
        ];
        let pos = l.state.commitments.len() as u32;
        let (c, b) = authorize(d, &l.state, vec![], os.clone(), 0, 0, [0; 36], Some(&u))?;
        l.accept(&prove(&pk, c, b)?, Some((&u, &wallets[owner].native)))?;
        notes.push((owner, pos, os[0].clone()));
        saved.push((
            owner,
            pos,
            os[0].clone(),
            fallback(&pk, d, &l.state, &wallets[owner], &os[0], pos)?,
        ));
    }
    let before = l.state.clone();
    let reserve_before = l.reserve.clone();
    // Combine Alice's two receipts, pay Bob a varied amount, keep Alice's change.
    let os = [
        output(&wallets[1], &d, 731_000_000)?,
        output(&wallets[0], &d, 1_189_000_000)?,
    ];
    let pos = l.state.commitments.len() as u32;
    let (c, b) = authorize(
        d,
        &l.state,
        vec![
            selected(&wallets[0], &notes[0].2, 1, &l.state)?,
            selected(&wallets[0], &notes[1].2, 2, &l.state)?,
        ],
        os.clone(),
        1,
        0,
        [0; 36],
        None,
    )?;
    let payment = prove(&pk, c, b)?;
    let (payment_tx, _, _) = settle(&d, &l.state, &l.reserve, &l.vk, &payment, None)?;
    l.accept(&payment, None)?;
    // Normal-first: saved per-note fallback cannot consume either real input.
    for x in &saved[..2] {
        if settle(&d, &l.state, &l.reserve, &l.vk, &x.3, None).is_ok() {
            return Err("spent input fallback accepted".into());
        }
    }
    // Fallback-first: apply Alice's independent exit to a fork, reject the payment.
    let (ft, fe, fs) = settle(&d, &before, &reserve_before, &l.vk, &saved[0].3, None)?;
    native::validate(&ft, &fe)?;
    replay_rejected(&ft, &l.reserve, &l.state, &d, &l.vk, &saved[0].3)?;
    let fu = native::Utxo::output(&ft, 0, 0);
    replay_rejected(&payment_tx, &fu, &fs, &d, &l.vk, &payment)?;
    if settle(&d, &fs, &fu, &l.vk, &payment, None).is_ok() {
        return Err("payment after fallback accepted".into());
    }
    // Both outputs decrypt for intended owners; hidden change is a real spendable note.
    for (i, owner) in [1usize, 0].iter().enumerate() {
        wallets[*owner].decrypt(
            &d,
            &hex::decode(&payment.ciphertexts[i])?,
            &payment.auth()?.outputs[i],
        )?;
    }
    saved.drain(..2);
    notes.drain(..2);
    let change_fallback = fallback(&pk, d, &l.state, &wallets[0], &os[1], pos + 1)?;
    saved.push((0, pos + 1, os[1].clone(), change_fallback));
    // Partial native payout of Bob's received note, retaining private change.
    let partial_os = [
        output(&wallets[1], &d, 480_000_000)?,
        output(&wallets[1], &d, 0)?,
    ];
    let partial_pos = l.state.commitments.len() as u32;
    let payout_spk = native::encode_spk(&native::p2pk(&wallets[1].payout_key(&d, pos))?)
        .try_into()
        .unwrap();
    let (c, b) = authorize(
        d,
        &l.state,
        vec![selected(&wallets[1], &os[0], pos, &l.state)?],
        partial_os.clone(),
        1,
        211_000_000,
        payout_spk,
        None,
    )?;
    let partial = prove(&pk, c, b)?;
    l.accept(&partial, None)?;
    wallets[1].decrypt(
        &d,
        &hex::decode(&partial.ciphertexts[0])?,
        &partial.auth()?.outputs[0],
    )?;
    // Spend the private withdrawal change: Carol receives a payment, Bob keeps change.
    let final_os = [
        output(&wallets[2], &d, 170_000_000)?,
        output(&wallets[1], &d, 270_000_000)?,
    ];
    let final_pos = l.state.commitments.len() as u32;
    let (c, b) = authorize(
        d,
        &l.state,
        vec![selected(
            &wallets[1],
            &partial_os[0],
            partial_pos,
            &l.state,
        )?],
        final_os.clone(),
        1,
        0,
        [0; 36],
        None,
    )?;
    let respent = prove(&pk, c, b)?;
    l.accept(&respent, None)?;
    for (i, owner) in [2usize, 1].iter().enumerate() {
        wallets[*owner].decrypt(
            &d,
            &hex::decode(&respent.ciphertexts[i])?,
            &respent.auth()?.outputs[i],
        )?;
        saved.push((
            *owner,
            final_pos + i as u32,
            final_os[i].clone(),
            fallback(
                &pk,
                d,
                &l.state,
                &wallets[*owner],
                &final_os[i],
                final_pos + i as u32,
            )?,
        ));
    }
    let mut by_wallet = [0u64; 4];
    let mut unchanged = 0;
    for (owner, pos, n, bundle) in saved {
        let r = ExitRequest {
            domain: d,
            state: l.state.clone(),
            reserve: l.reserve.clone(),
            vk: hex::encode(&l.vk),
            bundle: bundle.clone(),
        };
        let file = out.join(format!("exit-{pos}.json"));
        save(&file, &r)?;
        // Separate process accepts only public state + the saved authorization/proof.
        let process = std::process::Command::new("bwrap")
            .args([
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--clearenv",
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/bin",
                "/bin",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
            ])
            .arg(std::env::current_exe()?)
            .arg("/app")
            .arg("--ro-bind")
            .arg(&file)
            .arg("/request.json")
            .args(["--", "/app", "exit", "/request.json"])
            .output()?;
        if !process.status.success() {
            return Err(format!(
                "saved exit process: {}",
                String::from_utf8_lossy(&process.stderr)
            )
            .into());
        }
        let response: Value = serde_json::from_slice(&process.stdout)?;
        if response["isolated"] != true {
            return Err("exit isolation missing".into());
        }
        let tx = native::parse_tx(&response["tx"])?;
        if tx.payload[P_AUTH..P_CIPHER] != hex::decode(&bundle.authorization)?
            || tx.inputs[0].signature_script[2..130] != hex::decode(&bundle.proof)?
        {
            return Err("saved proof/auth changed".into());
        }
        l.accept(&bundle, None)?;
        by_wallet[owner] += n.value - FEE;
        unchanged += 1;
    }
    if l.reserve.amount != 0 || by_wallet.contains(&0) {
        return Err("not all wallets paid/drained".into());
    }
    let report = json!({"offline_only":true,"synthetic_native_utxos":prepared.is_none(),"planned_native_utxos":prepared.is_some(),"real_groth16_proofs":true,"saved_proofs_unchanged":unchanged,"isolated_exit_clients":unchanged,"exit_clients_have_private_keys_or_pk":false,"wallet_exit_payouts_sompi":by_wallet,"private_change_decrypted":true,"partial_withdrawal_sompi":211_000_000,"partial_change_respent":true,"normal_and_fallback_mutually_exclusive":true,"reserve_remaining":l.reserve.amount,"total_input_sompi":l.credits,"total_payout_sompi":l.payouts,"total_fee_sompi":l.fees,"operations":l.rows.len(),"elapsed_ms":start.elapsed().as_millis(),"native_adversarial_controls":l.controls,"rows":l.rows});
    save(&out.join("result-private.json"), &report)?;
    if prepared.is_none() {
        println!(
            "{}",
            json!({"operations":report["operations"],"saved_exits":unchanged,"wallets_paid":4,"reserve_remaining":0,"fee_sompi":l.fees})
        );
    }
    Ok(())
}
pub fn run() -> Result<()> {
    let a = std::env::args().collect::<Vec<_>>();
    match a.get(1).map(String::as_str) {
        Some("verify-study") => study::verify_raw(
            Path::new(a.get(2).ok_or("verify-study PUBLIC_TRACE OUT")?),
            Path::new(a.get(3).ok_or("verify-study PUBLIC_TRACE OUT")?),
        ),
        Some("study") => study::run(
            Path::new(a.get(2).ok_or("study PARAMS PLAN OUT")?),
            Path::new(a.get(3).ok_or("study PARAMS PLAN OUT")?),
            Path::new(a.get(4).ok_or("study PARAMS PLAN OUT")?),
        ),
        Some("common-study") => study::common(
            Path::new(a.get(2).ok_or("common-study PARAMS PLAN OUT")?),
            Path::new(a.get(3).ok_or("common-study PARAMS PLAN OUT")?),
            Path::new(a.get(4).ok_or("common-study PARAMS PLAN OUT")?),
        ),
        Some("audit") => super::audit::run(
            Path::new(a.get(2).ok_or("audit PRIVATE_RESULT OUT")?),
            Path::new(a.get(3).ok_or("audit PRIVATE_RESULT OUT")?),
        ),
        Some("boundary") => boundary(
            Path::new(a.get(2).ok_or("boundary REQUEST OUT")?),
            Path::new(a.get(3).ok_or("boundary REQUEST OUT")?),
        ),
        Some("controls") => circuit_controls(),
        Some("setup") => setup(Path::new(a.get(2).ok_or("setup DIR")?)),
        Some("demo") => demo(
            Path::new(a.get(2).ok_or("demo PARAMS OUT")?),
            Path::new(a.get(3).ok_or("demo PARAMS OUT")?),
            None,
        ),
        Some("exit") => {
            let r: ExitRequest = read(Path::new(a.get(2).ok_or("exit REQUEST")?))?;
            if Path::new("/home/luke").exists() {
                return Err("exit worker requires isolated mount namespace".into());
            }
            let net = fs::read_to_string("/proc/net/dev")?;
            let interfaces = net
                .lines()
                .filter_map(|l| l.split_once(':').map(|x| x.0.trim()))
                .collect::<Vec<_>>();
            if interfaces != vec!["lo"] {
                return Err("exit worker network not isolated".into());
            }
            println!(
                "{}",
                json!({"tx":exit_request(&r)?,"isolated":true,"private_keys_mounted":false,"proving_key_mounted":false,"network_interfaces":interfaces})
            );
            Ok(())
        }
        _ => Err("setup DIR | demo PARAMS OUT | controls | exit REQUEST | boundary REQUEST OUT | audit PRIVATE_RESULT OUT | study PARAMS PLAN OUT | common-study PARAMS PLAN OUT | verify-study PUBLIC_TRACE OUT".into()),
    }
}

fn native_mutations(tx: &Transaction, entries: &[UtxoEntry]) -> Result<Vec<String>> {
    let mut passed = Vec::new();
    for (name, offset) in [
        ("domain", P_AUTH + 8),
        ("anchor", P_AUTH + A_ANCHOR),
        ("nf-slot-0", P_AUTH + A_NF),
        ("nf-slot-1", P_AUTH + A_NF + 32),
        ("cm-slot-0", P_AUTH + A_CM),
        ("cm-slot-1", P_AUTH + A_CM + 32),
        ("mode", P_AUTH + A_MODE),
        ("payout", P_AUTH + A_PAYOUT),
        ("fee", P_AUTH + A_FEE),
        ("destination", P_AUTH + A_SPK),
        ("deposit", P_AUTH + A_DEP),
        ("funding-outpoint", P_AUTH + A_FUND),
        ("funding-script", P_AUTH + A_FSPK),
        ("bootstrap", P_AUTH + A_BOOT),
        ("ciphertext", P_CIPHER),
        ("next-count", P_STATE + 1),
        ("next-nf-count", P_STATE + 5),
        ("next-cm-root", P_STATE + 9),
        ("next-nf-root", P_STATE + 41),
        ("next-history", P_STATE + 73),
        ("anchor-path", P_WITNESS),
        ("nf0-predecessor", P_WITNESS + W_NF + 4),
        ("nf0-path", P_WITNESS + W_NF + 72),
        ("nf1-predecessor", P_WITNESS + W_NF + NF_WIT + 4),
        ("nf1-path", P_WITNESS + W_NF + NF_WIT + 72),
        ("cm-append", P_WITNESS + W_CM_APPEND),
        ("history-append", P_WITNESS + W_HISTORY_APPEND),
    ] {
        let mut bad = tx.clone();
        bad.payload[offset] ^= 1;
        bad.finalize();
        native::set_mass(&bad, entries)?;
        if native::script_units_at(&bad, entries, 0).is_ok() {
            return Err(format!("native mutation accepted: {name}").into());
        }
        passed.push(name.to_string());
    }
    for name in ["proof", "reserve-amount", "payout-output", "extra-output"] {
        let mut bad = tx.clone();
        let mut e = entries.to_vec();
        match name {
            "proof" => bad.inputs[0].signature_script[2] ^= 1,
            "reserve-amount" => e[0].amount += 1,
            "payout-output" => bad.outputs[0].value -= 1,
            _ => {
                bad.outputs[0].value -= 1;
                bad.outputs
                    .push(TransactionOutput::new(1, native::p2pk(&[7; 32])?));
            }
        }
        bad.finalize();
        native::set_mass(&bad, &e)?;
        if native::script_units_at(&bad, &e, 0).is_ok() {
            return Err(format!("native mutation accepted: {name}").into());
        }
        passed.push(name.into());
    }
    Ok(passed)
}
fn replay_rejected(
    tx: &Transaction,
    current: &native::Utxo,
    state: &PublicState,
    d: &H,
    vk: &[u8],
    bundle: &Bundle,
) -> Result<()> {
    let mut bad = tx.clone();
    bad.inputs[0].previous_outpoint = current.outpoint()?;
    bad.inputs[0].signature_script = covenant::signature(
        &hex::decode(&bundle.proof)?,
        &covenant::redeem(d, &state.compact()?, vk)?,
    )?;
    let a = bundle.auth()?;
    bad.outputs[0].value = current
        .amount
        .checked_sub(a.payout + a.fee)
        .ok_or("replay balance")?;
    bad.finalize();
    let e = vec![current.entry()?];
    native::set_mass(&bad, &e)?;
    if native::script_units_at(&bad, &e, 0).is_ok() {
        return Err("native stale/duplicate replay accepted".into());
    }
    Ok(())
}
fn circuit_controls() -> Result<()> {
    let (c, _) = fixture()?;
    let mut cases: Vec<(&str, Circuit, bool)> = vec![("bootstrap", c.clone(), true)];
    let s = PublicState::initial(c.inputs[0].note.commitment(&c.auth.domain))?
        .witness(&c.auth)?
        .0;
    let ins = (0..2)
        .map(|i| Input {
            real: true,
            note: c.outputs[i].clone(),
            secret: c.inputs[0].secret,
            position: i as u32 + 1,
            path: s.cm_tree().unwrap().path(i as u32 + 1).unwrap(),
            dummy_key: [0; 32],
            dummy_seed: [0; 32],
        })
        .collect();
    let mut os = c.outputs.clone();
    os[0].value = 731_000_000;
    os[1].value = 1_189_000_000;
    let (two, _) = authorize(c.auth.domain, &s, ins, os, 1, 0, [0; 36], None)?;
    cases.push(("two-real-inputs", two.clone(), true));
    let mut x = two.clone();
    x.inputs[1] = x.inputs[0].clone();
    x.auth.nfs[1] = x.auth.nfs[0];
    x.outputs[1].value = x.inputs[0].note.value * 2 - x.outputs[0].value - FEE;
    x.auth.outputs[1] = x.outputs[1].commitment(&x.auth.domain);
    cases.push(("duplicate-input", x, false));
    let mut x = two.clone();
    x.inputs[1].secret[0] ^= 1;
    cases.push(("second-owner", x, false));
    let mut x = two.clone();
    x.inputs[1].path[0][0] ^= 1;
    cases.push(("second-membership", x, false));
    let mut x = two.clone();
    x.auth.nfs[1][0] ^= 1;
    cases.push(("second-nullifier", x, false));
    let mut x = c.clone();
    x.auth.nfs[1] = [7; 32];
    cases.push(("arbitrary-dummy-nf", x, false));
    let mut x = c.clone();
    x.inputs[1].note.value = 1;
    cases.push(("dummy-value", x, false));
    let mut x = two.clone();
    x.outputs[0].value += 1;
    x.auth.outputs[0] = x.outputs[0].commitment(&x.auth.domain);
    cases.push(("inflation", x, false));
    let mut x = two.clone();
    x.outputs[1].value += x.outputs[0].value - NOTE_FLOOR;
    x.outputs[0].value = NOTE_FLOOR;
    x.auth.outputs = x.outputs.each_ref().map(|n| n.commitment(&x.auth.domain));
    cases.push(("minimum-note", x.clone(), true));
    x.outputs[0].value -= 1;
    x.outputs[1].value += 1;
    x.auth.outputs = x.outputs.each_ref().map(|n| n.commitment(&x.auth.domain));
    cases.push(("below-floor-change", x, false));
    let mut x = two.clone();
    x.outputs[1].value += x.outputs[0].value;
    x.outputs[0].value = 0;
    x.auth.outputs = x.outputs.each_ref().map(|n| n.commitment(&x.auth.domain));
    cases.push(("zero-output-padding", x, true));
    let mut x = two.clone();
    x.auth.domain[0] ^= 1;
    cases.push(("wrong-domain", x, false));
    let mut x = two.clone();
    x.inputs[1].position += 2;
    cases.push(("wrong-position", x, false));
    let mut x = two.clone();
    x.inputs[0].note.value = u64::MAX;
    cases.push(("amount-overflow", x, false));
    for (name, c, expect) in cases {
        let (_, ok) = c.check()?;
        if ok != expect {
            return Err(format!("circuit control {name}: {ok}, expected {expect}").into());
        }
        println!(
            "{}",
            json!({"control":name,"expected_satisfied":expect,"passed":true})
        );
    }
    Ok(())
}

fn boundary(request: &Path, out: &Path) -> Result<()> {
    // Synthetic boundary state: exercises native depth/count arithmetic with a
    // genuine saved proof. It does NOT claim a replayed 65k-note funded history.
    use crate::compact::tree::{NfLeaf, less};
    let mut r: ExitRequest = read(request)?;
    let a = r.bundle.auth()?;
    let original_count = r.state.commitments.len();
    let mut tree = r.state.cm_tree()?;
    while r.state.commitments.len() < 65_535 {
        for _ in 0..2 {
            let cm = hash(
                &[
                    b"synthetic capacity CM".as_slice(),
                    &(r.state.commitments.len() as u64).to_le_bytes(),
                ]
                .concat(),
            );
            tree.append(tree::cm_leaf(&cm))?;
            r.state.commitments.push(cm);
        }
        r.state.roots.push(tree.root());
    }
    let mut values = r
        .state
        .nullifiers
        .iter()
        .map(|l| l.value)
        .collect::<Vec<_>>();
    let mut seen = values
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    for i in 0u64.. {
        if values.len() == 131_069 {
            break;
        }
        let nf = hash(&[b"synthetic capacity NF".as_slice(), &i.to_le_bytes()].concat());
        if !a.nfs.contains(&nf) && nf != [0; 32] && seen.insert(nf) {
            values.push(nf);
        }
    }
    let mut order = (0..values.len()).collect::<Vec<_>>();
    order.sort_by(|i, j| {
        if values[*i] == values[*j] {
            std::cmp::Ordering::Equal
        } else if less(&values[*i], &values[*j]) {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    let mut leaves = values
        .iter()
        .map(|v| NfLeaf {
            value: *v,
            next_index: 0,
            next_value: [0; 32],
        })
        .collect::<Vec<_>>();
    for pair in order.windows(2) {
        leaves[pair[0]].next_index = pair[1] as u32;
        leaves[pair[0]].next_value = values[pair[1]];
    }
    r.state.nullifiers = leaves;
    r.reserve.amount = a.payout + a.fee;
    r.reserve.spk = hex::encode(native::encode_spk(&reserve_spk(
        &r.domain,
        &r.state,
        &hex::decode(&r.vk)?,
    )?));
    let (tx, e, next) = settle(
        &r.domain,
        &r.state,
        &r.reserve,
        &hex::decode(&r.vk)?,
        &r.bundle,
        None,
    )?;
    native::validate(&tx, &e)?;
    native::policy(&tx, &e)?;
    if tx.outputs.len() != 1
        || next.commitments != r.state.commitments
        || next.roots != r.state.roots
        || next.nullifiers.len() != 131_071
    {
        return Err("capacity drain shape".into());
    }
    let mut append = a.clone();
    append.mode = 1;
    append.outputs = [[11; 32], [12; 32]];
    if r.state.witness(&append).is_ok() {
        return Err("append beyond capacity".into());
    }
    save(
        out,
        &json!({"synthetic_boundary_state_not_replayed_history":true,"original_cm_count":original_count,"cm_count":65535,"nf_count_before":131068,"nf_count_after":131070,"native_terminal_exit_valid":true,"saved_proof_unchanged":tx.inputs[0].signature_script[2..130]==hex::decode(&r.bundle.proof)?,"new_commitments":0,"cm_append_refused":true,"metrics":native::metrics(&tx,&e)?,"script_units":native::meter(&tx,&e)?}),
    )?;
    Ok(())
}
