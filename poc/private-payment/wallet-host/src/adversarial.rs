//! Native differential/failure controls for the exact guest library.
//! Native rejection and VM execution are not proofs of invalidity.
use crate::fixture::{self, Tree};
use anyhow::{ensure, Result};
use kpi_wallet_core::*;
use serde_json::json;
use std::{fs, path::Path};
fn refresh(w: &mut Witness) -> Result<()> {
    for j in 0..2 {
        let (n, f) = old_note(&w.old[j])?;
        w.intent.nf[j] = n.nullifier(&f).to_bytes();
        let (c, e, b) = output(&w.new[j], &w.intent.nf[j])?;
        w.intent.cmx[j] = c;
        w.intent.epk[j] = e;
        w.intent.ciphertext[j] = b
    }
    Ok(())
}
fn reject(w: &Witness) -> Result<()> {
    ensure!(validate(w).is_err(), "invalid wallet witness accepted");
    Ok(())
}
pub fn run(root: &Path, out: &Path) -> Result<()> {
    let read = |name: &str| -> Result<Witness> {
        Witness::decode(&fs::read(root.join(name).join("input.bin"))?)
    };
    let credit = read("credit")?;
    let transfer = read("transfer")?;
    let exit = read("exit")?;
    for w in [&credit, &transfer, &exit] {
        let raw = w.encode()?;
        ensure!(validate(w)? == w.intent.journal(&w.auth)?, "native journal");
        ensure!(
            Witness::decode(&raw)?.encode()? == raw,
            "canonical witness roundtrip"
        )
    }
    let mut cases = Vec::new();
    macro_rules! bad {
        ($label:expr,$base:expr,$change:expr) => {{
            let mut w = $base.clone();
            ($change)(&mut w);
            reject(&w)?;
            cases.push($label.to_owned());
        }};
    }
    bad!("wrong spending key", transfer, |w: &mut Witness| {
        w.old[0].sk = fixture::spending_key().unwrap();
        refresh(w).unwrap();
    });
    bad!(
        "wrong internal/external scope",
        transfer,
        |w: &mut Witness| {
            w.old[0].scope ^= 1;
            refresh(w).unwrap();
        }
    );
    bad!(
        "positive note without membership",
        transfer,
        |w: &mut Witness| w.old[0].path = None
    );
    bad!("dummy with a path", credit, |w: &mut Witness| w.old[0]
        .path =
        transfer.old[0].path);
    bad!("wrong path sibling", transfer, |w: &mut Witness| w.old
        [0]
    .path
    .as_mut()
    .unwrap()
    .1[0][0] ^=
        1);
    bad!("wrong hidden position", transfer, |w: &mut Witness| w
        .old[0]
        .path
        .as_mut()
        .unwrap()
        .0 ^=
        1);
    bad!("wrong root", transfer, |w: &mut Witness| w.intent.anchor =
        credit.intent.anchor);
    bad!("noncanonical root", credit, |w: &mut Witness| w
        .intent
        .anchor =
        [255; 32]);
    bad!("noncanonical rho", transfer, |w: &mut Witness| w.old[0]
        .rho =
        [255; 32]);
    bad!("unknown scope", transfer, |w: &mut Witness| w.old[0]
        .scope = 2);
    bad!("caller selected nullifier", transfer, |w: &mut Witness| {
        w.intent.nf[0][0] ^= 1
    });
    bad!("duplicate slot nullifier", transfer, |w: &mut Witness| w
        .intent
        .nf[1] =
        w.intent.nf[0]);
    bad!("wrong output seed", transfer, |w: &mut Witness| w.new[0]
        .seed[0] ^=
        1);
    bad!("wrong output memo", transfer, |w: &mut Witness| w.new[0]
        .memo[17] ^=
        1);
    bad!("wrong output recipient", transfer, |w: &mut Witness| w
        .new[0]
        .address =
        w.new[1].address);
    bad!("forbidden output address", transfer, |w: &mut Witness| w
        .new[0]
        .address =
        [0; 43]);
    bad!(
        "new rho not paired with input nf",
        transfer,
        |w: &mut Witness| {
            w.new.swap(0, 1);
        }
    );
    bad!(
        "inflated output with recomputed delivery",
        transfer,
        |w: &mut Witness| {
            w.new[0].value += 1;
            refresh(w).unwrap();
        }
    );
    bad!("hidden output value", transfer, |w: &mut Witness| w.new
        [0]
    .value +=
        1);
    bad!("unbalanced private fee", transfer, |w: &mut Witness| {
        w.intent.fee = 1;
        w.intent.fee_script = Some(Script {
            version: 0,
            bytes: vec![0x51],
        });
    });
    bad!("changed exit principal", exit, |w: &mut Witness| w
        .intent
        .exited +=
        1);
    bad!("exit_only with positive output", exit, |w: &mut Witness| {
        w.new[0].value = 1;
        w.intent.exited -= 1;
        refresh(w).unwrap();
    });
    bad!("credit principal mismatch", credit, |w: &mut Witness| w
        .intent
        .principal +=
        1);
    bad!("CREDIT wrong signing key", credit, |w: &mut Witness| w
        .intent
        .deposit
        .as_mut()
        .unwrap()
        .key =
        [7; 32]);
    for slot in 0..2 {
        for at in [0, 52, 579] {
            let mut w = transfer.clone();
            w.intent.ciphertext[slot][at] ^= 1;
            reject(&w)?;
            cases.push(format!("ciphertext {slot}/{at}"));
        }
        for field in [0, 1] {
            let mut w = transfer.clone();
            if field == 0 {
                w.intent.cmx[slot][0] ^= 1
            } else {
                w.intent.epk[slot][0] ^= 1
            };
            reject(&w)?;
            cases.push(format!("commitment/epk {slot}/{field}"));
        }
    }
    for at in 1..65 {
        let mut w = credit.clone();
        w.auth[at] ^= 1;
        reject(&w)?;
        cases.push(format!("credit signature byte {at}"));
    }
    for auth in [vec![0], vec![2], vec![1; 64], vec![1; 66]] {
        let mut w = credit.clone();
        w.auth = auth;
        reject(&w)?;
        cases.push("wrong CREDIT authorization frame".into());
    }
    for i in 0..8 {
        let mut w = credit.clone();
        w.intent.ids[i][0] ^= 1;
        reject(&w)?;
        cases.push(format!("signed credit context {i}"));
    }
    let program = fs::read(root.join("credit/program.bin"))?;
    let mut selected = Vec::new();
    let mut w = transfer.clone();
    w.old[0].path.as_mut().unwrap().0 ^= 1;
    selected.push(("wrong-position", w, "membership root mismatch"));
    let mut w = transfer.clone();
    w.old[0].sk = fixture::spending_key()?;
    refresh(&mut w)?;
    selected.push(("wrong-owner", w, "membership root mismatch"));
    let mut w = transfer.clone();
    w.intent.ciphertext[0][579] ^= 1;
    selected.push(("wrong-delivery", w, "output commitment/delivery mismatch"));
    let mut w = transfer.clone();
    w.new[0].value += 1;
    refresh(&mut w)?;
    selected.push(("inflation", w, "TRANSFER conservation"));
    let mut w = credit.clone();
    w.auth[64] ^= 1;
    selected.push(("bad-recovery-signature", w, "signature error"));
    let negatives = root.join("negative-vm");
    fs::create_dir(&negatives)?;
    for (name, w, reason) in selected {
        reject(&w)?;
        fixture::case(&negatives, name, &program, &w)?;
        fixture::save(
            &negatives.join(name).join("expected-rejection.txt"),
            reason.as_bytes(),
        )?;
    }
    let mut framing = 0;
    for w in [&credit, &transfer, &exit] {
        let raw = w.encode()?;
        for stop in 0..raw.len() {
            ensure!(
                Witness::decode(&raw[..stop]).is_err(),
                "truncated witness accepted"
            );
            framing += 1
        }
        let mut trailing = raw;
        trailing.push(0);
        ensure!(
            Witness::decode(&trailing).is_err(),
            "trailing witness accepted"
        );
        framing += 1;
    }
    // A two-real-input equation above u64::MAX must use u128, not wrapping u64.
    let mut high = transfer.clone();
    let mut tree = Tree::default();
    for n in &mut high.old {
        n.value = u64::MAX;
        let (note, _) = old_note(n)?;
        tree.leaves
            .push(orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes())
    }
    high.intent.anchor = tree.root_path(None)?.0;
    for j in 0..2 {
        high.old[j].path = Some((j as u32, tree.root_path(Some(j as u32))?.1));
        high.new[j].value = u64::MAX;
    }
    refresh(&mut high)?;
    validate(&high)?;
    let mut wrapped = high.clone();
    wrapped.new[0].value = u64::MAX - 1;
    wrapped.new[1].value = u64::MAX;
    refresh(&mut wrapped)?;
    reject(&wrapped)?;
    cases.push("u128 high-value imbalance".into());
    // One-sompi transfer and zero dummy, with checked established constructors.
    let mut tiny = transfer.clone();
    tiny.old[0].value = 1;
    tiny.old[1] = fixture::dummy()?;
    let mut tree = Tree::default();
    tree.leaves.push(
        orchard::note::ExtractedNoteCommitment::from(old_note(&tiny.old[0])?.0.commitment())
            .to_bytes(),
    );
    tiny.old[0].path = Some((0, tree.root_path(Some(0))?.1));
    tiny.intent.anchor = tree.root_path(None)?.0;
    tiny.new[0].value = 1;
    tiny.new[1].value = 0;
    refresh(&mut tiny)?;
    validate(&tiny)?;
    let report = json!({"scope":"NATIVE_SHARED_WALLET_RELATION_CONTROLS_NOT_PROOFS_OF_INVALIDITY","validLifecycleRelations":3,"extraBoundaryRelations":2,"negativeRelationCasesRejected":cases.len(),"negativeCases":cases,"witnessFramingRejections":framing,"fullTreeStateMaterialized":false,"nativeTransactions":0});
    fixture::save(out, &serde_json::to_vec_pretty(&report)?)?;
    println!(
        "Native wallet relation controls passed: {} negative cases and {framing} framing cases",
        cases.len()
    );
    Ok(())
}

pub fn wire(golden: &Path, out: &Path) -> Result<()> {
    let corpus: serde_json::Value = serde_json::from_slice(&fs::read(golden)?)?;
    let mut vectors = 0;
    let mut rejected = 0;
    for row in corpus["vectors"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("golden corpus"))?
    {
        let raw = hex::decode(
            row["encodedHex"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("golden bytes"))?,
        )?;
        let i = Intent::decode(&raw)?;
        ensure!(i.encode()? == raw, "reviewed public intent changed");
        ensure!(
            hex::encode(hash(&raw)) == row["intentId"].as_str().unwrap(),
            "intent digest mismatch"
        );
        for stop in 0..raw.len() {
            ensure!(
                Intent::decode(&raw[..stop]).is_err(),
                "truncated intent accepted"
            );
            rejected += 1
        }
        let mut trailing = raw;
        trailing.push(0);
        ensure!(
            Intent::decode(&trailing).is_err(),
            "trailing intent accepted"
        );
        rejected += 1;
        vectors += 1;
    }
    fixture::save(
        out,
        &serde_json::to_vec_pretty(
            &json!({"scope":"NEW_WALLET_PARSER_AGAINST_FROZEN_PUBLIC_CORPUS","goldenIntents":vectors,"truncationAndTrailingRejections":rejected,"nativeTransactions":0}),
        )?,
    )?;
    println!("Wallet parser matches {vectors} frozen intents; {rejected} malformed frames reject");
    Ok(())
}
