//! Offline restore/replay exercises; no native accepted order or settlement.
use crate::{
    fixture::{self, Backup},
    history::{self, History},
    state::{self, State},
};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
use kpi_wallet_core::*;
use risc0_zkvm::Receipt;
use serde_json::json;
use sha2::{Digest as _, Sha512};
use std::{fs, path::Path};
fn pin(text: &str) -> Result<[u8; 32]> {
    hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("history pin width"))
}
fn backup(p: &Path) -> Result<Backup> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
fn record_receipt(h: &History, proofs: &Path, n: usize) -> Result<Receipt> {
    let r = &h.records[n];
    history::load_receipt(proofs, &r.name, &r.receipt_sha256)
}
fn reject_atomic(state: &State, i: &[u8], auth: &[u8], r: &Receipt) -> Result<String> {
    let mut s = state.clone();
    let before = s.economic_bytes();
    let cursor = s.cursor;
    let (ok, reason) = s.apply(i, auth, r)?;
    ensure!(
        !ok && s.economic_bytes() == before && s.cursor == cursor + 1,
        "invalid operation not atomic"
    );
    Ok(reason)
}
pub fn command(
    hist: &Path,
    expected: &str,
    proofs: &Path,
    backup_path: &Path,
    out: &Path,
) -> Result<()> {
    let b = backup(backup_path)?;
    let raw = fs::read(hist)?;
    let (s, notes) = history::restore(&raw, &pin(expected)?, proofs, &b)?;
    let balance = notes.iter().try_fold(0u64, |sum, n| {
        sum.checked_add(n.value)
            .context("restored balance overflow")
    })?;
    fixture::save(
        out,
        &serde_json::to_vec_pretty(
            &json!({"scope":"LOCAL_SYNTHETIC_HISTORY_RECEIPT_REPLAY_AND_BOTH_SCOPE_SCAN","historySha256":expected,"stateCommitment":hex::encode(s.commitment()),"spendableSompi":balance,"spendableNotes":notes.len(),"internalNotes":notes.iter().filter(|n|n.scope==1).count(),"privateLiabilitiesSompi":s.private,"unpaidExitSompi":s.exits,"reserveSompi":s.reserve,"nativeTransactions":0}),
        )?,
    )?;
    println!(
        "Restored local wallet: {balance} spendable sompi from complete pinned synthetic history"
    );
    Ok(())
}
pub fn exercise(cases: &Path, proofs: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let history_path = out.join("history.json");
    let expected = history::seal(
        cases,
        proofs,
        &history_path,
        &["credit", "transfer", "exit"],
    )?;
    let raw = fs::read(&history_path)?;
    let h: History = serde_json::from_slice(&raw)?;
    let (s, accepted) = history::replay(&raw, &expected, proofs)?;
    ensure!(
        accepted.len() == 3,
        "baseline history did not accept three real receipts"
    );
    let alice = backup(&cases.join("alice-backup.json"))?;
    let bob = backup(&cases.join("bob-backup.json"))?;
    let (_, a) = history::restore(&raw, &expected, proofs, &alice)?;
    let (_, b) = history::restore(&raw, &expected, proofs, &bob)?;
    ensure!(
        a.len() == 1 && a[0].value == 400 && a[0].scope == 1 && b.is_empty(),
        "restored balances/scopes/spentness mismatch"
    );
    ensure!(
        s.private == 400 && s.exits == 600 && s.reserve == 1000,
        "exit incorrectly released reserve"
    );
    let mut negatives = Vec::new();
    for (index, name) in [
        (0, "credited deposit replay"),
        (1, "stale allowed-root double spend"),
        (2, "restored duplicate exit"),
    ] {
        let r = &h.records[index];
        negatives.push((
            name.to_owned(),
            reject_atomic(
                &s,
                &hex::decode(&r.intent)?,
                &hex::decode(&r.authorization)?,
                &record_receipt(&h, proofs, index)?,
            )?,
        ));
    }
    let receipt = record_receipt(&h, proofs, 1)?;
    let transfer = &accepted[1];
    for j in 0..8 {
        let mut i = transfer.clone();
        i.ids[j][0] ^= 1;
        negatives.push((
            format!("wrong immutable policy field {j}"),
            reject_atomic(&s, &i.encode()?, &[0], &receipt)?,
        ));
    }
    let genesis = State::genesis(&accepted[0])?;
    ensure!(
        genesis.allowed.len() == 1
            && genesis
                .allowed
                .contains(&orchard::Anchor::empty_tree().to_bytes()),
        "wrong genesis anchor"
    );
    negatives.push((
        "orphaned/unallowed root".into(),
        reject_atomic(&genesis, &transfer.encode()?, &[0], &receipt)?,
    ));
    // First credit uses the actual real receipt and consumes P without R += p.
    let mut batch = genesis.clone();
    let ci = hex::decode(&h.records[0].intent)?;
    let ca = hex::decode(&h.records[0].authorization)?;
    let cr = record_receipt(&h, proofs, 0)?;
    ensure!(
        batch.apply(&ci, &ca, &cr)?.0
            && batch.private == 1000
            && batch.pending == 0
            && batch.reserve == 1000,
        "first CREDIT/boundary conservation"
    );
    let mut bad = receipt.clone();
    if let risc0_zkvm::InnerReceipt::Succinct(ref mut inner) = bad.inner {
        inner.seal[0] ^= 1
    }
    let before = batch.economic_bytes();
    ensure!(
        !batch.apply(&transfer.encode()?, &[0], &bad)?.0 && before == batch.economic_bytes(),
        "bad proof changed economics"
    );
    ensure!(
        batch.apply(&transfer.encode()?, &[0], &receipt)?.0,
        "valid-after-invalid did not continue"
    );
    // Correct signature, same A and same message, different nonce prefix. This
    // hazardous API is solely an adversarial fixture with an unfunded test key;
    // honest wallet signing uses SigningKey::sign, never this altered prefix.
    let seed: [u8; 32] = hex::decode(
        alice
            .pending_deposit_seed
            .as_ref()
            .context("pending seed inventory")?,
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("seed width"))?;
    let expanded: [u8; 64] = Sha512::digest(seed).into();
    let mut esk = ExpandedSecretKey::from_bytes(&expanded);
    esk.hash_prefix[0] ^= 1;
    let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    let msg = kpi_recovery_auth_vectors::credit_message(
        &accepted[0].ids[0].as_slice().try_into()?,
        &hash(&ci),
    );
    let signature = raw_sign::<Sha512>(&esk, &msg, &vk).to_bytes();
    kpi_recovery_auth_vectors::verify_profile(&vk.to_bytes(), &msg, &signature)?;
    let alternate = [vec![1], signature.to_vec()].concat();
    ensure!(alternate != ca, "alternate signature fixture is identical");
    negatives.push((
        "C1 second valid signature on same intent".into(),
        reject_atomic(&genesis, &ci, &alternate, &cr)?,
    ));
    let mut expired = genesis.clone();
    expired.cursor = 101;
    negatives.push((
        "expired real receipt".into(),
        reject_atomic(&expired, &ci, &ca, &cr)?,
    ));
    let mut boundary = genesis.clone();
    boundary.cursor = 100;
    ensure!(
        boundary.apply(&ci, &ca, &cr)?.0,
        "inclusive expiry boundary rejected"
    );
    let mut overflow = genesis.clone();
    overflow.cursor = u64::MAX;
    let previous = overflow.commitment();
    ensure!(
        overflow.apply(&ci, &ca, &cr).is_err() && overflow.commitment() == previous,
        "cursor wrapped/partially mutated"
    );
    for count in [
        0,
        (1u64 << 32) - 2,
        (1u64 << 32) - 1,
        1u64 << 32,
        (1u64 << 32) + 1,
        u64::MAX,
    ] {
        for mode in [0, 1] {
            let want = count <= 1u64 << 32 && (mode == 1 || count <= (1u64 << 32) - 2);
            ensure!(
                state::capacity(count, mode).is_ok() == want,
                "capacity/no-wrap boundary"
            );
        }
    }
    // Complete history, ciphertexts and current spentness are authenticated
    // before trial decryption, so omissions never silently return zero balance.
    let mut changed = h.clone();
    let mut op = Intent::decode(&hex::decode(&changed.records[1].intent)?)?;
    op.ciphertext[0][10] ^= 1;
    changed.records[1].intent = hex::encode(op.encode()?);
    let altered = serde_json::to_vec_pretty(&changed)?;
    ensure!(
        history::restore(&altered, &expected, proofs, &alice).is_err(),
        "changed history accepted under old pin"
    );
    // A caller-recomputed pin explicitly trusts a different synthetic branch.
    // The changed transfer and its dependent exit must be no-ops there; this
    // cannot authenticate the original canonical history.
    let (altered_state, altered_accepted) = history::replay(&altered, &hash(&altered), proofs)?;
    let (_, altered_alice) = history::restore(&altered, &hash(&altered), proofs, &alice)?;
    let (_, altered_bob) = history::restore(&altered, &hash(&altered), proofs, &bob)?;
    ensure!(
        altered_accepted.len() == 1
            && altered_state.private == 1000
            && altered_state.exits == 0
            && altered_alice.iter().map(|n| n.value).sum::<u64>() == 1000
            && altered_bob.is_empty(),
        "changed ciphertext bypassed receipt binding/no-op classification"
    );
    let mut prefix = h.clone();
    prefix.records.pop();
    let prefix_raw = serde_json::to_vec_pretty(&prefix)?;
    ensure!(
        history::restore(&prefix_raw, &expected, proofs, &bob).is_err(),
        "stale/truncated history accepted as latest"
    );
    fixture::save(&out.join("before-exit-history.json"), &prefix_raw)?;
    let (_, before_b) = history::restore(&prefix_raw, &hash(&prefix_raw), proofs, &bob)?;
    ensure!(
        before_b.iter().map(|n| n.value).sum::<u64>() == 600,
        "pre-exit restored receiver balance"
    );
    let mut foreign = backup(&cases.join("alice-backup.json"))?;
    foreign.context[4] = "00".repeat(20);
    ensure!(
        history::restore(&raw, &expected, proofs, &foreign).is_err(),
        "foreign backup context accepted"
    );
    let mut missing = backup(&cases.join("alice-backup.json"))?;
    missing.pending_deposit_seed = None;
    ensure!(
        history::restore(&raw, &expected, proofs, &missing).is_err(),
        "incomplete pending recovery inventory accepted"
    );
    let mut duplicate = backup(&cases.join("alice-backup.json"))?;
    duplicate
        .orchard_keys
        .push(duplicate.orchard_keys[0].clone());
    ensure!(
        history::restore(&raw, &expected, proofs, &duplicate).is_err(),
        "duplicate backup keys inflated restored balance"
    );
    let mut absent = h.clone();
    absent.records[1].name = "missing-receipt".into();
    let absent_raw = serde_json::to_vec_pretty(&absent)?;
    ensure!(
        history::restore(&absent_raw, &hash(&absent_raw), proofs, &alice).is_err(),
        "missing receipt treated as invalid or zero balance"
    );
    let mut alias = backup(&cases.join("alice-backup.json"))?;
    alias
        .orchard_keys
        .push(alias.orchard_keys[0].to_uppercase());
    ensure!(
        history::restore(&raw, &expected, proofs, &alias).is_err(),
        "hex alias duplicate key inflated restored balance"
    );
    // Persist a well-formed false receipt between valid operations and replay
    // that complete synthetic order, rather than using a host validity flag.
    let bad_dir = proofs.join("invalid-wallet");
    fs::create_dir(&bad_dir)?;
    fs::create_dir(bad_dir.join("proof"))?;
    let false_bytes = bincode::serialize(&bad)?;
    fixture::save(&bad_dir.join("proof/wallet-receipt.bin"), &false_bytes)?;
    let mut mixed = h.clone();
    let mut false_record = h.records[1].clone();
    false_record.name = "invalid-wallet".into();
    false_record.receipt_sha256 = hex::encode(hash(&false_bytes));
    mixed.records.insert(1, false_record);
    let mixed_raw = serde_json::to_vec_pretty(&mixed)?;
    let mixed_pin = hash(&mixed_raw);
    let (mixed_state, mixed_notes) = history::restore(&mixed_raw, &mixed_pin, proofs, &alice)?;
    ensure!(
        mixed_state.cursor == 4
            && mixed_state.private == 400
            && mixed_notes.len() == 1
            && mixed_notes[0].value == 400,
        "restore omitted invalid operation or reset spentness"
    );
    reject_atomic(&mixed_state, &transfer.encode()?, &[0], &receipt)?;
    fixture::save(&out.join("mixed-history.json"), &mixed_raw)?;
    // Spend the internal change reconstructed from backup + public history only.
    let sk = history::keys(&alice)?[0];
    let mut i = fixture::base(s.ids.clone(), 2, s.tree.root_path(None)?.0);
    i.mode = 1;
    i.exited = 400;
    i.exit = Some(Script {
        version: 0,
        bytes: vec![0x51],
    });
    let mut restored = Witness {
        intent: i,
        old: [a[0].clone(), fixture::dummy()?],
        new: [
            fixture::new_output(sk, 1, 0)?,
            fixture::new_output(sk, 0, 0)?,
        ],
        auth: vec![],
    };
    fixture::complete(&mut restored, None)?;
    let program = fs::read(cases.join("credit/program.bin"))?;
    fixture::case(cases, "restored-exit", &program, &restored)?;
    let report = json!({"scope":"RECEIPT_BACKED_HOST_ADMISSION_AND_RESTORE_NOT_PROVED_OUTER_OR_NATIVE","historySha256":hex::encode(expected),"beforeExitHistorySha256":hex::encode(hash(&prefix_raw)),"stateCommitment":hex::encode(s.commitment()),"realWalletReceiptsReplayed":3,"negativeAdmissionCases":negatives,"historyAndBackupRejections":7,"replacementPinBranchRejectsAlteredOperations":true,"capacityBoundaryChecks":12,"inclusiveExpiryAndOverflowChecked":true,"hostValidInvalidValid":true,"mixedHistoryRestored":true,"mixedHistorySha256":hex::encode(mixed_pin),"secondValidSignatureRejectedByJournal":true,"aliceRestoredInternalSompi":400,"bobSpentSompi":600,"reserveSompi":1000,"privateSompi":400,"unpaidExitSompi":600,"restoredSpendCasePrepared":true,"fullTreeMaterialized":false,"nativeTransactions":0});
    fixture::save(
        &out.join("report.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    println!(
        "Receipt-backed offline admission and restore controls passed; restored exit prepared."
    );
    Ok(())
}
pub fn finalize(cases: &Path, proofs: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let path = out.join("history.json");
    let expected = history::seal(
        cases,
        proofs,
        &path,
        &["credit", "transfer", "exit", "restored-exit"],
    )?;
    let raw = fs::read(&path)?;
    let (s, a) = history::restore(
        &raw,
        &expected,
        proofs,
        &backup(&cases.join("alice-backup.json"))?,
    )?;
    let (_, b) = history::restore(
        &raw,
        &expected,
        proofs,
        &backup(&cases.join("bob-backup.json"))?,
    )?;
    ensure!(
        a.is_empty() && b.is_empty() && s.private == 0 && s.exits == 1000 && s.reserve == 1000,
        "restored exit accounting mismatch"
    );
    let h: History = serde_json::from_slice(&raw)?;
    let mut double_rejections = 0;
    for j in [1, 2, 3] {
        let r = &h.records[j];
        reject_atomic(
            &s,
            &hex::decode(&r.intent)?,
            &hex::decode(&r.authorization)?,
            &record_receipt(&h, proofs, j)?,
        )?;
        double_rejections += 1;
    }
    fixture::save(
        &out.join("report.json"),
        &serde_json::to_vec_pretty(
            &json!({"scope":"FOUR_REAL_OFFLINE_WALLET_RECEIPTS_HOST_REPLAY_AND_RESTORE_NOT_NATIVE_R16","historySha256":hex::encode(expected),"stateCommitment":hex::encode(s.commitment()),"realWalletReceiptsReplayed":4,"restoredSpendProofAccepted":true,"restoredReplayRejections":double_rejections,"aliceSpendableSompi":0,"bobSpendableSompi":0,"privateSompi":0,"unpaidExitSompi":1000,"reserveSompi":1000,"nativePayouts":0,"nativeTransactions":0}),
        )?,
    )?;
    println!("Four real receipts replayed: restored spend accepted; duplicate spends/exits rejected; all 1000 sompi remain unpaid synthetic exit liabilities.");
    Ok(())
}

/// Public evidence verification needs no backup, key or original witness.
pub fn verify_history(hist: &Path, expected: &str, proofs: &Path, out: &Path) -> Result<()> {
    let raw = fs::read(hist)?;
    let (s, accepted) = history::replay(&raw, &pin(expected)?, proofs)?;
    let records: History = serde_json::from_slice(&raw)?;
    fixture::save(
        out,
        &serde_json::to_vec_pretty(
            &json!({"scope":"PUBLIC_RECEIPT_AND_SYNTHETIC_HISTORY_VERIFICATION_NOT_NATIVE_ACCEPTANCE","historySha256":expected,"actualWalletImage":hex::encode(&s.ids[7]),"stateCommitment":hex::encode(s.commitment()),"acceptedWalletOperations":accepted.len(),"rejectedOperations":records.records.len()-accepted.len(),"cursor":s.cursor,"privateLiabilitiesSompi":s.private,"pendingSompi":s.pending,"unpaidExitSompi":s.exits,"unpaidFeeSompi":s.fees,"reserveSompi":s.reserve,"nullifiers":s.spent.len(),"leaves":s.tree.leaves.len(),"allowedAnchors":s.allowed.len(),"privateInputsOrBackupsRead":false,"nativeTransactions":0}),
        )?,
    )?;
    println!(
        "Verified {} wallet operations and current synthetic state using only public evidence",
        accepted.len()
    );
    Ok(())
}
