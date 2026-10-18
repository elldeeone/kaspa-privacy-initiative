//! Existing-library interoperability checks, not a private wallet circuit.
use anyhow::{ensure, Context, Result};
use incrementalmerkletree::{Hashable, Level};
use orchard::{
    keys::{
        Diversifier, FullViewingKey, IncomingViewingKey, PreparedIncomingViewingKey, Scope,
        SpendValidatingKey, SpendingKey,
    },
    note::{
        ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho, TransmittedNoteCiphertext,
    },
    note_encryption::{NoteBytesData, OrchardDomain, OrchardNoteEncryption},
    tree::{MerkleHashOrchard, MerklePath},
    value::{NoteValue, ValueCommitment},
    Action, Address, Note,
};
use pasta_curves::pallas;
use serde_json::{json, Value};
use std::{fs, io::Write, path::Path};
use zcash_note_encryption::{try_note_decryption, Domain};

fn bytes<const N: usize>(value: &Value) -> Result<[u8; N]> {
    hex::decode(value.as_str().context("hex string")?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong byte length"))
}

fn key_vectors(vectors: &[Value]) -> Result<usize> {
    let mut boundaries = 0;
    for v in vectors {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes(&v["sk"])?))
            .context("valid published SK")?;
        let fvk = FullViewingKey::from(&sk);
        let expected_fvk = [&v["ak"], &v["nk"], &v["rivk"]]
            .into_iter()
            .map(|v| hex::decode(v.as_str().unwrap()))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .concat();
        ensure!(
            fvk.to_bytes().as_slice() == expected_fvk,
            "full viewing key mismatch"
        );
        let ivk = fvk.to_ivk(Scope::External).to_bytes();
        ensure!(
            ivk[..32] == bytes::<32>(&v["dk"])? && ivk[32..] == bytes::<32>(&v["ivk"])?,
            "incoming viewing key mismatch"
        );
        let addr = fvk.address(
            Diversifier::from_bytes(bytes(&v["default_d"])?),
            Scope::External,
        );
        let raw = addr.to_raw_address_bytes();
        ensure!(
            raw[..11] == bytes::<11>(&v["default_d"])?
                && raw[11..] == bytes::<32>(&v["default_pk_d"])?,
            "recipient mismatch"
        );
        ensure!(
            fvk.scope_for_address(&addr) == Some(Scope::External),
            "recipient hierarchy mismatch"
        );
        let rho = Option::<Rho>::from(Rho::from_bytes(&bytes(&v["note_rho"])?)).context("rho")?;
        let seed =
            Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes(&v["note_rseed"])?, &rho))
                .context("seed")?;
        let note = Option::<Note>::from(Note::from_parts(
            addr,
            NoteValue::from_raw(v["note_v"].as_u64().context("u64 value")?),
            rho,
            seed,
            NoteVersion::V2,
        ))
        .context("published note")?;
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        ensure!(
            cmx.to_bytes() == bytes::<32>(&v["note_cmx"])?,
            "V2 commitment mismatch"
        );
        ensure!(
            note.nullifier(&fvk).to_bytes() == bytes::<32>(&v["note_nf"])?,
            "nullifier mismatch"
        );
        let wrong_sk =
            Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).context("test SK")?;
        let wrong_fvk = FullViewingKey::from(&wrong_sk);
        ensure!(
            wrong_fvk.scope_for_address(&addr).is_none(),
            "wrong spending key owns recipient"
        );
        ensure!(
            note.nullifier(&wrong_fvk) != note.nullifier(&fvk),
            "wrong nullifier authority alias"
        );
        for amount in [0, 1, u64::MAX] {
            let seed =
                Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes(&v["note_rseed"])?, &rho))
                    .context("boundary seed")?;
            let n = Option::<Note>::from(Note::from_parts(
                addr,
                NoteValue::from_raw(amount),
                rho,
                seed,
                NoteVersion::V2,
            ))
            .context("boundary note")?;
            ensure!(n.value().inner() == amount, "u64 note range changed");
            boundaries += 1;
        }
    }
    Ok(boundaries)
}

fn encryption_vectors(vectors: &[Value]) -> Result<usize> {
    let test_sk =
        Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).context("test key")?;
    let vk = SpendValidatingKey::from(FullViewingKey::from(&test_sk));
    let rk = vk.randomize(&pallas::Scalar::from(0));
    let mut negative = 0;
    for (index, v) in vectors.iter().enumerate() {
        let ivk = Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(&bytes(
            &v["incoming_viewing_key"],
        )?))
        .context("ivk")?;
        let prepared = PreparedIncomingViewingKey::new(&ivk);
        let mut address = [0; 43];
        address[..11].copy_from_slice(&bytes::<11>(&v["default_d"])?);
        address[11..].copy_from_slice(&bytes::<32>(&v["default_pk_d"])?);
        let address = Option::<Address>::from(Address::from_raw_address_bytes(&address))
            .context("address")?;
        let nf = Option::<Nullifier>::from(Nullifier::from_bytes(&bytes(&v["nf_old"])?))
            .context("nf")?;
        let rho = Option::<Rho>::from(Rho::from_bytes(&nf.to_bytes())).context("rho")?;
        let seed = Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes(&v["rseed"])?, &rho))
            .context("seed")?;
        let note = Option::<Note>::from(Note::from_parts(
            address,
            NoteValue::from_raw(v["v"].as_u64().context("value")?),
            rho,
            seed,
            NoteVersion::V2,
        ))
        .context("note")?;
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        ensure!(
            cmx.to_bytes() == bytes::<32>(&v["cmx"])?,
            "encryption note commitment mismatch"
        );
        let memo: [u8; 512] = bytes(&v["memo"])?;
        let ne = OrchardNoteEncryption::new(None, note, memo);
        ensure!(
            OrchardDomain::epk_bytes(ne.epk()).0 == bytes::<32>(&v["ephemeral_key"])?,
            "derived ephemeral key mismatch"
        );
        ensure!(
            ne.encrypt_note_plaintext().as_ref() == bytes::<580>(&v["c_enc"])?,
            "full encrypted delivery mismatch"
        );
        let cv =
            Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&bytes(&v["cv_net"])?))
                .context("cv")?;
        // A valid test rk is needed only to construct the public output type.
        // It does not authorize spending/crediting any note in this checker.
        let make = |epk, ciphertext| {
            Action::from_parts(
                nf,
                rk.clone(),
                cmx,
                TransmittedNoteCiphertext {
                    epk_bytes: epk,
                    enc_ciphertext: NoteBytesData(ciphertext),
                    out_ciphertext: [0; 80],
                },
                cv.clone(),
                (),
            )
        };
        let ciphertext: [u8; 580] = bytes(&v["c_enc"])?;
        let action = make(bytes(&v["ephemeral_key"])?, ciphertext)?;
        let domain = OrchardDomain::for_action(&action);
        let (decoded, recipient, m) =
            try_note_decryption(&domain, &prepared, &action).context("full trial decryption")?;
        ensure!(
            decoded.version() == NoteVersion::V2 && recipient == address && m == memo,
            "received data mismatch"
        );
        for at in [0, 52, 579] {
            let mut bad = ciphertext;
            bad[at] ^= 1;
            let bad = make(bytes(&v["ephemeral_key"])?, bad)?;
            ensure!(
                try_note_decryption(&domain, &prepared, &bad).is_none(),
                "altered ciphertext accepted"
            );
            negative += 1;
        }
        let other = &vectors[(index + 1) % vectors.len()];
        let wrong = Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(&bytes(
            &other["incoming_viewing_key"],
        )?))
        .context("other IVK")?;
        ensure!(
            try_note_decryption(&domain, &PreparedIncomingViewingKey::new(&wrong), &action)
                .is_none(),
            "wrong recipient decrypted"
        );
        ensure!(
            make([0; 32], ciphertext).is_err() && make([255; 32], ciphertext).is_err(),
            "identity/malformed ephemeral key accepted"
        );
        negative += 3;
        let seed = Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes(&v["rseed"])?, &rho))
            .context("version seed")?;
        let newer = Option::<Note>::from(Note::from_parts(
            address,
            NoteValue::from_raw(v["v"].as_u64().unwrap()),
            rho,
            seed,
            NoteVersion::V3,
        ))
        .context("V3 comparison note")?;
        let newer_cmx = ExtractedNoteCommitment::from(newer.commitment());
        let ne = OrchardNoteEncryption::new(None, newer, memo);
        let newer_action = Action::from_parts(
            nf,
            rk.clone(),
            newer_cmx,
            TransmittedNoteCiphertext {
                epk_bytes: OrchardDomain::epk_bytes(ne.epk()).0,
                enc_ciphertext: ne.encrypt_note_plaintext(),
                out_ciphertext: [0; 80],
            },
            cv,
            (),
        )?;
        ensure!(
            try_note_decryption(
                &OrchardDomain::for_action(&newer_action),
                &prepared,
                &newer_action
            )
            .is_none(),
            "unsupported V3 decrypted in V2 domain"
        );
        negative += 1;
    }
    Ok(negative)
}

fn tree_vectors(data: &Value, full_depth: &Value) -> Result<(usize, usize)> {
    let empty = data["commitment_tree"][0]["empty_roots"]
        .as_array()
        .context("empty roots")?;
    ensure!(empty.len() == 33, "33 empty roots required");
    for (i, root) in empty.iter().enumerate() {
        ensure!(
            MerkleHashOrchard::empty_root(Level::from(i as u8)).to_bytes() == bytes::<32>(root)?,
            "empty root mismatch"
        );
    }
    let mut paths = 0;
    for v in data["merkle_path"].as_array().context("published paths")? {
        for (position, path) in v["paths"].as_array().context("paths")?.iter().enumerate() {
            let mut node = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(
                &bytes(&v["leaves"][position])?,
            ))
            .context("leaf")?;
            for (level, sibling) in path.as_array().context("path")?.iter().enumerate() {
                let sibling = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(
                    &bytes(sibling)?,
                ))
                .context("sibling")?;
                node = if position & (1 << level) == 0 {
                    MerkleHashOrchard::combine(Level::from(level as u8), &node, &sibling)
                } else {
                    MerkleHashOrchard::combine(Level::from(level as u8), &sibling, &node)
                };
            }
            ensure!(
                node.to_bytes() == bytes::<32>(&v["root"])?,
                "published 4-level path mismatch"
            );
            paths += 1;
        }
    }
    let mut negatives = 0;
    for v in full_depth["vectors"]
        .as_array()
        .context("independent full-depth paths")?
    {
        let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
            &bytes(&v["leaf"])?,
        ))
        .context("full-depth leaf")?;
        let siblings: Vec<_> = v["siblings"]
            .as_array()
            .context("siblings")?
            .iter()
            .map(|x| {
                Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&bytes(x)?))
                    .context("full-depth sibling")
            })
            .collect::<Result<_>>()?;
        let path: [MerkleHashOrchard; 32] = siblings
            .try_into()
            .map_err(|_| anyhow::anyhow!("depth32 required"))?;
        let position = u32::try_from(v["position"].as_u64().context("position")?)?;
        ensure!(
            MerklePath::from_parts(position, path).root(cmx).to_bytes() == bytes::<32>(&v["root"])?,
            "independent depth32 root mismatch"
        );
        ensure!(
            MerklePath::from_parts(position ^ 1, path)
                .root(cmx)
                .to_bytes()
                != bytes::<32>(&v["root"])?,
            "changed position accepted"
        );
        negatives += 1;
        let mut bad = path;
        bad[31] = MerkleHashOrchard::empty_root(Level::from(30));
        ensure!(
            MerklePath::from_parts(position, bad).root(cmx).to_bytes() != bytes::<32>(&v["root"])?,
            "wrong high sibling accepted"
        );
        negatives += 1;
    }
    Ok((paths, negatives))
}

fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(a.len() == 4, "VECTORS_JSON DEPTH32_JSON NEW_REPORT");
    let data: Value = serde_json::from_slice(&fs::read(&a[1])?)?;
    ensure!(
        data["orchardCommit"] == "616a669df8c9a59c33d47064d3ce04b25d026b2e",
        "vector source pin mismatch"
    );
    let full: Value = serde_json::from_slice(&fs::read(&a[2])?)?;
    let keys = data["keys"].as_array().context("key vectors")?;
    let encryption = data["note_encryption"]
        .as_array()
        .context("encryption vectors")?;
    ensure!(
        keys.len() == 10 && encryption.len() == 10,
        "complete published corpus required"
    );
    let boundaries = key_vectors(keys)?;
    let additional = full["additionalNoteEncryptionVectors"]
        .as_array()
        .context("independent encryption corpus")?;
    ensure!(
        additional.len() == 10,
        "complete independent encryption corpus required"
    );
    let encryption_negatives = encryption_vectors(encryption)? + encryption_vectors(additional)?;
    let (paths, tree_negatives) = tree_vectors(&data, &full)?;
    ensure!(
        FullViewingKey::from_bytes(&[255; 96]).is_none(),
        "noncanonical FVK accepted"
    );
    ensure!(
        bool::from(IncomingViewingKey::from_bytes(&[0; 64]).is_none()),
        "zero IVK accepted"
    );
    ensure!(
        bool::from(Rho::from_bytes(&[255; 32]).is_none()),
        "noncanonical rho accepted"
    );
    ensure!(
        bool::from(Nullifier::from_bytes(&[255; 32]).is_none()),
        "noncanonical nullifier accepted"
    );
    ensure!(
        bool::from(ExtractedNoteCommitment::from_bytes(&[255; 32]).is_none()),
        "noncanonical cmx accepted"
    );
    ensure!(
        bool::from(MerkleHashOrchard::from_bytes(&[255; 32]).is_none()),
        "noncanonical sibling accepted"
    );
    ensure!(
        bool::from(Address::from_raw_address_bytes(&[255; 43]).is_none()),
        "malformed recipient accepted"
    );
    let report = json!({"scope":"NATIVE_ESTABLISHED_PRIMITIVE_INTEROPERABILITY_NOT_WALLET_PROOF_OR_AUDIT",
        "orchardCommit":data["orchardCommit"],"keyNoteNullifierVectors":keys.len(),"encryptionVectors":encryption.len()+additional.len(),
        "u64ValueBoundaryNotes":boundaries,"encryptionNegativeCases":encryption_negatives,"publishedEmptyRoots":33,
        "publishedFourLevelPaths":paths,"independentDepth32Paths":full["vectors"].as_array().unwrap().len(),
        "depth32NegativeCases":tree_negatives,"malformedEncodingCases":7,"nativeTransactions":0,"fullWalletRelationImplemented":false});
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new(&a[3]))?;
    writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    println!("{}", report);
    Ok(())
}
