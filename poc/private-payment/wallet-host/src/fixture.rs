//! Fresh unfunded secrets, synthetic deposits/policy and complete local fixtures.
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use kpi_wallet_core::{
    incrementalmerkletree::{Hashable, Level},
    orchard::{
        keys::{Diversifier, FullViewingKey, Scope, SpendingKey},
        note::{RandomSeed, Rho},
        tree::MerkleHashOrchard,
        Anchor,
    },
    *,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub fn entropy<const N: usize>() -> Result<[u8; N]> {
    let mut a = [0; N];
    fs::File::open("/dev/urandom")?.read_exact(&mut a)?;
    Ok(a)
}
pub fn spending_key() -> Result<[u8; 32]> {
    loop {
        let b = entropy()?;
        if bool::from(SpendingKey::from_bytes(b).is_some()) {
            return Ok(b);
        }
    }
}
pub fn fresh_rho() -> Result<[u8; 32]> {
    loop {
        let b = entropy()?;
        if bool::from(Rho::from_bytes(&b).is_some()) {
            return Ok(b);
        }
    }
}
pub fn fresh_seed(rho: &[u8; 32]) -> Result<[u8; 32]> {
    let rho = Option::<Rho>::from(Rho::from_bytes(rho)).context("rho")?;
    loop {
        let b = entropy()?;
        if bool::from(RandomSeed::from_bytes(b, &rho).is_some()) {
            return Ok(b);
        }
    }
}
pub fn address(sk: [u8; 32], scope: u8, d: [u8; 11]) -> [u8; 43] {
    FullViewingKey::from(&SpendingKey::from_bytes(sk).unwrap())
        .address(
            Diversifier::from_bytes(d),
            if scope == 0 {
                Scope::External
            } else {
                Scope::Internal
            },
        )
        .to_raw_address_bytes()
}
pub fn dummy() -> Result<OldNote> {
    let rho = fresh_rho()?;
    Ok(OldNote {
        sk: spending_key()?,
        scope: 0,
        diversifier: entropy()?,
        value: 0,
        rho,
        seed: fresh_seed(&rho)?,
        path: None,
    })
}
pub fn new_output(sk: [u8; 32], scope: u8, value: u64) -> Result<NewNote> {
    Ok(NewNote {
        address: address(sk, scope, entropy()?),
        value,
        seed: entropy()?,
        memo: [0; 512],
    })
}
pub fn complete(w: &mut Witness, signer: Option<[u8; 32]>) -> Result<()> {
    for slot in 0..2 {
        let (n, f) = old_note(&w.old[slot])?;
        w.intent.nf[slot] = n.nullifier(&f).to_bytes();
        // Seed constructors are rejection sampled for each actual new rho.
        if Option::<RandomSeed>::from(RandomSeed::from_bytes(
            w.new[slot].seed,
            &Rho::from_bytes(&w.intent.nf[slot]).unwrap(),
        ))
        .is_none()
        {
            w.new[slot].seed = fresh_seed(&w.intent.nf[slot])?
        }
        let (c, e, b) = output(&w.new[slot], &w.intent.nf[slot])?;
        w.intent.cmx[slot] = c;
        w.intent.epk[slot] = e;
        w.intent.ciphertext[slot] = b;
    }
    w.auth = if let Some(sk) = signer {
        let msg = kpi_recovery_auth_vectors::credit_message(
            &w.intent.ids[0].as_slice().try_into()?,
            &hash(&w.intent.encode()?),
        );
        [
            vec![1],
            SigningKey::from_bytes(&sk).sign(&msg).to_bytes().to_vec(),
        ]
        .concat()
    } else {
        vec![0]
    };
    validate(w)?;
    Ok(())
}
#[derive(Clone, Default)]
pub struct Tree {
    pub leaves: Vec<[u8; 32]>,
}
impl Tree {
    pub fn root_path(&self, position: Option<u32>) -> Result<([u8; 32], [[u8; 32]; 32])> {
        if let Some(p) = position {
            ensure!((p as usize) < self.leaves.len(), "position not present")
        }
        let mut nodes = self
            .leaves
            .iter()
            .map(|b| {
                Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(b)).context("leaf")
            })
            .collect::<Result<Vec<_>>>()?;
        let mut siblings = [[0; 32]; 32];
        for (level, sibling) in siblings.iter_mut().enumerate() {
            let empty = MerkleHashOrchard::empty_root(Level::from(level as u8));
            let at = position.map(|p| (p as usize >> level) ^ 1).unwrap_or(0);
            *sibling = nodes.get(at).unwrap_or(&empty).to_bytes();
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    MerkleHashOrchard::combine(
                        Level::from(level as u8),
                        &pair[0],
                        pair.get(1).unwrap_or(&empty),
                    )
                })
                .collect();
        }
        Ok((
            nodes
                .first()
                .copied()
                .unwrap_or_else(|| MerkleHashOrchard::empty_root(Level::from(32)))
                .to_bytes(),
            siblings,
        ))
    }
    pub fn append(&mut self, i: &Intent) {
        if i.mode == 0 {
            self.leaves.extend(i.cmx)
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub profile: String,
    pub context: Vec<String>,
    pub orchard_keys: Vec<String>,
    pub pending_deposit_seed: Option<String>,
    pub pending_deposit_reference: Option<String>,
}
// Local research files include real fresh secrets but authorize no funds. Never
// include this backup or input.bin files in public evidence archives.
pub fn save_secret(p: &Path, b: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    Ok(())
}
pub fn save(p: &Path, b: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    Ok(())
}
pub fn base(ids: [Vec<u8>; 8], kind: u8, anchor: [u8; 32]) -> Intent {
    Intent {
        ids,
        kind,
        mode: 0,
        expiry: Some(100),
        anchor,
        nf: [[0; 32]; 2],
        cmx: [[0; 32]; 2],
        epk: [[0; 32]; 2],
        ciphertext: [[0; 580]; 2],
        deposit: None,
        principal: 0,
        exit: None,
        exited: 0,
        fee_script: None,
        fee: 0,
    }
}
pub fn case(root: &Path, name: &str, program: &[u8], w: &Witness) -> Result<()> {
    let p = root.join(name);
    fs::create_dir(&p)?;
    let input = w.encode()?;
    let journal = w.intent.journal(&w.auth)?;
    save(&p.join("program.bin"), program)?;
    save_secret(&p.join("input.bin"), &input)?;
    save(&p.join("intent.bin"), &w.intent.encode()?)?;
    save(&p.join("authorization.bin"), &w.auth)?;
    save(&p.join("expected-journal.bin"), &journal)?;
    save(
        &p.join("case.json"),
        &serde_json::to_vec_pretty(
            &json!({"program_sha256":hex::encode(hash(program)),"input_sha256":hex::encode(hash(&input)),"expected_journal_sha256":hex::encode(hash(&journal)),"expected_program_image":risc0_zkvm::compute_image_id(program)?.to_string()}),
        )?,
    )?;
    Ok(())
}
pub fn prepare(program: &Path, root: &Path) -> Result<()> {
    let program = fs::read(program)?;
    let image = risc0_zkvm::compute_image_id(&program)?;
    fs::create_dir(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let ids: [Vec<u8>; 8] = std::array::from_fn(|i| {
        if i == 7 {
            image.as_bytes().to_vec()
        } else {
            let x = hash(format!("KPI/offline/synthetic-policy/v1/{i}").as_bytes());
            x[..if i == 4 { 20 } else { 32 }].to_vec()
        }
    });
    let a = spending_key()?;
    let b = spending_key()?;
    let deposit_seed = entropy()?;
    let deposit = Deposit {
        tx: entropy()?,
        index: 0,
        descriptor: entropy()?,
        key: SigningKey::from_bytes(&deposit_seed)
            .verifying_key()
            .to_bytes(),
    };
    let backup = Backup {
        profile: "OFFLINE_ONLY_PLAINTEXT_RESEARCH_BACKUP_V1".into(),
        context: ids.iter().map(hex::encode).collect(),
        orchard_keys: vec![hex::encode(a), hex::encode(b)],
        pending_deposit_seed: Some(hex::encode(deposit_seed)),
        pending_deposit_reference: Some(hex::encode(
            [
                deposit.tx.to_vec(),
                deposit.index.to_le_bytes().to_vec(),
                deposit.descriptor.to_vec(),
                deposit.key.to_vec(),
                1000u64.to_le_bytes().to_vec(),
            ]
            .concat(),
        )),
    };
    save_secret(
        &root.join("backup.json"),
        &serde_json::to_vec_pretty(&backup)?,
    )?;
    let alice = Backup {
        profile: backup.profile.clone(),
        context: backup.context.clone(),
        orchard_keys: vec![hex::encode(a)],
        pending_deposit_seed: backup.pending_deposit_seed.clone(),
        pending_deposit_reference: backup.pending_deposit_reference.clone(),
    };
    let bob = Backup {
        profile: backup.profile.clone(),
        context: backup.context.clone(),
        orchard_keys: vec![hex::encode(b)],
        pending_deposit_seed: None,
        pending_deposit_reference: None,
    };
    save_secret(
        &root.join("alice-backup.json"),
        &serde_json::to_vec_pretty(&alice)?,
    )?;
    save_secret(
        &root.join("bob-backup.json"),
        &serde_json::to_vec_pretty(&bob)?,
    )?;
    let mut i = base(ids.clone(), 0, Anchor::empty_tree().to_bytes());
    i.principal = 1000;
    i.deposit = Some(deposit);
    let mut credit = Witness {
        intent: i,
        old: [dummy()?, dummy()?],
        new: [new_output(a, 0, 700)?, new_output(a, 1, 300)?],
        auth: vec![],
    };
    complete(&mut credit, Some(deposit_seed))?;
    let mut tree = Tree::default();
    tree.append(&credit.intent);
    case(root, "credit", &program, &credit)?;
    let old_from =
        |w: &Witness, slot: usize, sk, scope, position, tree: &Tree| -> Result<OldNote> {
            let n = new_note(&w.new[slot], &w.intent.nf[slot])?;
            Ok(OldNote {
                sk,
                scope,
                diversifier: n.recipient().to_raw_address_bytes()[..11].try_into()?,
                value: n.value().inner(),
                rho: n.rho().to_bytes(),
                seed: *n.rseed().as_bytes(),
                path: Some((position, tree.root_path(Some(position))?.1)),
            })
        };
    let mut transfer = Witness {
        intent: base(ids.clone(), 1, tree.root_path(None)?.0),
        old: [
            old_from(&credit, 0, a, 0, 0, &tree)?,
            old_from(&credit, 1, a, 1, 1, &tree)?,
        ],
        new: [new_output(b, 0, 600)?, new_output(a, 1, 400)?],
        auth: vec![],
    };
    complete(&mut transfer, None)?;
    case(root, "transfer", &program, &transfer)?;
    tree.append(&transfer.intent);
    let mut i = base(ids.clone(), 2, tree.root_path(None)?.0);
    i.mode = 1;
    i.exited = 600;
    i.exit = Some(Script {
        version: 0,
        bytes: vec![0x51],
    });
    let mut exit = Witness {
        intent: i,
        old: [old_from(&transfer, 0, b, 0, 2, &tree)?, dummy()?],
        new: [new_output(b, 1, 0)?, new_output(b, 0, 0)?],
        auth: vec![],
    };
    complete(&mut exit, None)?;
    case(root, "exit", &program, &exit)?;
    // Restored Alice must reconstruct this internal change note from ciphertexts,
    // not from transfer's retained private witness. Native checking creates its
    // exit later using scan results and the same current synthetic history.
    save(
        &root.join("fixture.json"),
        &serde_json::to_vec_pretty(
            &json!({"scope":"UNFUNDED_OFFLINE_SYNTHETIC_POLICY_AND_HISTORY","context":ids.iter().map(hex::encode).collect::<Vec<_>>(),"order":["credit","transfer","exit"],"nativeTransactions":0,"initialPrincipalSompi":1000,"expectedAfterExit":{"alice":400,"bob":0,"unpaidExit":600},"actualWalletImage":image.to_string()}),
        )?,
    )?;
    println!(
        "Prepared fresh unfunded offline credit/transfer/exit cases; secrets retained locally."
    );
    Ok(())
}
