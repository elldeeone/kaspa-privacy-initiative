//! Research-only exact Orchard V2 wallet relation; no native or pool authority.
pub mod codec;
use anyhow::{ensure, Context, Result};
pub use codec::*;
pub use incrementalmerkletree;
pub use orchard;
use orchard::{
    keys::{Diversifier, FullViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    note_encryption::{OrchardDomain, OrchardNoteEncryption},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Address, Anchor, Note,
};
pub use zcash_note_encryption;
use zcash_note_encryption::Domain;

pub fn old_note(n: &OldNote) -> Result<(Note, FullViewingKey)> {
    ensure!(n.scope <= 1, "unknown scope");
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(n.sk)).context("spending key")?;
    let fvk = FullViewingKey::from(&sk);
    let address = fvk.address(
        Diversifier::from_bytes(n.diversifier),
        if n.scope == 0 {
            Scope::External
        } else {
            Scope::Internal
        },
    );
    let rho = Option::<Rho>::from(Rho::from_bytes(&n.rho)).context("old rho")?;
    let seed =
        Option::<RandomSeed>::from(RandomSeed::from_bytes(n.seed, &rho)).context("old seed")?;
    let note = Option::<Note>::from(Note::from_parts(
        address,
        NoteValue::from_raw(n.value),
        rho,
        seed,
        NoteVersion::V2,
    ))
    .context("old note")?;
    Ok((note, fvk))
}
pub fn new_note(n: &NewNote, nf: &[u8; 32]) -> Result<Note> {
    let address = Option::<Address>::from(Address::from_raw_address_bytes(&n.address))
        .context("output address")?;
    let rho = Option::<Rho>::from(Rho::from_bytes(nf)).context("new rho from nf")?;
    let seed =
        Option::<RandomSeed>::from(RandomSeed::from_bytes(n.seed, &rho)).context("new seed")?;
    Option::<Note>::from(Note::from_parts(
        address,
        NoteValue::from_raw(n.value),
        rho,
        seed,
        NoteVersion::V2,
    ))
    .context("new note")
}
pub fn output(n: &NewNote, nf: &[u8; 32]) -> Result<([u8; 32], [u8; 32], [u8; 580])> {
    let note = new_note(n, nf)?;
    let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
    let enc = OrchardNoteEncryption::new(None, note, n.memo);
    Ok((
        cmx,
        OrchardDomain::epk_bytes(enc.epk()).0,
        enc.encrypt_note_plaintext().0,
    ))
}
pub fn validate(w: &Witness) -> Result<Vec<u8>> {
    let i = &w.intent;
    i.shape()?;
    Option::<Anchor>::from(Anchor::from_bytes(i.anchor)).context("canonical anchor")?;
    ensure!(i.nf[0] != i.nf[1], "duplicate slot nullifier");
    let mut input = 0u128;
    let mut out = 0u128;
    for slot in 0..2 {
        let n = &w.old[slot];
        ensure!(
            n.path.is_some() == (n.value > 0),
            "membership presence/value mismatch"
        );
        let (note, fvk) = old_note(n)?;
        ensure!(
            note.nullifier(&fvk).to_bytes() == i.nf[slot],
            "derived nullifier mismatch"
        );
        if let Some((position, siblings)) = &n.path {
            let mut path = [MerkleHashOrchard::empty_leaf(); 32];
            for (p, b) in path.iter_mut().zip(siblings) {
                *p = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(b))
                    .context("canonical sibling")?
            }
            ensure!(
                MerklePath::from_parts(*position, path)
                    .root(ExtractedNoteCommitment::from(note.commitment()))
                    .to_bytes()
                    == i.anchor,
                "membership root mismatch"
            );
        }
        let (cmx, epk, ciphertext) = output(&w.new[slot], &i.nf[slot])?;
        ensure!(
            cmx == i.cmx[slot] && epk == i.epk[slot] && ciphertext == i.ciphertext[slot],
            "output commitment/delivery mismatch"
        );
        input = input
            .checked_add(n.value as u128)
            .context("input overflow")?;
        out = out
            .checked_add(w.new[slot].value as u128)
            .context("output overflow")?;
    }
    let spent = out
        .checked_add(i.exited as u128)
        .and_then(|v| v.checked_add(i.fee as u128))
        .context("balance overflow")?;
    match i.kind {
        0 => ensure!(
            input == 0 && out == i.principal as u128,
            "CREDIT conservation"
        ),
        1 => ensure!(input > 0 && input == spent, "TRANSFER conservation"),
        2 => ensure!(input == spent, "EXIT conservation"),
        _ => unreachable!(),
    }
    if i.mode == 1 {
        ensure!(
            i.kind == 2 && w.new.iter().all(|n| n.value == 0),
            "exit_only requires zero outputs"
        )
    }
    if let Some(sig) = kpi_recovery_auth_vectors::parse_authorization(i.kind, &w.auth)? {
        let d = i.deposit.as_ref().context("credit deposit")?;
        let message = kpi_recovery_auth_vectors::credit_message(
            &i.ids[0].as_slice().try_into()?,
            &hash(&i.encode()?),
        );
        kpi_recovery_auth_vectors::verify_profile(&d.key, &message, &sig)?;
    }
    i.journal(&w.auth)
}
// Tree hashing imported explicitly; no alternative commitment primitive.
use incrementalmerkletree::Hashable;
