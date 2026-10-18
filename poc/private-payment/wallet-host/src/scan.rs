//! Full local Orchard V2 scanning in both scopes, followed by current spentness.
//! Private module: history::restore first pins complete history and replays every
//! receipt/full public operation. An unauthenticated iterator is not authority.
use crate::state::State;
use anyhow::{ensure, Context, Result};
use kpi_wallet_core::{
    orchard::{
        keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey},
        note::{ExtractedNoteCommitment, Nullifier},
        note_encryption::{CompactAction, NoteBytesData, OrchardDomain},
    },
    zcash_note_encryption::{try_note_decryption, EphemeralKeyBytes, ShieldedOutput},
    *,
};
struct Output {
    cmx: ExtractedNoteCommitment,
    epk: [u8; 32],
    ciphertext: NoteBytesData<580>,
}
impl ShieldedOutput<OrchardDomain> for Output {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.epk)
    }
    fn cmstar(&self) -> &ExtractedNoteCommitment {
        &self.cmx
    }
    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx.to_bytes()
    }
    fn enc_ciphertext(&self) -> Option<&NoteBytesData<580>> {
        Some(&self.ciphertext)
    }
    fn enc_ciphertext_compact(&self) -> NoteBytesData<52> {
        NoteBytesData(self.ciphertext.0[..52].try_into().unwrap())
    }
}
pub fn scan(keys: &[[u8; 32]], history: &[Intent], state: &State) -> Result<Vec<OldNote>> {
    let mut owned = Vec::new();
    let mut position = 0u64;
    for i in history {
        ensure!(i.ids == state.ids, "scan context");
        for slot in 0..2 {
            if i.mode == 1 {
                continue;
            }
            let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
                &i.cmx[slot],
            ))
            .context("scan cmx")?;
            let nf =
                Option::<Nullifier>::from(Nullifier::from_bytes(&i.nf[slot])).context("scan nf")?;
            let compact = CompactAction::from_parts(
                nf,
                cmx,
                EphemeralKeyBytes(i.epk[slot]),
                i.ciphertext[slot][..52].try_into()?,
            );
            let domain = OrchardDomain::for_compact_action(&compact);
            let output = Output {
                cmx,
                epk: i.epk[slot],
                ciphertext: NoteBytesData(i.ciphertext[slot]),
            };
            for sk in keys {
                let sk_checked = Option::<SpendingKey>::from(SpendingKey::from_bytes(*sk))
                    .context("backup spending key")?;
                let fvk = FullViewingKey::from(&sk_checked);
                for (scope_id, scope) in [(0, Scope::External), (1, Scope::Internal)] {
                    let prepared = PreparedIncomingViewingKey::new(&fvk.to_ivk(scope));
                    if let Some((note, recipient, _memo)) =
                        try_note_decryption(&domain, &prepared, &output)
                    {
                        ensure!(
                            note.recipient() == recipient
                                && fvk.scope_for_address(&recipient) == Some(scope),
                            "received hierarchy/scope"
                        );
                        ensure!(
                            note.version() == orchard::note::NoteVersion::V2,
                            "unsupported received note"
                        );
                        if note.value().inner() > 0
                            && !state.spent.contains(&note.nullifier(&fvk).to_bytes())
                        {
                            ensure!(
                                state.tree.leaves.get(position as usize) == Some(&i.cmx[slot]),
                                "canonical position"
                            );
                            let (root, path) =
                                state.tree.root_path(Some(u32::try_from(position)?))?;
                            ensure!(state.allowed.contains(&root), "current root missing");
                            owned.push(OldNote {
                                sk: *sk,
                                scope: scope_id,
                                diversifier: recipient.to_raw_address_bytes()[..11].try_into()?,
                                value: note.value().inner(),
                                rho: note.rho().to_bytes(),
                                seed: *note.rseed().as_bytes(),
                                path: Some((u32::try_from(position)?, path)),
                            });
                        }
                    }
                }
            }
            position = position.checked_add(1).context("scan position overflow")?;
        }
    }
    ensure!(
        position as usize == state.tree.leaves.len(),
        "incomplete scan history"
    );
    Ok(owned)
}
