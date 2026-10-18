//! Primitive/API compatibility only. No wallet authorization or native IO.
#![no_main]
use orchard::{
    keys::{Diversifier, FullViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    value::NoteValue,
    Note,
};
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);

fn main() {
    // Runtime input prevents compile-time constant folding of the public
    // fixture. Keys here are published test-vector keys; never fund them.
    let mut input = [0u8; 115];
    env::read_slice(&mut input);
    let sk = SpendingKey::from_bytes(input[..32].try_into().unwrap()).unwrap();
    let value = u64::from_le_bytes(input[32..40].try_into().unwrap());
    let rho = Rho::from_bytes(input[40..72].try_into().unwrap()).unwrap();
    let seed = RandomSeed::from_bytes(input[72..104].try_into().unwrap(), &rho).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address(
        Diversifier::from_bytes(input[104..115].try_into().unwrap()),
        Scope::External,
    );
    let note = Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        rho,
        seed,
        NoteVersion::V2,
    )
    .unwrap();
    let cmx = ExtractedNoteCommitment::from(note.commitment());
    let nf = note.nullifier(&fvk);
    env::commit_slice(b"KPI/P1/OrchardV2/primitive-check/v1");
    env::commit_slice(&cmx.to_bytes());
    env::commit_slice(&nf.to_bytes());
}
