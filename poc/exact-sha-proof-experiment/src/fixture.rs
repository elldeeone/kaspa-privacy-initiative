use crate::Result;
use payment::{
    self,
    circuit::{InputWitness, TransferCircuit},
};
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    real: bool,
    note_hex168: String,
    s_hex32: String,
    k_hex32: String,
    position: u32,
    cm_path_hex: [String; 16],
    dummy_key_hex32: String,
    dummy_seed_hex32: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    note_hex168: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    classification: String,
    auth_hex484: String,
    inputs: [Input; 2],
    outputs: [Output; 2],
}

fn fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s)?;
    if hex::encode(&bytes) != s {
        return Err("noncanonical hex".into());
    }
    bytes.try_into().map_err(|_| "fixed width".into())
}

// Same deny_unknown_fields and exact widths as the frozen baseline schema.
// There is no S7, old PK, native VM, wallet or network dependency here.
pub fn circuit_from_bytes(bytes: &[u8]) -> Result<TransferCircuit> {
    let fixture: Fixture = serde_json::from_slice(bytes)?;
    if fixture.classification != "PUBLIC_SYNTHETIC_DO_NOT_FUND" {
        return Err("public synthetic identity required".into());
    }
    let mut inputs = Vec::new();
    for i in fixture.inputs {
        let mut path = [[0; 32]; 16];
        for (to, from) in path.iter_mut().zip(&i.cm_path_hex) {
            *to = fixed(from)?;
        }
        inputs.push(InputWitness {
            real: i.real,
            note: payment::Note::parse(&fixed::<168>(&i.note_hex168)?)?,
            owner_secret: fixed(&i.s_hex32)?,
            nullifier_secret: fixed(&i.k_hex32)?,
            position: i.position,
            path,
            dummy_key: fixed(&i.dummy_key_hex32)?,
            dummy_seed: fixed(&i.dummy_seed_hex32)?,
        });
    }
    Ok(TransferCircuit {
        authorization: payment::Authorization::parse(&fixed::<484>(&fixture.auth_hex484)?)?,
        inputs: inputs.try_into().map_err(|_| "input count")?,
        outputs: [
            payment::Note::parse(&fixed::<168>(&fixture.outputs[0].note_hex168)?)?,
            payment::Note::parse(&fixed::<168>(&fixture.outputs[1].note_hex168)?)?,
        ],
    })
}
