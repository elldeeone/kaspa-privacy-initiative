//! Independent native deposits in a separate immutable v5 pool. The private
//! relation and v4 wire/code remain unchanged; only native admission is new.
use super::*;
pub mod covenant;
pub mod harness;
#[cfg(test)]
mod tests;

pub const CONTRIBUTION: u64 = 1_000_000_000;
pub fn state_bytes(s: &State) -> Vec<u8> {
    let mut b = s.bytes();
    b[0] = 5;
    b
}
pub fn parse_state(b: &[u8]) -> Result<State> {
    if b.len() != STATE_LEN || b[0] != 5 {
        return Err("v5 state framing".into());
    }
    let mut old = b.to_vec();
    old[0] = 4;
    State::parse(&old)
}
pub fn is_deposit(payload: &[u8]) -> bool {
    payload.starts_with(b"KPICD01\0")
}
pub fn parse(payload: &[u8]) -> Result<(bool, Authorization, State)> {
    if payload.len() != PAYLOAD_SIZE || (!is_deposit(payload) && !payload.starts_with(b"KPICR01\0"))
    {
        return Err("v5 payload framing".into());
    }
    let a = Authorization::parse(&payload[P_AUTH..P_CIPHER])?;
    if hash(&payload[P_CIPHER..P_STATE]) != a.cipher_hash
        || (a.mode == 2 && payload[P_CIPHER..P_STATE] != [0; 370])
    {
        return Err("v5 ciphertext binding".into());
    }
    Ok((
        is_deposit(payload),
        a,
        parse_state(&payload[P_STATE..P_WITNESS])?,
    ))
}
pub fn admission(old: &PublicState, a: &Authorization) -> Result<(PublicState, Vec<u8>)> {
    let s = old.compact()?;
    if s.nf_count == 0
        || s.nf_count >= s.cm_count
        || s.cm_count < 3
        || a.mode != 1
        || a.count != 1
        || a.bootstrap < 2 * NOTE_FLOOR
        || a.bootstrap > MAX_SOMPI
        || a.fee == 0
        || a.payout != 0
        || a.spk != [0; 36]
        || a.bootstrap
            .checked_sub(a.fee)
            .is_none_or(|v| v < 2 * NOTE_FLOOR)
        || a.outputs.contains(&[0; 32])
        || a.outputs[0] == a.outputs[1]
    {
        return Err("deposit shape/value/bootstrap".into());
    }
    let mut next = old.clone();
    let mut w = vec![0; W_LEN];
    let put = |w: &mut Vec<u8>, offset: usize, p: tree::Path| {
        for (i, h) in p.iter().enumerate() {
            w[offset + i * 32..offset + (i + 1) * 32].copy_from_slice(h)
        }
    };
    for (i, cm) in a.outputs.iter().enumerate() {
        put(
            &mut w,
            W_CM_APPEND + i * PATH_LEN,
            next.cm_tree()?.path(next.commitments.len().try_into()?)?,
        );
        next.commitments.push(*cm);
    }
    put(
        &mut w,
        W_HISTORY_APPEND,
        old.history_tree()?.path(old.roots.len().try_into()?)?,
    );
    next.roots.push(next.cm_tree()?.root());
    next.compact()?;
    Ok((next, w))
}
pub fn update(
    old: &PublicState,
    a: &Authorization,
    deposit: bool,
) -> Result<(PublicState, Vec<u8>)> {
    if deposit {
        admission(old, a)
    } else {
        old.witness(a)
    }
}
pub fn payload(bundle: &Bundle, next: &State, w: &[u8], deposit: bool) -> Result<Vec<u8>> {
    if w.len() != W_LEN {
        return Err("v5 witness size".into());
    }
    let a = bundle.auth()?;
    let c = bundle.ciphertext_bytes()?;
    if hash(&c) != a.cipher_hash {
        return Err("ciphertext digest".into());
    }
    Ok([
        if deposit {
            b"KPICD01\0".as_slice()
        } else {
            b"KPICR01\0".as_slice()
        },
        &a.bytes(),
        &c,
        &state_bytes(next),
        w,
    ]
    .concat())
}
pub fn reserve_spk(
    domain: &H,
    state: &PublicState,
    vk: &[u8],
) -> Result<kaspa_consensus_core::tx::ScriptPublicKey> {
    Ok(pay_to_script_hash_script(&covenant::redeem(
        domain,
        &state.compact()?,
        vk,
    )?))
}
pub fn settle(
    domain: &H,
    old: &PublicState,
    input: &native::Utxo,
    vk: &[u8],
    bundle: &Bundle,
    external: Option<&native::Utxo>,
) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let a = bundle.auth()?;
    let deposit = external.is_some();
    if a.domain != *domain
        || input.spk != hex::encode(native::encode_spk(&reserve_spk(domain, old, vk)?))
    {
        return Err("v5 domain/current reserve".into());
    }
    let (next, w) = update(old, &a, deposit)?;
    let state = next.compact()?;
    let mut total = input.amount;
    if let Some(e) = external {
        let spk = native::decode_spk(&e.spk)?;
        if e.is_coinbase
            || a.bootstrap != e.amount
            || spk.version() != 0
            || spk.script().len() != 34
            || spk.script()[0] != 0x20
            || spk.script()[33] != 0xac
            || e.outpoint()? == input.outpoint()?
        {
            return Err("deposit input identity/amount/script".into());
        }
        total = total
            .checked_add(e.amount)
            .filter(|v| *v <= MAX_SOMPI)
            .ok_or("deposit input sum")?;
    }
    let remaining = total
        .checked_sub(a.payout)
        .and_then(|v| v.checked_sub(a.fee))
        .ok_or("v5 backing underflow")?;
    let terminal = state.cm_count == state.nf_count;
    let mut outputs = Vec::new();
    if !terminal {
        outputs.push(TransactionOutput::new(
            remaining,
            reserve_spk(domain, &next, vk)?,
        ));
    } else if remaining != 0 {
        return Err("v5 terminal backing".into());
    }
    if a.mode == 2 {
        outputs.push(TransactionOutput::new(
            a.payout,
            native::decode_spk(&hex::encode(a.spk))?,
        ));
    }
    let redeem = covenant::redeem(domain, &old.compact()?, vk)?;
    let mut inputs = vec![TransactionInput::new_with_compute_budget(
        input.outpoint()?,
        covenant::signature(&hex::decode(&bundle.proof)?, &redeem)?,
        u64::MAX,
        covenant::BUDGET,
    )];
    let mut entries = vec![input.entry()?];
    if let Some(e) = external {
        let mut placeholder = vec![0; 66];
        placeholder[0] = 65;
        placeholder[65] = 1;
        inputs.push(TransactionInput::new_with_compute_budget(
            e.outpoint()?,
            placeholder,
            u64::MAX,
            10,
        ));
        entries.push(e.entry()?);
    }
    let tx = Transaction::new(
        1,
        inputs,
        outputs,
        0,
        Default::default(),
        0,
        payload(bundle, &state, &w, deposit)?,
    );
    native::set_mass(&tx, &entries)?;
    Ok((tx, entries))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Fees {
    pub transfer: u64,
    pub deposit: u64,
    pub exit: u64,
}
pub fn fees() -> Result<Fees> {
    let d = [9; 32];
    let vk = [0; 328];
    let key = [7; 32];
    let ext = native::Utxo {
        txid: hex::encode([8; 32]),
        index: 0,
        amount: CONTRIBUTION,
        spk: hex::encode(native::encode_spk(&native::p2pk(&key)?)),
        daa: 0,
        is_coinbase: false,
    };
    let mut values = Vec::new();
    for kind in 0..4 {
        let mut old = PublicState::initial([1; 32])?;
        let make = |s: &PublicState| -> Result<Authorization> {
            Ok(Authorization {
                domain: d,
                count: s.commitments.len() as u32,
                anchor: s.cm_tree()?.root(),
                nullifier: [4; 32],
                outputs: [[5; 32], [6; 32]],
                mode: 1,
                payout: 0,
                fee: 1,
                spk: [0; 36],
                bootstrap: 0,
                cipher_hash: hash(&[0; 370]),
            })
        };
        if kind == 1 || kind == 2 {
            old = old.witness(&make(&old)?)?.0;
        }
        let mut a = make(&old)?;
        a.nullifier = [8; 32];
        if kind == 1 {
            a.count = 1;
            a.bootstrap = CONTRIBUTION;
        }
        if kind >= 2 {
            a.mode = 2;
            a.outputs = [[0; 32]; 2];
            a.payout = if kind == 3 {
                CONTRIBUTION - 1
            } else {
                100_000_000
            };
            a.spk = native::encode_spk(&native::p2pk(&key)?).try_into().unwrap();
        }
        let u = native::Utxo {
            txid: hex::encode([3; 32]),
            index: 0,
            amount: CONTRIBUTION,
            spk: hex::encode(native::encode_spk(&reserve_spk(&d, &old, &vk)?)),
            daa: 0,
            is_coinbase: false,
        };
        let b = Bundle {
            authorization: hex::encode(a.bytes()),
            proof: hex::encode([0; 128]),
            ciphertexts: [hex::encode([0; 185]), hex::encode([0; 185])],
        };
        let (tx, e) = settle(
            &d,
            &old,
            &u,
            &vk,
            &b,
            if kind == 1 { Some(&ext) } else { None },
        )?;
        values.push(
            native::metrics(&tx, &e)?["mining_mass"]
                .as_u64()
                .ok_or("v5 mass")?
                .checked_mul(100)
                .ok_or("fee overflow")?,
        );
    }
    let f = Fees {
        transfer: values[0],
        deposit: values[1],
        exit: values[2].max(values[3]),
    };
    if f.exit + PAYOUT_FLOOR > NOTE_FLOOR {
        return Err("unchanged note floor cannot fund v5 exit".into());
    }
    Ok(f)
}
