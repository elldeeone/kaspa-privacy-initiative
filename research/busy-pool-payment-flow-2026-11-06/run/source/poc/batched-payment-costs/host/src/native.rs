//! Current native bank adapter. Mutable state prefix, immutable verifier suffix.
use crate::receipt_script;
use kaspa_consensus::processes::transaction_validator::{
    TransactionValidator, tx_validation_in_utxo_context::TxValidationFlags,
};
use kaspa_consensus_core::{config::params::TESTNET_PARAMS, mass::MassCalculator, tx::*};
use kaspa_hashes::Hash;
use kaspa_txscript::{
    opcodes::codes::*, pay_to_script_hash_script, pay_to_script_hash_signature_script_with_flags,
    script_builder::ScriptBuilder,
};
use kpi_batched_payment_core::{DOMAIN, Effects, H, NativeOutput};
use serde_json::{Value, json};
use std::sync::Arc;

pub const BUDGET: u16 = 1600;
pub fn encoded(spk: &ScriptPublicKey) -> Vec<u8> {
    [spk.version().to_be_bytes().as_slice(), spk.script()].concat()
}
pub fn spk(raw: &[u8]) -> ScriptPublicKey {
    ScriptPublicKey::new(
        u16::from_be_bytes(raw[..2].try_into().unwrap()),
        raw[2..].to_vec().into(),
    )
}
fn op(b: &mut ScriptBuilder, x: u8) {
    b.add_op(x).unwrap();
}
fn data(b: &mut ScriptBuilder, x: &[u8]) {
    b.add_data(x).unwrap();
}
fn num(b: &mut ScriptBuilder, x: i64) {
    b.add_i64(x).unwrap();
}
fn number(b: &mut ScriptBuilder, opcode: u8, n: i64) {
    op(b, opcode);
    num(b, n);
    op(b, OpEqualVerify);
}

pub struct Policy {
    pub image: H,
}
impl Policy {
    pub fn redeem(&self, root: H) -> Vec<u8> {
        let mut len = 0i64;
        for _ in 0..12 {
            let bytes = self.build(root, len);
            if bytes.len() as i64 == len {
                return bytes;
            }
            len = bytes.len() as i64;
        }
        panic!("redeem length did not converge")
    }
    pub fn spk(&self, root: H) -> ScriptPublicKey {
        pay_to_script_hash_script(&self.redeem(root))
    }
    fn build(&self, root: H, len: i64) -> Vec<u8> {
        let mut b = ScriptBuilder::new();
        data(&mut b, &root);
        // Witness: proof,new_root. Redeem starts by pushing current root.
        number(&mut b, OpTxVersion, 1);
        number(&mut b, OpTxInputCount, 1);
        number(&mut b, OpTxInputIndex, 0);
        number(&mut b, OpTxLockTime, 0);
        number(&mut b, OpTxGas, 0);
        op(&mut b, OpTxSubnetId);
        data(&mut b, &[0; 20]);
        op(&mut b, OpEqualVerify);
        num(&mut b, 0);
        op(&mut b, OpTxInputSeq);
        data(&mut b, &[0; 8]);
        op(&mut b, OpEqualVerify);
        op(&mut b, OpTxOutputCount);
        num(&mut b, 8);
        op(&mut b, OpLessThanOrEqual);
        op(&mut b, OpVerify);
        // Save new root; journal starts with old_root || new_root.
        op(&mut b, OpOver);
        op(&mut b, OpToAltStack);
        op(&mut b, OpSwap);
        op(&mut b, OpCat);
        op(&mut b, OpDup);
        num(&mut b, 0);
        num(&mut b, 32);
        op(&mut b, OpSubstr);
        data(&mut b, DOMAIN);
        op(&mut b, OpSwap);
        op(&mut b, OpCat);
        num(&mut b, 0);
        op(&mut b, OpOutpointTxId);
        op(&mut b, OpCat);
        num(&mut b, 0);
        op(&mut b, OpOutpointIndex);
        num(&mut b, 8);
        op(&mut b, OpNum2Bin);
        op(&mut b, OpCat);
        num(&mut b, 0);
        op(&mut b, OpTxInputAmount);
        num(&mut b, 8);
        op(&mut b, OpNum2Bin);
        op(&mut b, OpCat);
        op(&mut b, OpTxOutputCount);
        num(&mut b, 8);
        op(&mut b, OpNum2Bin);
        op(&mut b, OpCat);
        for i in 0..8 {
            op(&mut b, OpTxOutputCount);
            num(&mut b, i);
            op(&mut b, OpGreaterThan);
            op(&mut b, OpIf);
            num(&mut b, i);
            number(&mut b, OpOutputAuthorizingInput, -1);
            num(&mut b, i);
            op(&mut b, OpTxOutputAmount);
            num(&mut b, 8);
            op(&mut b, OpNum2Bin);
            op(&mut b, OpCat);
            num(&mut b, i);
            op(&mut b, OpTxOutputSpk);
            op(&mut b, OpSize);
            num(&mut b, 8);
            op(&mut b, OpNum2Bin);
            op(&mut b, OpSwap);
            op(&mut b, OpToAltStack);
            op(&mut b, OpCat);
            op(&mut b, OpFromAltStack);
            op(&mut b, OpCat);
            op(&mut b, OpEndIf);
        }
        op(&mut b, OpSHA256);
        op(&mut b, OpCat);
        num(&mut b, 0);
        op(&mut b, OpTxPayloadLen);
        op(&mut b, OpTxPayloadSubstr);
        op(&mut b, OpSHA256);
        op(&mut b, OpCat);
        op(&mut b, OpSHA256);
        // A zero new-root means the guest proved complete principal drainage.
        op(&mut b, OpFromAltStack);
        op(&mut b, OpDup);
        data(&mut b, &[0; 32]);
        op(&mut b, OpEqual);
        op(&mut b, OpIf);
        op(&mut b, OpDrop);
        op(&mut b, OpElse);
        data(&mut b, &[OpData32]);
        op(&mut b, OpSwap);
        op(&mut b, OpCat);
        // Existing covenant suffix extraction, with our 33-byte root prefix.
        op(&mut b, OpTxInputIndex);
        op(&mut b, OpTxInputIndex);
        op(&mut b, OpTxInputScriptSigLen);
        num(&mut b, -len + 33);
        op(&mut b, OpAdd);
        op(&mut b, OpTxInputIndex);
        op(&mut b, OpTxInputScriptSigLen);
        op(&mut b, OpTxInputScriptSigSubstr);
        op(&mut b, OpCat);
        op(&mut b, OpBlake2b);
        data(&mut b, &[0, 0, OpBlake2b, OpData32]);
        op(&mut b, OpSwap);
        op(&mut b, OpCat);
        data(&mut b, &[OpEqual]);
        op(&mut b, OpCat);
        num(&mut b, 0);
        op(&mut b, OpTxOutputSpk);
        op(&mut b, OpEqualVerify);
        op(&mut b, OpEndIf);
        receipt_script::verify_risc0_groth16(&mut b, &self.image);
        op(&mut b, OpTrue);
        b.drain()
    }
    pub fn witness(&self, root: H, new: H, proof: &[u8]) -> Vec<u8> {
        let mut b = ScriptBuilder::new();
        data(&mut b, proof);
        data(&mut b, &new);
        pay_to_script_hash_signature_script_with_flags(
            self.redeem(root),
            b.drain(),
            Default::default(),
        )
        .unwrap()
    }
}
pub fn effects(tx: &Transaction, value: u64) -> Effects {
    Effects {
        previous: tx.inputs[0].previous_outpoint.transaction_id.as_bytes(),
        index: tx.inputs[0].previous_outpoint.index,
        input_value: value,
        outputs: tx
            .outputs
            .iter()
            .map(|o| NativeOutput {
                value: o.value,
                spk: encoded(&o.script_public_key),
            })
            .collect(),
    }
}
pub fn transaction(
    previous: TransactionOutpoint,
    outputs: Vec<TransactionOutput>,
    payload: Vec<u8>,
    budget: u16,
) -> Transaction {
    Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            previous,
            vec![],
            0,
            budget,
        )],
        outputs,
        0,
        Default::default(),
        0,
        payload,
    )
}
pub fn quote(tx: &Transaction, entry: &UtxoEntry) -> Value {
    let pop = PopulatedTransaction::new(tx, vec![entry.clone()]);
    let calc = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let n = calc.calc_non_contextual_masses(tx);
    let c = calc.calc_contextual_masses(&pop).unwrap();
    let limit = TESTNET_PARAMS.block_mass_limits;
    let fee_mass = n
        .compute_mass
        .max(n.normalized_transient(&limit.cofactors()));
    json!({"computeMass":n.compute_mass,"transientMass":n.transient_mass,"storageMass":c.storage_mass,"feeMass":fee_mass,"minimumDefaultRelayFeeSompi":fee_mass*100,"fitsBlock":n.compute_mass<=limit.compute&&n.transient_mass<=limit.transient&&c.storage_mass<=limit.storage,"serializedBytes":bincode::serialize(tx).unwrap().len()})
}
pub fn validate(tx: &Transaction, entry: &UtxoEntry) -> Result<Value, String> {
    let p = TESTNET_PARAMS;
    let calc = MassCalculator::new_with_consensus_params(&p);
    let pop = PopulatedTransaction::new(tx, vec![entry.clone()]);
    let contextual = calc
        .calc_contextual_masses(&pop)
        .ok_or("undefined contextual mass")?;
    tx.set_storage_mass(contextual.storage_mass);
    let validator = TransactionValidator::new(
        p.max_tx_inputs,
        p.max_tx_outputs,
        p.max_signature_script_len,
        p.max_script_public_key_len,
        p.coinbase_payload_script_public_key_max_len,
        p.coinbase_maturity(),
        p.ghostdag_k(),
        Arc::new(kaspa_txscript::caches::TxScriptCacheCounters::default()),
        calc,
        p.mass_per_sig_op,
    );
    validator
        .validate_tx_in_isolation(tx)
        .map_err(|e| format!("isolation:{e:?}"))?;
    let fee = validator
        .validate_populated_transaction_and_get_fee(
            &pop,
            1_000_000_000,
            1_000_000_000,
            TxValidationFlags::Full,
            None,
            None,
        )
        .map_err(|e| format!("full:{e:?}"))?;
    let mut q = quote(tx, entry);
    if !q["fitsBlock"].as_bool().unwrap() {
        return Err("block component mass".into());
    }
    if fee < q["minimumDefaultRelayFeeSompi"].as_u64().unwrap() {
        return Err("default relay fee".into());
    }
    use kaspa_txscript::{p2sh_sig_scanner, script_class::ScriptClass};
    if ScriptClass::from_script(&entry.script_public_key) == ScriptClass::ScriptHash
        && p2sh_sig_scanner(&tx.inputs[0].signature_script, &entry.script_public_key) > 15
    {
        return Err("P2SH standard sigops".into());
    }
    for o in &tx.outputs {
        if o.script_public_key.version() != 0
            || ScriptClass::from_script(&o.script_public_key) == ScriptClass::NonStandard
        {
            return Err("nonstandard output".into());
        }
    }
    q["feeSompi"] = json!(fee);
    q["nativeFullValidation"] = json!(true);
    q["offlineDefaultRelayChecks"] = json!(true);
    Ok(q)
}
pub fn fake_point(seed: H) -> TransactionOutpoint {
    TransactionOutpoint::new(Hash::from_bytes(seed), 0)
}
