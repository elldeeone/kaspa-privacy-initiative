//! Finite public-claim subset covenants. Only native VM execution is claimed.
use crate::proof::{self, Authorization, H};
use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    hashing::sighash::SigHashReusedValuesUnsync,
    mass::MassCalculator,
    tx::{
        PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_hashes::Hash;
use kaspa_txscript::{
    EngineFlags, TxScriptEngine, caches::Cache, covenants::CovenantsContext,
    engine_context::EngineContext, opcodes::codes::*, pay_to_script_hash_script,
    pay_to_script_hash_signature_script_with_flags, script_builder::ScriptBuilder,
};

pub const PRINCIPAL: u64 = 1_000_000_000;
pub const FEE: u64 = 20_000_000;
// Three Groth16 checks cost 47.25M units before small script overhead under the
// pinned schedule. 4,800 budget units give 48M without exceeding block mass.
pub const BUDGET: u16 = 4_800;
pub const ALL: u8 = 7;
pub fn active(mask: u8) -> Vec<usize> {
    (0..3).filter(|i| mask & (1 << i) != 0).collect()
}
pub fn reserve(mask: u8) -> u64 {
    active(mask).len() as u64 * (PRINCIPAL + FEE)
}
pub fn encoded(spk: &ScriptPublicKey) -> Vec<u8> {
    [spk.version().to_be_bytes().as_slice(), spk.script()].concat()
}
fn op(b: &mut ScriptBuilder, code: u8) {
    b.add_op(code).unwrap();
}
fn num(b: &mut ScriptBuilder, n: i64) {
    b.add_i64(n).unwrap();
}
fn data(b: &mut ScriptBuilder, v: &[u8]) {
    b.add_data(v).unwrap();
}
fn equal_number(b: &mut ScriptBuilder, code: u8, n: i64) {
    op(b, code);
    num(b, n);
    op(b, OpEqualVerify);
}
fn output_amount(b: &mut ScriptBuilder, i: usize, n: u64) {
    num(b, i as i64);
    equal_number(b, OpTxOutputAmount, n as i64);
}
fn p2pk(b: &mut ScriptBuilder, i: usize) {
    num(b, i as i64);
    equal_number(b, OpOutputAuthorizingInput, -1);
    num(b, i as i64);
    op(b, OpTxOutputSpk);
    op(b, OpSize);
    num(b, 36);
    op(b, OpEqualVerify);
    op(b, OpDup);
    num(b, 0);
    num(b, 3);
    op(b, OpSubstr);
    data(b, &[0, 0, 32]);
    op(b, OpEqualVerify);
    num(b, 35);
    num(b, 36);
    op(b, OpSubstr);
    data(b, &[OpCheckSig]);
    op(b, OpEqualVerify);
}
pub struct Policy {
    pub claims: [H; 3],
    pub scripts: Vec<Vec<u8>>,
    pub domain: H,
}
impl Policy {
    pub fn new(claims: [H; 3], vk: &[u8]) -> Self {
        assert_eq!(
            claims
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
        let mut bytes = b"KPI-finite-common-set-current-L1-v1\0".to_vec();
        bytes.extend(TESTNET_PARAMS.genesis.hash.as_bytes());
        for c in claims {
            bytes.extend(c);
        }
        let mut p = Self {
            claims,
            scripts: vec![vec![]; 8],
            domain: proof::hash(&bytes),
        };
        for mask in 1..=ALL {
            p.scripts[mask as usize] = p.build(mask, vk);
        }
        p
    }
    pub fn prefix(&self, mask: u8, solo: Option<usize>) -> Vec<u8> {
        let mut b = b"KPI-common-set-effects-v1\0".to_vec();
        b.extend(self.domain);
        b.push(mask);
        b.push(solo.map(|i| i as u8).unwrap_or(255));
        b.extend(PRINCIPAL.to_le_bytes());
        b.extend(FEE.to_le_bytes());
        b
    }
    pub fn spk(&self, mask: u8) -> ScriptPublicKey {
        pay_to_script_hash_script(&self.scripts[mask as usize])
    }
    fn context_script(&self, b: &mut ScriptBuilder, mask: u8, solo: Option<usize>) {
        data(b, &self.prefix(mask, solo));
        num(b, 0);
        op(b, OpOutpointTxId);
        op(b, OpCat);
        num(b, 0);
        op(b, OpOutpointIndex);
        num(b, 8);
        op(b, OpNum2Bin);
        op(b, OpCat);
        let count = if solo.is_some() {
            if active(mask).len() > 1 { 2 } else { 1 }
        } else {
            active(mask).len()
        };
        for i in 0..count {
            num(b, i as i64);
            op(b, OpTxOutputAmount);
            num(b, 8);
            op(b, OpNum2Bin);
            op(b, OpCat);
            let len = if solo.is_some() && i == 1 {
                37u64
            } else {
                36u64
            };
            data(b, &len.to_le_bytes());
            op(b, OpCat);
            num(b, i as i64);
            op(b, OpTxOutputSpk);
            op(b, OpCat);
        }
        op(b, OpSHA256);
    }
    fn verify(
        &self,
        b: &mut ScriptBuilder,
        mask: u8,
        solo: Option<usize>,
        claim: usize,
        vk: &[u8],
    ) {
        // Witness is auth_hi,auth_lo,proof. Reconstruct actual effects for each
        // proof, so no host digest or per-owner destination enters this ABI.
        op(b, OpToAltStack);
        self.context_script(b, mask, solo);
        op(b, OpDup);
        num(b, 16);
        num(b, 32);
        op(b, OpSubstr);
        data(b, &[0; 16]);
        op(b, OpCat);
        op(b, OpSwap);
        num(b, 0);
        num(b, 16);
        op(b, OpSubstr);
        data(b, &[0; 16]);
        op(b, OpCat);
        for half in self.claims[claim].chunks(16).rev() {
            let mut field = half.to_vec();
            field.extend([0; 16]);
            data(b, &field);
        }
        num(b, 6);
        op(b, OpFromAltStack);
        data(b, vk);
        data(b, &[0x20]);
        op(b, OpZkPrecompile);
        op(b, OpVerify);
    }
    fn solo_branches(&self, b: &mut ScriptBuilder, mask: u8, owners: &[usize], vk: &[u8]) {
        if owners.is_empty() {
            op(b, OpReturn);
            return;
        }
        let who = owners[0];
        op(b, OpDup);
        num(b, who as i64);
        op(b, OpEqual);
        op(b, OpIf);
        op(b, OpDrop);
        let next = mask & !(1 << who);
        let count = if next == 0 { 1 } else { 2 };
        equal_number(b, OpTxOutputCount, count);
        output_amount(b, 0, PRINCIPAL);
        p2pk(b, 0);
        if next != 0 {
            output_amount(b, 1, reserve(next));
            num(b, 1);
            equal_number(b, OpOutputAuthorizingInput, -1);
            num(b, 1);
            op(b, OpTxOutputSpk);
            data(b, &encoded(&self.spk(next)));
            op(b, OpEqualVerify);
        }
        self.verify(b, mask, Some(who), who, vk);
        op(b, OpElse);
        self.solo_branches(b, mask, &owners[1..], vk);
        op(b, OpEndIf);
    }
    fn build(&self, mask: u8, vk: &[u8]) -> Vec<u8> {
        let mut b = ScriptBuilder::new();
        equal_number(&mut b, OpTxVersion, 1);
        equal_number(&mut b, OpTxInputCount, 1);
        equal_number(&mut b, OpTxLockTime, 0);
        equal_number(&mut b, OpTxGas, 0);
        equal_number(&mut b, OpTxPayloadLen, 0);
        op(&mut b, OpTxSubnetId);
        data(&mut b, &[0; 20]);
        op(&mut b, OpEqualVerify);
        // Sequence introspection returns raw LE64 flags, not a minimally
        // encoded script integer. Compare the exact eight bytes.
        num(&mut b, 0);
        op(&mut b, OpTxInputSeq);
        data(&mut b, &0u64.to_le_bytes());
        op(&mut b, OpEqualVerify);
        num(&mut b, 0);
        equal_number(&mut b, OpTxInputAmount, reserve(mask) as i64);
        let owners = active(mask);
        op(&mut b, OpIf);
        equal_number(&mut b, OpTxOutputCount, owners.len() as i64);
        for i in 0..owners.len() {
            output_amount(&mut b, i, PRINCIPAL);
            p2pk(&mut b, i);
        }
        for i in 0..owners.len() {
            for j in i + 1..owners.len() {
                num(&mut b, i as i64);
                op(&mut b, OpTxOutputSpk);
                num(&mut b, j as i64);
                op(&mut b, OpTxOutputSpk);
                op(&mut b, OpEqual);
                num(&mut b, 0);
                op(&mut b, OpEqualVerify);
            }
        }
        for who in &owners {
            self.verify(&mut b, mask, None, *who, vk);
        }
        op(&mut b, OpElse);
        self.solo_branches(&mut b, mask, &owners, vk);
        op(&mut b, OpEndIf);
        op(&mut b, OpTrue);
        b.drain()
    }
    pub fn context(&self, mask: u8, solo: Option<usize>, tx: &Transaction) -> H {
        let mut b = self.prefix(mask, solo);
        let out = &tx.inputs[0].previous_outpoint;
        b.extend(out.transaction_id.as_bytes());
        b.extend((out.index as u64).to_le_bytes());
        for o in &tx.outputs {
            let spk = encoded(&o.script_public_key);
            b.extend(o.value.to_le_bytes());
            b.extend((spk.len() as u64).to_le_bytes());
            b.extend(spk);
        }
        proof::hash(&b)
    }
    pub fn transaction(
        &self,
        mask: u8,
        solo: Option<usize>,
        previous: TransactionOutpoint,
        keys: &[ScriptPublicKey],
    ) -> Transaction {
        let mut outputs = keys
            .iter()
            .map(|k| TransactionOutput::new(PRINCIPAL, k.clone()))
            .collect::<Vec<_>>();
        if let Some(who) = solo {
            let next = mask & !(1 << who);
            if next != 0 {
                outputs.push(TransactionOutput::new(reserve(next), self.spk(next)));
            }
        }
        Transaction::new(
            1,
            vec![TransactionInput::new_with_compute_budget(
                previous,
                vec![],
                0,
                BUDGET,
            )],
            outputs,
            0,
            Default::default(),
            0,
            vec![],
        )
    }
    pub fn witness(&self, mask: u8, solo: Option<usize>, auths: &[Authorization]) -> Vec<u8> {
        let mut b = ScriptBuilder::new();
        for a in auths.iter().rev() {
            for chunk in a.auth.chunks(16).rev() {
                let mut f = chunk.to_vec();
                f.extend([0; 16]);
                data(&mut b, &f);
            }
            data(&mut b, &proof::serialize(&a.proof));
        }
        if let Some(who) = solo {
            num(&mut b, who as i64);
            num(&mut b, 0);
        } else {
            num(&mut b, 1);
        }
        pay_to_script_hash_signature_script_with_flags(
            self.scripts[mask as usize].clone(),
            b.drain(),
            Default::default(),
        )
        .unwrap()
    }
}
pub fn execute(policy: &Policy, mask: u8, tx: &Transaction) -> Result<u64, String> {
    let entry = UtxoEntry::new(reserve(mask), policy.spk(mask), 0, false, None);
    let pop = PopulatedTransaction::new(tx, vec![entry; tx.inputs.len()]);
    let ctx = CovenantsContext::from_tx(&pop).map_err(|e| format!("context:{e:?}"))?;
    let cache = Cache::new(100);
    let reused = SigHashReusedValuesUnsync::new();
    let ec = EngineContext::new(&cache)
        .with_reused(&reused)
        .with_covenants_ctx(&ctx);
    let mut trace = Vec::new();
    let mut vm = TxScriptEngine::from_transaction_input(
        &pop,
        &tx.inputs[0],
        0,
        &pop.entries[0],
        ec,
        EngineFlags::default(),
    )
    .with_opcode_execution_log_buffer(&mut trace);
    if let Err(error) = vm.execute() {
        drop(vm);
        let text = String::from_utf8_lossy(&trace);
        let recent = text
            .lines()
            .rev()
            .take(12)
            .map(|l| l.split(", astack:").next().unwrap_or(l))
            .collect::<Vec<_>>();
        return Err(format!(
            "script:{error:?}; recent reverse opcodes:{recent:?}"
        ));
    }
    Ok(vm.used_script_units().0)
}
pub fn mass(policy: &Policy, mask: u8, tx: &Transaction) -> serde_json::Value {
    let entry = UtxoEntry::new(reserve(mask), policy.spk(mask), 0, false, None);
    let pop = PopulatedTransaction::new(tx, vec![entry]);
    let calculator = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let fixed = calculator.calc_non_contextual_masses(tx);
    match calculator.calc_contextual_masses(&pop) {
        Some(m) => {
            let limits = TESTNET_PARAMS.block_mass_limits;
            serde_json::json!({"computeMass":fixed.compute_mass,"transientMass":fixed.transient_mass,"storageMass":m.storage_mass,"blockComputeLimit":limits.compute,"blockTransientLimit":limits.transient,"blockStorageLimit":limits.storage,"withinBlockComponentLimits":fixed.compute_mass<=limits.compute && fixed.transient_mass<=limits.transient && m.storage_mass<=limits.storage})
        }
        None => serde_json::Value::Null,
    }
}
pub fn fake_outpoint(seed: H) -> TransactionOutpoint {
    TransactionOutpoint::new(Hash::from_bytes(seed), 0)
}
