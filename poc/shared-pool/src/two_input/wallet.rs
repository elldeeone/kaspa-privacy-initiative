//! Local v6 wallet integration. No network, setup, or chain-acceptance oracle.
//!
//! Descriptor, parameter pins and expected head must be authenticated outside
//! this component. Public parent bytes do not establish current spendability.
//! Backups are private; prepared transactions and receive envelopes are public.
use super::*;
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use crypto_box::SecretKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};

pub const BACKUP_FORMAT: &str = "kpi-v6-wallet-backup-v1";
pub const RECEIVE_FORMAT: &str = "kpi-v6-receive-v1";
pub const KEY_DERIVATION: &str = "KPI/payout-key/v2";
pub const SCOPE: &str = "offline local wallet; accepted history, freshness and funding unspentness are external assumptions";

fn hash_text(s: &str) -> Result<()> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 || hex::encode(bytes) != s {
        return Err("noncanonical SHA-256/hash encoding".into());
    }
    Ok(())
}

fn amount(s: &str) -> Result<u64> {
    let value: u64 = s.parse()?;
    if value.to_string() != s || value > MAX_SOMPI {
        return Err("noncanonical sompi amount/range".into());
    }
    Ok(value)
}

/// Hash the typed descriptor's compact JSON, not a file's whitespace/key order.
pub fn descriptor_hash(descriptor: &replay::Descriptor) -> Result<String> {
    Ok(hex::encode(hash(&serde_json::to_vec(descriptor)?)))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterPin {
    pub sha256: String,
    pub bytes: u64,
}
impl ParameterPin {
    fn check(&self) -> Result<()> {
        hash_text(&self.sha256)?;
        if self.bytes == 0 {
            return Err("empty proving parameter pin".into());
        }
        Ok(())
    }
}

/// Supplied independently of the history file. Matching this does not prove
/// acceptance or freshness of the expected endpoint itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub transaction_count: usize,
    pub last_full_hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReceive {
    pub format: String,
    pub descriptor_sha256: String,
    pub receive: crate::protocol::Receive,
}
impl PublicReceive {
    fn check(&self, descriptor: &replay::Descriptor) -> Result<()> {
        if self.format != RECEIVE_FORMAT
            || self.descriptor_sha256 != descriptor_hash(descriptor)?
            || self.receive.owner == [0; 32]
            || self.receive.incoming == [0; 32]
        {
            return Err("recipient format/pool/identity mismatch".into());
        }
        Ok(())
    }
}

/// Contains keys, never a cache of later notes/witnesses or saved exit proofs.
/// The original note opening is required only for a founder restoring position 0.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    format: String,
    descriptor_sha256: String,
    parameters: ParameterPin,
    native_derivation: String,
    wallet: Wallet,
    initial_note: Option<Note>,
}
impl Backup {
    pub fn new(
        wallet: Wallet,
        descriptor: &replay::Descriptor,
        vk: &[u8],
        parameters: ParameterPin,
        initial_note: Option<Note>,
    ) -> Result<Self> {
        descriptor.validate(vk)?;
        let result = Self {
            format: BACKUP_FORMAT.into(),
            descriptor_sha256: descriptor_hash(descriptor)?,
            parameters,
            native_derivation: KEY_DERIVATION.into(),
            wallet,
            initial_note,
        };
        result.check(descriptor)?;
        Ok(result)
    }

    pub fn fresh(
        descriptor: &replay::Descriptor,
        vk: &[u8],
        parameters: ParameterPin,
    ) -> Result<Self> {
        Self::new(Wallet::fresh(), descriptor, vk, parameters, None)
    }

    fn check(&self, descriptor: &replay::Descriptor) -> Result<()> {
        self.parameters.check()?;
        if self.format != BACKUP_FORMAT
            || self.native_derivation != KEY_DERIVATION
            || self.descriptor_sha256 != descriptor_hash(descriptor)?
        {
            return Err("backup version/pool/derivation mismatch".into());
        }
        if let Some(note) = &self.initial_note {
            let receive = self.wallet.receive(&descriptor.domain);
            if note.owner != receive.owner
                || note.incoming != receive.incoming
                || note.commitment(&descriptor.domain) != descriptor.initial_commitment
                || note.value != amount(&descriptor.initial_value_sompi)?
                || !(NOTE_FLOOR..=MAX_SOMPI).contains(&note.value)
            {
                return Err("founder opening ownership/value/commitment mismatch".into());
            }
        }
        Ok(())
    }

    pub fn parameters(&self) -> &ParameterPin {
        &self.parameters
    }

    pub fn receive(&self, descriptor: &replay::Descriptor) -> Result<PublicReceive> {
        self.check(descriptor)?;
        Ok(PublicReceive {
            format: RECEIVE_FORMAT.into(),
            descriptor_sha256: self.descriptor_sha256.clone(),
            receive: self.wallet.receive(&descriptor.domain),
        })
    }

    pub fn native_key(&self, descriptor: &replay::Descriptor, index: u32) -> Result<H> {
        self.check(descriptor)?;
        Ok(self.wallet.payout_key(&descriptor.domain, index))
    }

    /// Local funding information is deliberately separate from PublicReceive.
    pub fn funding(&self, descriptor: &replay::Descriptor, index: u32) -> Result<Value> {
        let spk = native::p2pk(&self.native_key(descriptor, index)?)?;
        Ok(json!({
            "descriptor_sha256": self.descriptor_sha256,
            "native_derivation": KEY_DERIVATION,
            "native_key_index": index,
            "script_public_key": hex::encode(native::encode_spk(&spk)),
            "address": native::address(&spk)?,
        }))
    }

    /// Parent must already be a private directory. Exclusive creation also
    /// rejects an existing file or symlink; no old backup is overwritten.
    pub fn save_new(&self, path: &Path) -> Result<()> {
        let parent = path.parent().ok_or("backup directory required")?;
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("backup directory must be private (0700)".into());
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        serde_json::to_writer_pretty(&mut file, self)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }
}

/// Request amounts are canonical decimal sompi. No arbitrary payout script or
/// private input note can be injected through this interface.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Admit {
        txid: String,
        index: u32,
        native_key_index: u32,
    },
    Pay {
        positions: Vec<u32>,
        recipient: PublicReceive,
        amount_sompi: String,
    },
    Exit {
        positions: Vec<u32>,
        native_key_index: u32,
    },
}

struct Owned {
    note: Note,
    position: u32,
    spent: bool,
}

/// Private internals and no Deserialize prevent using a caller's state JSON as
/// authenticated membership or spentness. Construction always replays history.
pub struct Context {
    descriptor: replay::Descriptor,
    vk: Vec<u8>,
    replay: replay::Replay,
    parents: Vec<Value>,
    head: Head,
}
impl Context {
    pub fn new(
        descriptor: replay::Descriptor,
        vk: Vec<u8>,
        lineage: &[Value],
        parents: &[Value],
        expected: Head,
    ) -> Result<Self> {
        hash_text(&expected.last_full_hash)?;
        if expected.transaction_count != lineage.len() || lineage.is_empty() {
            return Err("expected head count mismatch".into());
        }
        let replay = replay::replay(&descriptor, &vk, lineage, parents)?;
        if replay.records.last().ok_or("empty replay")?.full_hash != expected.last_full_hash {
            return Err("expected head full hash mismatch".into());
        }
        Ok(Self {
            descriptor,
            vk,
            replay,
            parents: parents.to_vec(),
            head: expected,
        })
    }

    pub fn head(&self) -> &Head {
        &self.head
    }
    pub fn descriptor(&self) -> &replay::Descriptor {
        &self.descriptor
    }
    pub fn replay(&self) -> &replay::Replay {
        &self.replay
    }

    fn binding(&self) -> Result<H> {
        Ok(hash(&serde_json::to_vec(&(
            descriptor_hash(&self.descriptor)?,
            &self.head,
        ))?))
    }

    fn owned(&self, backup: &Backup) -> Result<Vec<Owned>> {
        backup.check(&self.descriptor)?;
        let d = &self.descriptor.domain;
        let state = &self.replay.state;
        let tree = state.cm_tree()?;
        let mut owned = Vec::new();
        let mut accept = |note: Note, position: u32| -> Result<()> {
            let cm = note.commitment(d);
            if state.commitments.get(position as usize) != Some(&cm)
                || tree::root_from(tree::cm_leaf(&cm), position, &tree.path(position)?)
                    != tree.root()
            {
                return Err("receipt membership/position mismatch".into());
            }
            let nf = crate::compact::nullifier(d, &backup.wallet.spending, &cm, position);
            owned.push(Owned {
                note,
                position,
                spent: state.spent(&nf),
            });
            Ok(())
        };
        if let Some(note) = &backup.initial_note {
            accept(note.clone(), 0)?;
        }
        let mut position = 1u32;
        for record in self.replay.records.iter().skip(1) {
            let tx = native::parse_tx(&record.transaction)?;
            let bundle = replay::bundle(&tx)?;
            let a = bundle.auth()?;
            if a.mode == 2 {
                continue;
            }
            for slot in 0..2 {
                if state.commitments.get(position as usize) != Some(&a.outputs[slot]) {
                    return Err("receipt transcript/position mismatch".into());
                }
                // Delivery is sender-controlled even under a valid proof.
                // Reject/uncredit malformed delivery without denying access
                // to unrelated valid receipts. Public-state errors above and
                // membership errors in accept() remain hard failures.
                if let Ok(Some(note)) = receipt(
                    &backup.wallet,
                    d,
                    &hex::decode(&bundle.ciphertexts[slot])?,
                    &a.outputs[slot],
                ) {
                    accept(note, position)?;
                }
                // Both real and padding outputs occupy a leaf.
                position = position.checked_add(1).ok_or("receipt position overflow")?;
            }
        }
        if position as usize != state.commitments.len() {
            return Err("receipt transcript count mismatch".into());
        }
        Ok(owned)
    }

    /// Local inspection is sensitive wallet information; it is not a public
    /// receive envelope or transaction export. No note opening/key is returned.
    pub fn inspect(&self, backup: &Backup) -> Result<Value> {
        let owned = self.owned(backup)?;
        let balance = owned.iter().filter(|n| !n.spent).try_fold(0u64, |sum, n| {
            sum.checked_add(n.note.value)
                .filter(|v| *v <= MAX_SOMPI)
                .ok_or("wallet balance overflow/range")
        })?;
        Ok(json!({
            "scope": SCOPE,
            "chain_acceptance_verified": false,
            "sensitive_local_wallet_view": true,
            "descriptor_sha256": descriptor_hash(&self.descriptor)?,
            "head": self.head,
            "bootstrap_validated": self.replay.bootstrap_validated,
            "drained": self.replay.reserve.is_none(),
            "balance_sompi": balance.to_string(),
            "notes": owned.iter().map(|n| json!({
                "position": n.position, "value_sompi": n.note.value.to_string(), "spent": n.spent,
            })).collect::<Vec<_>>(),
        }))
    }

    fn select(&self, backup: &Backup, positions: &[u32]) -> Result<Vec<circuit::Input>> {
        if positions.is_empty() || positions.len() > 2 {
            return Err("select one or two owned positions".into());
        }
        let mut seen = HashSet::new();
        let owned = self.owned(backup)?;
        positions
            .iter()
            .map(|position| {
                if !seen.insert(*position) {
                    return Err("duplicate selected position".into());
                }
                let note = owned
                    .iter()
                    .find(|n| n.position == *position)
                    .ok_or("selected position absent or not owned")?;
                if note.spent {
                    return Err("selected position already spent".into());
                }
                harness::selected(&backup.wallet, &note.note, *position, &self.replay.state)
            })
            .collect()
    }

    fn funding(&self, txid: &str, index: u32) -> Result<native::Utxo> {
        hash_text(txid)?;
        let mut parents = replay::Parents::new(&self.parents)?;
        // Reconstruct all external consumption, including the founding input.
        for (i, record) in self.replay.records.iter().enumerate() {
            let tx = native::parse_tx(&record.transaction)?;
            if i == 0 {
                parents.consume(&tx.inputs[0].previous_outpoint)?;
            } else if replay::bundle(&tx)?.auth()?.mode == 0 {
                parents.consume(&tx.inputs[1].previous_outpoint)?;
            }
        }
        parents.consume(&kaspa_consensus_core::tx::TransactionOutpoint::new(
            kaspa_hashes::Hash::from_bytes(
                hex::decode(txid)?.try_into().map_err(|_| "txid length")?,
            ),
            index,
        ))
    }

    fn plan(&self, backup: &Backup, action: &Action) -> Result<Prepared> {
        backup.check(&self.descriptor)?;
        let d = self.descriptor.domain;
        let reserve = self.replay.reserve.as_ref().ok_or("pool drained")?;
        let (inputs, outputs, mode, payout, spk, external, funding_key) = match action {
            Action::Admit {
                txid,
                index,
                native_key_index,
            } => {
                if !self.replay.bootstrap_validated {
                    return Err("admission before bootstrap".into());
                }
                let source = self.funding(txid, *index)?;
                let key = backup.native_key(&self.descriptor, *native_key_index)?;
                if source.spk != hex::encode(native::encode_spk(&native::p2pk(&key)?)) {
                    return Err("funding output is not owned by this wallet/key index".into());
                }
                reserve
                    .amount
                    .checked_add(source.amount)
                    .filter(|v| *v <= MAX_SOMPI)
                    .ok_or("aggregate native amount out of range")?;
                let credit = source
                    .amount
                    .checked_sub(FEE)
                    .filter(|v| *v >= NOTE_FLOOR)
                    .ok_or("admission credit below v6 note floor after fee")?;
                (
                    vec![],
                    [
                        harness::output(&backup.wallet, &d, credit)?,
                        harness::output(&backup.wallet, &d, 0)?,
                    ],
                    0,
                    0,
                    [0; 36],
                    Some(source),
                    Some(key),
                )
            }
            Action::Pay {
                positions,
                recipient,
                amount_sompi,
            } => {
                recipient.check(&self.descriptor)?;
                let value = amount(amount_sompi)?;
                if value < NOTE_FLOOR {
                    return Err("payment below v6 note floor".into());
                }
                let inputs = self.select(backup, positions)?;
                let total = input_total(&inputs)?;
                let change = total
                    .checked_sub(value)
                    .and_then(|v| v.checked_sub(FEE))
                    .ok_or("payment plus fee exceeds selected value")?;
                if change != 0 && change < NOTE_FLOOR {
                    return Err("change below v6 note floor".into());
                }
                (
                    inputs,
                    [
                        recipient.receive.note(value)?,
                        harness::output(&backup.wallet, &d, change)?,
                    ],
                    1,
                    0,
                    [0; 36],
                    None,
                    None,
                )
            }
            Action::Exit {
                positions,
                native_key_index,
            } => {
                let inputs = self.select(backup, positions)?;
                // Reconstructible after recovery from spent notes alone;
                // a lost request/sidecar must not hide the payout key index.
                if positions.iter().min() != Some(native_key_index) {
                    return Err("exit key index must equal the lowest selected position".into());
                }
                let payout = input_total(&inputs)?
                    .checked_sub(FEE)
                    .filter(|v| *v >= PAYOUT_FLOOR)
                    .ok_or("exit payout below v6 payout floor after fee")?;
                let key = backup.native_key(&self.descriptor, *native_key_index)?;
                let spk = native::encode_spk(&native::p2pk(&key)?)
                    .try_into()
                    .map_err(|_| "native payout script size")?;
                (
                    inputs,
                    [Note::dummy(), Note::dummy()],
                    2,
                    payout,
                    spk,
                    None,
                    None,
                )
            }
        };
        let (circuit, bundle) = harness::authorize(
            d,
            &self.replay.state,
            inputs,
            outputs,
            mode,
            payout,
            spk,
            external.as_ref(),
        )?;
        // Check state/capacity/accounting before allocating a constraint system
        // or loading parameters. The placeholder proof is not validated here.
        settle(
            &d,
            &self.replay.state,
            reserve,
            &self.vk,
            &bundle,
            external.as_ref(),
        )?;
        Ok(Prepared {
            circuit,
            bundle,
            external,
            funding_key,
            binding: self.binding()?,
            parameters: backup.parameters.clone(),
            preparation_ms: 0,
            constraints: 0,
        })
    }

    pub fn prepare(&self, backup: &Backup, action: &Action) -> Result<Prepared> {
        let start = Instant::now();
        let mut prepared = self.plan(backup, action)?;
        let (constraints, satisfied) = prepared.circuit.check()?;
        if !satisfied {
            return Err("wallet request does not satisfy v6 relation".into());
        }
        prepared.constraints = constraints;
        prepared.preparation_ms = start.elapsed().as_millis();
        Ok(prepared)
    }
}

fn input_total(inputs: &[circuit::Input]) -> Result<u64> {
    inputs.iter().try_fold(0u64, |sum, input| {
        sum.checked_add(input.note.value)
            .filter(|v| *v <= MAX_SOMPI)
            .ok_or_else(|| "selected input total out of range".into())
    })
}

/// Failed trial decryption means unowned/undeliverable, never credit. Once
/// decryption succeeds, malformed or unspendable delivery returns a local
/// rejection; the scanner ignores that delivery and continues.
/// Ciphertext binding in the proof does not prove correct encryption.
fn receipt(wallet: &Wallet, d: &H, cipher: &[u8], cm: &H) -> Result<Option<Note>> {
    let Ok(plain) = SecretKey::from(wallet.viewing).unseal(cipher) else {
        return Ok(None);
    };
    if plain.len() != 137 || plain[0] != 1 || plain[1..33] != *d {
        return Err("decrypted receipt framing/domain".into());
    }
    if u64::from_le_bytes(plain[97..105].try_into()?) == 0 {
        // Zero-valued delivery cannot be credited. Validate its commitment and
        // ownership too, rather than treating arbitrary plaintext as padding.
        let zero = Note {
            owner: plain[33..65].try_into()?,
            incoming: plain[65..97].try_into()?,
            value: 0,
            rho: plain[105..137].try_into()?,
        };
        let receive = wallet.receive(d);
        if zero.owner != receive.owner
            || zero.incoming != receive.incoming
            || zero.commitment(d) != *cm
        {
            return Err("zero receipt validation".into());
        }
        return Ok(None);
    }
    let note = wallet.decrypt(d, cipher, cm)?;
    if note.value < NOTE_FLOOR {
        return Err("received note below v6 note floor".into());
    }
    Ok(Some(note))
}

/// Contains private proving material in memory only; intentionally not Serialize.
pub struct Prepared {
    circuit: circuit::Circuit,
    bundle: Bundle,
    external: Option<native::Utxo>,
    funding_key: Option<H>,
    binding: H,
    parameters: ParameterPin,
    preparation_ms: u128,
    constraints: usize,
}

#[derive(Serialize)]
pub struct PreparedTransaction {
    pub scope: &'static str,
    pub chain_acceptance_verified: bool,
    pub descriptor_sha256: String,
    pub base_head: Head,
    pub transaction: Value,
    pub bundle: Bundle,
    pub metrics: Value,
    pub preparation_ms: u128,
    pub proof_ms: u128,
    pub native_validation_ms: u128,
    pub constraints: usize,
}

struct HashedReader<R> {
    reader: R,
    digest: Sha256,
    bytes: u64,
}
impl<R: Read> Read for HashedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = self.reader.read(buf)?;
        self.digest.update(&buf[..count]);
        self.bytes += count as u64;
        Ok(count)
    }
}

/// One local process may retain this public PK to amortize validated decoding.
/// It never retains wallet keys/notes after a request completes.
pub struct Prover {
    pk: ProvingKey<Bn254>,
    parameters: ParameterPin,
    vk: Vec<u8>,
    pub load_ms: u128,
}
impl Prover {
    pub fn load(path: &Path, parameters: &ParameterPin, vk: &[u8]) -> Result<Self> {
        parameters.check()?;
        let start = Instant::now();
        let mut file = fs::File::open(path)?;
        if file.metadata()?.len() != parameters.bytes {
            return Err("proving parameter byte length mismatch".into());
        }
        // Reject corrupted/unauthenticated size fields before deserialization
        // can allocate query vectors. Keep the same descriptor open, then hash
        // the decoded stream again to detect modification during/between reads.
        let mut digest = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            digest.update(&buf[..n]);
        }
        if hex::encode(digest.finalize()) != parameters.sha256 {
            return Err("proving parameter SHA-256 mismatch".into());
        }
        file.seek(SeekFrom::Start(0))?;
        let mut reader = HashedReader {
            reader: BufReader::new(file),
            digest: Sha256::new(),
            bytes: 0,
        };
        // Compressed deserialization includes arkworks' point validation.
        // Hash exactly the stream decoded, preventing a hash/reopen substitution.
        let pk = ProvingKey::<Bn254>::deserialize_compressed(&mut reader)?;
        if reader.read(&mut [0u8; 1])? != 0
            || reader.bytes != parameters.bytes
            || hex::encode(reader.digest.finalize()) != parameters.sha256
        {
            return Err("proving parameter SHA-256/trailing bytes mismatch".into());
        }
        if harness::compressed(&pk.vk)? != vk {
            return Err("proving parameter embedded VK mismatch".into());
        }
        Ok(Self {
            pk,
            parameters: parameters.clone(),
            vk: vk.to_vec(),
            load_ms: start.elapsed().as_millis(),
        })
    }

    /// Research-only sibling harness hook for adversarial delivery fixtures.
    /// Uses this exact validated PK and locally verifies the generated proof.
    /// Not exposed by the wallet API/CLI; ordinary requests use opaque Prepared.
    pub(super) fn prove_circuit(
        &self,
        circuit: circuit::Circuit,
        bundle: Bundle,
    ) -> Result<Bundle> {
        harness::prove(&self.pk, circuit, bundle)
    }

    pub fn prove(&self, context: &Context, prepared: Prepared) -> Result<PreparedTransaction> {
        if prepared.binding != context.binding()?
            || self.vk != context.vk
            || self.parameters != prepared.parameters
        {
            return Err("prepared request context/parameter mismatch".into());
        }
        let start = Instant::now();
        let bundle = self.prove_circuit(prepared.circuit, prepared.bundle)?;
        let proof_ms = start.elapsed().as_millis();
        let validation = Instant::now();
        let (mut tx, entries, _) = settle(
            &context.descriptor.domain,
            &context.replay.state,
            context.replay.reserve.as_ref().ok_or("pool drained")?,
            &context.vk,
            &bundle,
            prepared.external.as_ref(),
        )?;
        if let Some(key) = prepared.funding_key {
            native::sign(&mut tx, &entries, 1, &key)?;
        }
        if native::validate(&tx, &entries)? != FEE {
            return Err("prepared native fee mismatch".into());
        }
        let metrics = native::policy(&tx, &entries)?;
        Ok(PreparedTransaction {
            scope: SCOPE,
            chain_acceptance_verified: false,
            descriptor_sha256: descriptor_hash(&context.descriptor)?,
            base_head: context.head.clone(),
            transaction: native::tx_json(&tx),
            bundle,
            metrics,
            preparation_ms: prepared.preparation_ms,
            proof_ms,
            native_validation_ms: validation.elapsed().as_millis(),
            constraints: prepared.constraints,
        })
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn print(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}

/// File references and a SENSITIVE local action cross this process boundary.
/// Actions reveal selected positions, private amounts and recipients. Never
/// export requests alongside the public transaction. No network listener,
/// broadcast, or mutable ledger is provided.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    backup: PathBuf,
    descriptor: PathBuf,
    vk: PathBuf,
    lineage: PathBuf,
    parents: PathBuf,
    head: PathBuf,
    action: Action,
}
impl Command {
    fn context(&self) -> Result<(Backup, Context)> {
        let backup = read_json(&self.backup)?;
        let context = Context::new(
            read_json(&self.descriptor)?,
            fs::read(&self.vk)?,
            &read_json::<Vec<Value>>(&self.lineage)?,
            &read_json::<Vec<Value>>(&self.parents)?,
            read_json(&self.head)?,
        )?;
        Ok((backup, context))
    }
    fn prepare(&self) -> Result<(Context, Prepared)> {
        let (backup, context) = self.context()?;
        let prepared = context.prepare(&backup, &self.action)?;
        Ok((context, prepared))
    }
}

pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = |i: usize| Path::new(&args[i]);
    match args.first().map(String::as_str) {
        Some("create") if args.len() == 5 => {
            let descriptor = read_json(paths(1))?;
            let backup = Backup::fresh(&descriptor, &fs::read(paths(2))?, read_json(paths(3))?)?;
            fs::DirBuilder::new().mode(0o700).create(paths(4))?;
            backup.save_new(&paths(4).join("backup.json"))?;
            let mut public = fs::OpenOptions::new().write(true).create_new(true)
                .mode(0o600).open(paths(4).join("receive.json"))?;
            serde_json::to_writer_pretty(&mut public, &backup.receive(&descriptor)?)?;
            public.write_all(b"\n")?;
            print(&json!({"created":true,"directory":paths(4),"descriptor_sha256":descriptor_hash(&descriptor)?}))?;
        }
        Some("receive") if args.len() == 3 => {
            print(&read_json::<Backup>(paths(1))?.receive(&read_json(paths(2))?)?)?;
        }
        Some("funding") if args.len() == 4 => {
            print(&read_json::<Backup>(paths(1))?.funding(&read_json(paths(2))?, args[3].parse()?)?)?;
        }
        Some("inspect") if args.len() == 7 => {
            let backup = read_json(paths(1))?;
            let context = Context::new(read_json(paths(2))?, fs::read(paths(3))?,
                &read_json::<Vec<Value>>(paths(4))?, &read_json::<Vec<Value>>(paths(5))?,
                read_json(paths(6))?)?;
            print(&context.inspect(&backup)?)?;
        }
        Some("prepare") if args.len() == 9 => {
            let command = Command {
                backup: paths(1).into(), descriptor: paths(2).into(), vk: paths(3).into(),
                lineage: paths(4).into(), parents: paths(5).into(), head: paths(6).into(),
                action: read_json(paths(7))?,
            };
            let (context, prepared) = command.prepare()?;
            let prover = Prover::load(paths(8), &prepared.parameters, &context.vk)?;
            print(&prover.prove(&context, prepared)?)?;
        }
        Some("serve") if args.len() == 4 => {
            let prover = Prover::load(paths(1), &read_json(paths(2))?, &fs::read(paths(3))?)?;
            eprintln!("validated public proving parameters loaded in {} ms", prover.load_ms);
            for line in std::io::stdin().lock().lines() {
                let response = (|| -> Result<PreparedTransaction> {
                    let command: Command = serde_json::from_str(&line?)?;
                    let (context, prepared) = command.prepare()?;
                    prover.prove(&context, prepared)
                })();
                match response {
                    Ok(result) => print(&json!({"ok":true,"result":result}))?,
                    Err(error) => print(&json!({"ok":false,"error":error.to_string()}))?,
                }
                std::io::stdout().flush()?;
            }
        }
        _ => return Err("usage: kpi-two-input-wallet create DESCRIPTOR VK PIN_JSON NEWDIR | receive BACKUP DESCRIPTOR | funding BACKUP DESCRIPTOR INDEX | inspect BACKUP DESCRIPTOR VK LINEAGE PARENTS HEAD | prepare BACKUP DESCRIPTOR VK LINEAGE PARENTS HEAD ACTION_JSON PK | serve PK PIN_JSON VK".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
