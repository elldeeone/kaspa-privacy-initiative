//! Draft transaction-v2 bytes; deliberately separate from the frozen interop packet.
use crate::{hash, profile_id, Error, ACTIONS, MAX_SOMPI, PROOF_BYTES};
use nonempty::NonEmpty;
use orchard::{
    bundle::{Authorization, Authorized, BundleVersion},
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    primitives::redpallas,
    value::ValueCommitment,
    Action, Anchor, Bundle, Proof,
};

pub const MAX_PACKET: usize = 262_144;
pub const MAX_ITEMS: usize = 16;
pub const MAX_BLOB: usize = 4096;
pub type AuthorizedBundle = Bundle<Authorized, i64>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub index: u32,
}
impl OutPoint {
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.txid);
        out.extend_from_slice(&self.index.to_le_bytes());
    }
}

#[derive(Clone, Debug)]
pub struct Input {
    pub previous: OutPoint,
    pub signature_script: Vec<u8>,
    pub sequence: u64,
    pub compute_budget: u16,
}
#[derive(Clone, Debug)]
pub struct Output {
    pub value: u64,
    pub script_version: u16,
    pub script: Vec<u8>,
    pub covenant: Option<(u16, [u8; 32])>,
}
#[derive(Clone, Debug)]
pub struct Effects {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub lock_time: u64,
    pub payload: Vec<u8>,
    pub storage_mass: u64,
    pub domain: [u8; 32],
    pub fee: u64,
    pub anchor_tree: u64,
    pub anchor_count: u64,
}
#[derive(Clone, Debug)]
pub struct Transaction {
    pub effects: Effects,
    pub bundle: AuthorizedBundle,
}

pub fn blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_BLOB {
        return Err(Error::Decode("blob bound"));
    }
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Q when `signatures` is false; wire fields 1..10 otherwise.
pub fn effect_bytes<T: Authorization>(
    e: &Effects,
    b: &Bundle<T, i64>,
    signatures: bool,
) -> Result<Vec<u8>, Error> {
    let version = BundleVersion::orchard_v2();
    if b.bundle_version() != version
        || *b.flags() != version.default_flags()
        || b.actions().len() != ACTIONS
    {
        return Err(Error::Profile);
    }
    if e.inputs.len() > MAX_ITEMS || e.outputs.len() > MAX_ITEMS {
        return Err(Error::Decode("item bound"));
    }
    if b.value_balance().unsigned_abs() > MAX_SOMPI || e.fee > MAX_SOMPI {
        return Err(Error::Range);
    }
    if e.anchor_count > 1 << 32 || !e.anchor_count.is_multiple_of(2) {
        return Err(Error::Anchor);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&(e.inputs.len() as u64).to_le_bytes());
    for input in &e.inputs {
        input.previous.write(&mut out);
        blob(
            &mut out,
            if signatures {
                &input.signature_script
            } else {
                &[]
            },
        )?;
        out.extend_from_slice(&input.sequence.to_le_bytes());
        out.extend_from_slice(&input.compute_budget.to_le_bytes());
    }
    out.extend_from_slice(&(e.outputs.len() as u64).to_le_bytes());
    for output in &e.outputs {
        out.extend_from_slice(&output.value.to_le_bytes());
        out.extend_from_slice(&output.script_version.to_le_bytes());
        blob(&mut out, &output.script)?;
        out.push(u8::from(output.covenant.is_some()));
        if let Some((index, id)) = output.covenant {
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&id);
        }
    }
    out.extend_from_slice(&e.lock_time.to_le_bytes());
    out.extend_from_slice(&[0; 20]);
    out.extend_from_slice(&0u64.to_le_bytes());
    blob(&mut out, &e.payload)?;
    out.extend_from_slice(&e.storage_mass.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&e.domain);
    out.extend_from_slice(&profile_id());
    for n in [e.fee, e.anchor_tree, e.anchor_count] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out.extend_from_slice(&b.anchor().to_bytes());
    out.extend_from_slice(&[3, ACTIONS as u8]);
    for a in b.actions() {
        out.extend_from_slice(&a.cv_net().to_bytes());
        out.extend_from_slice(&a.nullifier().to_bytes());
        out.extend_from_slice(&<[u8; 32]>::from(a.rk()));
        out.extend_from_slice(&a.cmx().to_bytes());
        let enc = a.encrypted_note();
        out.extend_from_slice(&enc.epk_bytes);
        out.extend_from_slice(&enc.enc_ciphertext.0);
        out.extend_from_slice(&enc.out_ciphertext);
    }
    out.extend_from_slice(&b.value_balance().to_le_bytes());
    Ok(out)
}

impl Transaction {
    pub fn txid(&self) -> Result<[u8; 32], Error> {
        Ok(hash(
            "TxID",
            &effect_bytes(&self.effects, &self.bundle, false)?,
        ))
    }
    pub fn txhash(&self) -> Result<[u8; 32], Error> {
        Ok(hash("TxHash", &self.encode()?))
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = effect_bytes(&self.effects, &self.bundle, true)?;
        let proof = self.bundle.authorization().proof().as_ref();
        if proof.len() != PROOF_BYTES {
            return Err(Error::Decode("proof length"));
        }
        out.extend_from_slice(&(PROOF_BYTES as u64).to_le_bytes());
        out.extend_from_slice(proof);
        for a in self.bundle.actions() {
            out.extend_from_slice(&<[u8; 64]>::from(a.authorization()));
        }
        out.extend_from_slice(&<[u8; 64]>::from(
            self.bundle.authorization().binding_signature(),
        ));
        if out.len() > MAX_PACKET {
            return Err(Error::Decode("packet bound"));
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PACKET {
            return Err(Error::Decode("packet bound"));
        }
        let mut r = Reader { bytes, at: 0 };
        if r.u16()? != 2 {
            return Err(Error::Profile);
        }
        let mut inputs = Vec::new();
        for _ in 0..r.count()? {
            inputs.push(Input {
                previous: OutPoint {
                    txid: r.array()?,
                    index: r.u32()?,
                },
                signature_script: r.blob()?,
                sequence: r.u64()?,
                compute_budget: r.u16()?,
            });
        }
        let mut outputs = Vec::new();
        for _ in 0..r.count()? {
            outputs.push(Output {
                value: r.u64()?,
                script_version: r.u16()?,
                script: r.blob()?,
                covenant: match r.byte()? {
                    0 => None,
                    1 => Some((r.u16()?, r.array()?)),
                    _ => return Err(Error::Decode("covenant tag")),
                },
            });
        }
        let lock_time = r.u64()?;
        if r.array::<20>()? != [0; 20] || r.u64()? != 0 {
            return Err(Error::Profile);
        }
        let payload = r.blob()?;
        let storage_mass = r.u64()?;
        if r.u16()? != 1 {
            return Err(Error::Profile);
        }
        let domain = r.array()?;
        if r.array::<32>()? != profile_id() {
            return Err(Error::Profile);
        }
        let fee = r.u64()?;
        let anchor_tree = r.u64()?;
        let anchor_count = r.u64()?;
        let anchor = Option::<Anchor>::from(Anchor::from_bytes(r.array()?))
            .ok_or(Error::Decode("anchor"))?;
        if r.byte()? != 3 || usize::from(r.byte()?) != ACTIONS {
            return Err(Error::Profile);
        }
        let mut actions = Vec::new();
        for _ in 0..ACTIONS {
            let cv = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&r.array()?))
                .ok_or(Error::Decode("cv"))?;
            let nf = Option::<Nullifier>::from(Nullifier::from_bytes(&r.array()?))
                .ok_or(Error::Decode("nf"))?;
            let rk = redpallas::VerificationKey::try_from(r.array::<32>()?)
                .map_err(|_| Error::Decode("rk"))?;
            let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
                &r.array()?,
            ))
            .ok_or(Error::Decode("cmx"))?;
            let enc = TransmittedNoteCiphertext {
                epk_bytes: r.array()?,
                enc_ciphertext: orchard::note_encryption::NoteBytesData(r.array()?),
                out_ciphertext: r.array()?,
            };
            actions.push(
                Action::from_parts(nf, rk, cmx, enc, cv, ())
                    .map_err(|_| Error::Decode("action keys"))?,
            );
        }
        let balance = i64::from_le_bytes(r.array()?);
        if r.u64()? != PROOF_BYTES as u64 {
            return Err(Error::Decode("proof length"));
        }
        let proof = Proof::new(r.take(PROOF_BYTES)?.to_vec());
        let mut signed = Vec::new();
        for a in actions {
            let signature = redpallas::Signature::from(r.array::<64>()?);
            signed.push(a.map(|_| signature));
        }
        let binding = redpallas::Signature::from(r.array::<64>()?);
        if r.at != bytes.len() {
            return Err(Error::Decode("trailing bytes"));
        }
        let version = BundleVersion::orchard_v2();
        let bundle = Bundle::try_from_parts(
            NonEmpty::from_vec(signed).unwrap(),
            version.default_flags(),
            balance,
            anchor,
            Authorized::from_parts(proof, binding),
            version,
        )
        .map_err(|_| Error::Profile)?;
        let tx = Self {
            effects: Effects {
                inputs,
                outputs,
                lock_time,
                payload,
                storage_mass,
                domain,
                fee,
                anchor_tree,
                anchor_count,
            },
            bundle,
        };
        if tx.encode()? != bytes {
            return Err(Error::Decode("noncanonical roundtrip"));
        }
        Ok(tx)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(Error::Decode("length overflow"))?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or(Error::Decode("truncated"))?;
        self.at = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn count(&mut self) -> Result<usize, Error> {
        let n = self.u64()?;
        if n > MAX_ITEMS as u64 {
            return Err(Error::Decode("item bound"));
        }
        Ok(n as usize)
    }
    fn blob(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.u64()?;
        if n > MAX_BLOB as u64 {
            return Err(Error::Decode("blob bound"));
        }
        Ok(self.take(n as usize)?.to_vec())
    }
}
