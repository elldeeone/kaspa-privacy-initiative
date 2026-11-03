//! Fixed two-Action research wire format. No fallback, variable proof or JSON amounts.
use crate::{
    effects::{Effects, Input, Output},
    profile_id, Error, ACTIONS, PROOF_BYTES,
};
use nonempty::NonEmpty;
use orchard::{
    bundle::{Authorization, Authorized, BundleVersion},
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    primitives::redpallas,
    value::ValueCommitment,
    Action, Anchor, Bundle, Proof,
};

pub const MAGIC: [u8; 8] = *b"KPIOV2\0\x01";
pub const MAX_ITEMS: usize = 16;
pub const MAX_BLOB: usize = 4096;
pub const MAX_PACKET: usize = 160_000;
pub type AuthorizedBundle = Bundle<Authorized, i64>;

#[derive(Clone, Debug)]
pub struct Envelope {
    pub effects: Effects,
    pub bundle: AuthorizedBundle,
}

fn blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_BLOB {
        return Err(Error::Decode("blob bound"));
    }
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

pub fn effect_bytes<T: Authorization>(
    effects: &Effects,
    bundle: &Bundle<T, i64>,
) -> Result<Vec<u8>, Error> {
    let version = BundleVersion::orchard_v2();
    if bundle.bundle_version() != version
        || bundle.actions().len() != ACTIONS
        || *bundle.flags() != version.default_flags()
    {
        return Err(Error::Profile);
    }
    if effects.tx_version != 1 {
        return Err(Error::Profile);
    }
    if effects.inputs.len() > MAX_ITEMS || effects.outputs.len() > MAX_ITEMS {
        return Err(Error::Decode("item bound"));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&profile_id());
    out.extend_from_slice(&effects.tx_version.to_le_bytes());
    for domain in [
        &effects.network,
        &effects.genesis,
        &effects.pool,
        &effects.accepted_context,
    ] {
        out.extend_from_slice(domain);
    }
    out.extend_from_slice(&effects.lock_time.to_le_bytes());
    out.extend_from_slice(&effects.subnetwork);
    for n in [effects.gas, effects.storage_mass, effects.fee] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out.extend_from_slice(&(effects.inputs.len() as u16).to_le_bytes());
    for input in &effects.inputs {
        if input.compute_kind > 1 || (input.compute_kind == 0 && input.compute > 255) {
            return Err(Error::Decode("compute tag/value"));
        }
        out.extend_from_slice(&input.txid);
        out.extend_from_slice(&input.index.to_le_bytes());
        out.extend_from_slice(&input.value.to_le_bytes());
        out.extend_from_slice(&input.sequence.to_le_bytes());
        out.push(input.compute_kind);
        out.extend_from_slice(&input.compute.to_le_bytes());
    }
    out.extend_from_slice(&(effects.outputs.len() as u16).to_le_bytes());
    for output in &effects.outputs {
        out.extend_from_slice(&output.value.to_le_bytes());
        out.extend_from_slice(&output.script_version.to_le_bytes());
        blob(&mut out, &output.script)?;
        out.push(u8::from(output.covenant.is_some()));
        if let Some((index, id)) = &output.covenant {
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(id);
        }
    }
    blob(&mut out, &effects.payload)?;
    out.push(bundle.flag_byte());
    out.extend_from_slice(&bundle.value_balance().to_le_bytes());
    out.extend_from_slice(&bundle.anchor().to_bytes());
    out.push(ACTIONS as u8);
    for action in bundle.actions() {
        out.extend_from_slice(&action.cv_net().to_bytes());
        out.extend_from_slice(&action.nullifier().to_bytes());
        out.extend_from_slice(&<[u8; 32]>::from(action.rk()));
        out.extend_from_slice(&action.cmx().to_bytes());
        let enc = action.encrypted_note();
        out.extend_from_slice(&enc.epk_bytes);
        out.extend_from_slice(&enc.enc_ciphertext.0);
        out.extend_from_slice(&enc.out_ciphertext);
    }
    Ok(out)
}

pub fn effect_digest<T: Authorization>(
    effects: &Effects,
    bundle: &Bundle<T, i64>,
) -> Result<[u8; 32], Error> {
    Ok(blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"KPIInteropEffV1!")
        .hash(&effect_bytes(effects, bundle)?)
        .as_bytes()
        .try_into()
        .unwrap())
}

impl Envelope {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = effect_bytes(&self.effects, &self.bundle)?;
        let proof = self.bundle.authorization().proof().as_ref();
        if proof.len() != PROOF_BYTES {
            return Err(Error::Decode("proof length"));
        }
        out.extend_from_slice(&(PROOF_BYTES as u32).to_le_bytes());
        out.extend_from_slice(proof);
        for action in self.bundle.actions() {
            out.extend_from_slice(&<[u8; 64]>::from(action.authorization()));
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
        if r.array::<8>()? != MAGIC {
            return Err(Error::Profile);
        }
        if r.array::<32>()? != profile_id() {
            return Err(Error::Profile);
        }
        let tx_version = r.u16()?;
        if tx_version != 1 {
            return Err(Error::Profile);
        }
        let mut effects = Effects {
            tx_version,
            network: r.array()?,
            genesis: r.array()?,
            pool: r.array()?,
            accepted_context: r.array()?,
            lock_time: r.u64()?,
            subnetwork: r.array()?,
            gas: r.u64()?,
            storage_mass: r.u64()?,
            fee: r.u64()?,
            inputs: Vec::new(),
            outputs: Vec::new(),
            payload: Vec::new(),
        };
        let count = r.count()?;
        for _ in 0..count {
            let input = Input {
                txid: r.array()?,
                index: r.u32()?,
                value: r.u64()?,
                sequence: r.u64()?,
                compute_kind: r.byte()?,
                compute: r.u64()?,
            };
            if input.compute_kind > 1 || (input.compute_kind == 0 && input.compute > 255) {
                return Err(Error::Decode("compute tag/value"));
            }
            effects.inputs.push(input);
        }
        let count = r.count()?;
        for _ in 0..count {
            let value = r.u64()?;
            let script_version = r.u16()?;
            let script = r.blob()?;
            let covenant = match r.byte()? {
                0 => None,
                1 => Some((r.u32()?, r.array()?)),
                _ => return Err(Error::Decode("covenant tag")),
            };
            effects.outputs.push(Output {
                value,
                script_version,
                script,
                covenant,
            });
        }
        effects.payload = r.blob()?;
        let version = BundleVersion::orchard_v2();
        let flags = orchard::bundle::Flags::from_byte(r.byte()?, version).ok_or(Error::Profile)?;
        if flags != version.default_flags() {
            return Err(Error::Profile);
        }
        let balance = i64::from_le_bytes(r.array()?);
        // Canonical integer-range constraints belong to the packet profile too.
        if balance.unsigned_abs() > crate::MAX_SOMPI {
            return Err(Error::Range);
        }
        let anchor = Option::<Anchor>::from(Anchor::from_bytes(r.array()?))
            .ok_or(Error::Decode("anchor"))?;
        if usize::from(r.byte()?) != ACTIONS {
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
        if r.u32()? as usize != PROOF_BYTES {
            return Err(Error::Decode("proof length"));
        }
        let proof = Proof::new(r.take(PROOF_BYTES)?.to_vec());
        let mut signed = Vec::new();
        for action in actions {
            let sig = redpallas::Signature::from(r.array::<64>()?);
            signed.push(action.map(|_| sig));
        }
        let binding = redpallas::Signature::from(r.array::<64>()?);
        if r.at != bytes.len() {
            return Err(Error::Decode("trailing bytes"));
        }
        let bundle = Bundle::try_from_parts(
            NonEmpty::from_vec(signed).unwrap(),
            flags,
            balance,
            anchor,
            Authorized::from_parts(proof, binding),
            version,
        )
        .map_err(|_| Error::Profile)?;
        let result = Self { effects, bundle };
        if result.encode()? != bytes {
            return Err(Error::Decode("noncanonical roundtrip"));
        }
        Ok(result)
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
        let n = usize::from(self.u16()?);
        if n > MAX_ITEMS {
            return Err(Error::Decode("item bound"));
        }
        Ok(n)
    }
    fn blob(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.u32()? as usize;
        if n > MAX_BLOB {
            return Err(Error::Decode("blob bound"));
        }
        Ok(self.take(n)?.to_vec())
    }
}
