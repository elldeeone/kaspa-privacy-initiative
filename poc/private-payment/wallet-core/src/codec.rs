//! Exact reviewed wire framing. IDs bind context; they do not authorize a pool.
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
pub const INTENT_TAG: &[u8] = b"KPI/private-payment/intent/v1";
pub const WITNESS_TAG: &[u8] = b"KPI/private-payment/witness/v1";
pub const MAX_INPUT: usize = 65536;
#[derive(Clone, PartialEq, Eq)]
pub struct Script {
    pub version: u16,
    pub bytes: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Deposit {
    pub tx: [u8; 32],
    pub index: u32,
    pub descriptor: [u8; 32],
    pub key: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub struct Intent {
    // G, D, network, pool, lane(20 bytes), statement, suite, wallet image.
    pub ids: [Vec<u8>; 8],
    pub kind: u8,
    pub mode: u8,
    pub expiry: Option<u64>,
    pub anchor: [u8; 32],
    pub nf: [[u8; 32]; 2],
    pub cmx: [[u8; 32]; 2],
    pub epk: [[u8; 32]; 2],
    pub ciphertext: [[u8; 580]; 2],
    pub deposit: Option<Deposit>,
    pub principal: u64,
    pub exit: Option<Script>,
    pub exited: u64,
    pub fee_script: Option<Script>,
    pub fee: u64,
}
pub fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
pub struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub fn new(raw: &'a [u8]) -> Self {
        Self { raw, at: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.raw.len() - self.at, "truncated frame");
        let b = &self.raw[self.at..self.at + n];
        self.at += n;
        Ok(b)
    }
    pub fn a<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into()?)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.a::<1>()?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.a()?))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.a()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.a()?))
    }
    pub fn flag(&mut self) -> Result<bool> {
        let f = self.u8()?;
        ensure!(f <= 1, "unknown flag");
        Ok(f == 1)
    }
    pub fn end(&self) -> Result<()> {
        ensure!(self.at == self.raw.len(), "trailing bytes");
        Ok(())
    }
    fn script(&mut self) -> Result<Option<Script>> {
        if !self.flag()? {
            return Ok(None);
        }
        let version = self.u16()?;
        let n = self.u32()? as usize;
        ensure!((1..=10000).contains(&n), "script length");
        Ok(Some(Script {
            version,
            bytes: self.take(n)?.to_vec(),
        }))
    }
}
fn put_script(out: &mut Vec<u8>, s: &Option<Script>) -> Result<()> {
    out.push(u8::from(s.is_some()));
    if let Some(s) = s {
        ensure!((1..=10000).contains(&s.bytes.len()), "script length");
        out.extend(s.version.to_le_bytes());
        out.extend((s.bytes.len() as u32).to_le_bytes());
        out.extend(&s.bytes);
    }
    Ok(())
}
impl Intent {
    pub fn shape(&self) -> Result<()> {
        for (i, id) in self.ids.iter().enumerate() {
            ensure!(id.len() == if i == 4 { 20 } else { 32 }, "context width");
        }
        ensure!(self.kind <= 2 && self.mode <= 1, "unknown kind/mode");
        ensure!(self.fee_script.is_some() == (self.fee > 0), "fee presence");
        match self.kind {
            0 => ensure!(
                self.deposit.is_some()
                    && self.principal > 0
                    && self.exit.is_none()
                    && self.exited == 0
                    && self.fee == 0
                    && self.mode == 0,
                "CREDIT fields"
            ),
            1 => ensure!(
                self.deposit.is_none()
                    && self.principal == 0
                    && self.exit.is_none()
                    && self.exited == 0
                    && self.mode == 0,
                "TRANSFER fields"
            ),
            2 => ensure!(
                self.deposit.is_none()
                    && self.principal == 0
                    && self.exit.is_some()
                    && self.exited > 0,
                "EXIT fields"
            ),
            _ => unreachable!(),
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.shape()?;
        let mut b = INTENT_TAG.to_vec();
        for id in &self.ids {
            b.extend(id)
        }
        b.extend([self.kind, self.mode]);
        b.push(u8::from(self.expiry.is_some()));
        if let Some(e) = self.expiry {
            b.extend(e.to_le_bytes())
        }
        b.extend(self.anchor);
        for a in [&self.nf, &self.cmx, &self.epk] {
            for v in a {
                b.extend(v)
            }
        }
        for c in self.ciphertext {
            b.extend(c)
        }
        b.push(u8::from(self.deposit.is_some()));
        if let Some(d) = &self.deposit {
            b.extend(d.tx);
            b.extend(d.index.to_le_bytes());
            b.extend(d.descriptor);
            b.extend(d.key)
        }
        b.extend(self.principal.to_le_bytes());
        put_script(&mut b, &self.exit)?;
        b.extend(self.exited.to_le_bytes());
        put_script(&mut b, &self.fee_script)?;
        b.extend(self.fee.to_le_bytes());
        Ok(b)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw);
        ensure!(r.take(INTENT_TAG.len())? == INTENT_TAG, "intent tag");
        let mut ids: [Vec<u8>; 8] = Default::default();
        for (i, id) in ids.iter_mut().enumerate() {
            *id = r.take(if i == 4 { 20 } else { 32 })?.to_vec()
        }
        let kind = r.u8()?;
        let mode = r.u8()?;
        let expiry = if r.flag()? { Some(r.u64()?) } else { None };
        let anchor = r.a()?;
        let nf = [r.a()?, r.a()?];
        let cmx = [r.a()?, r.a()?];
        let epk = [r.a()?, r.a()?];
        let ciphertext = [r.a()?, r.a()?];
        let deposit = if r.flag()? {
            Some(Deposit {
                tx: r.a()?,
                index: r.u32()?,
                descriptor: r.a()?,
                key: r.a()?,
            })
        } else {
            None
        };
        let principal = r.u64()?;
        let exit = r.script()?;
        let exited = r.u64()?;
        let fee_script = r.script()?;
        let fee = r.u64()?;
        r.end()?;
        let i = Self {
            ids,
            kind,
            mode,
            expiry,
            anchor,
            nf,
            cmx,
            epk,
            ciphertext,
            deposit,
            principal,
            exit,
            exited,
            fee_script,
            fee,
        };
        ensure!(i.encode()? == raw, "noncanonical intent");
        Ok(i)
    }
    pub fn journal(&self, auth: &[u8]) -> Result<Vec<u8>> {
        let ids = [0, 5, 6, 7].map(|i| self.ids[i].as_slice().try_into().unwrap());
        Ok(kpi_recovery_auth_vectors::expected_journal(
            &ids,
            &hash(&self.encode()?),
            &kpi_recovery_auth_vectors::authorization_digest(self.kind, auth)?,
        ))
    }
}
#[derive(Clone)]
pub struct OldNote {
    pub sk: [u8; 32],
    pub scope: u8,
    pub diversifier: [u8; 11],
    pub value: u64,
    pub rho: [u8; 32],
    pub seed: [u8; 32],
    pub path: Option<(u32, [[u8; 32]; 32])>,
}
#[derive(Clone)]
pub struct NewNote {
    pub address: [u8; 43],
    pub value: u64,
    pub seed: [u8; 32],
    pub memo: [u8; 512],
}
#[derive(Clone)]
pub struct Witness {
    pub intent: Intent,
    pub old: [OldNote; 2],
    pub new: [NewNote; 2],
    pub auth: Vec<u8>,
}
impl Witness {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut b = WITNESS_TAG.to_vec();
        let i = self.intent.encode()?;
        b.extend((i.len() as u32).to_le_bytes());
        b.extend(i);
        for n in &self.old {
            b.extend(n.sk);
            b.push(n.scope);
            b.extend(n.diversifier);
            b.extend(n.value.to_le_bytes());
            b.extend(n.rho);
            b.extend(n.seed);
            b.push(u8::from(n.path.is_some()));
            if let Some((p, s)) = &n.path {
                b.extend(p.to_le_bytes());
                for a in s {
                    b.extend(a)
                }
            }
        }
        for n in &self.new {
            b.extend(n.address);
            b.extend(n.value.to_le_bytes());
            b.extend(n.seed);
            b.extend(n.memo)
        }
        b.extend(&self.auth);
        ensure!(b.len() <= MAX_INPUT, "witness too large");
        Ok(b)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        ensure!(raw.len() <= MAX_INPUT, "witness too large");
        let mut r = Reader::new(raw);
        ensure!(r.take(WITNESS_TAG.len())? == WITNESS_TAG, "witness tag");
        let len = r.u32()? as usize;
        let intent = Intent::decode(r.take(len)?)?;
        let mut olds = Vec::new();
        for _ in 0..2 {
            let sk = r.a()?;
            let scope = r.u8()?;
            ensure!(scope <= 1, "unknown scope");
            let diversifier = r.a()?;
            let value = r.u64()?;
            let rho = r.a()?;
            let seed = r.a()?;
            let path = if r.flag()? {
                let p = r.u32()?;
                let mut s = [[0; 32]; 32];
                for a in &mut s {
                    *a = r.a()?
                }
                Some((p, s))
            } else {
                None
            };
            ensure!(
                path.is_some() == (value > 0),
                "membership presence/value mismatch"
            );
            olds.push(OldNote {
                sk,
                scope,
                diversifier,
                value,
                rho,
                seed,
                path,
            });
        }
        let mut news = Vec::new();
        for _ in 0..2 {
            news.push(NewNote {
                address: r.a()?,
                value: r.u64()?,
                seed: r.a()?,
                memo: r.a()?,
            })
        }
        let auth = if r.flag()? {
            [vec![1], r.take(64)?.to_vec()].concat()
        } else {
            vec![0]
        };
        r.end()?;
        kpi_recovery_auth_vectors::parse_authorization(intent.kind, &auth)?;
        Ok(Self {
            intent,
            old: olds.try_into().ok().context("two old")?,
            new: news.try_into().ok().context("two new")?,
            auth,
        })
    }
}
