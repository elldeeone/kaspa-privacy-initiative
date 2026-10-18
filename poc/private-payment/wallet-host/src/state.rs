//! Receipt-backed *host* adapter for explicit synthetic policy/history only.
//! This does not authenticate native backing/order and is not an R13 proof.
use crate::{fixture::Tree, proof};
use anyhow::{ensure, Context, Result};
use kpi_wallet_core::{orchard::Anchor, *};
use risc0_zkvm::{sha::Digest, Receipt};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone)]
pub struct State {
    pub ids: [Vec<u8>; 8],
    pub tree: Tree,
    pub allowed: BTreeSet<[u8; 32]>,
    pub spent: BTreeSet<[u8; 32]>,
    pub deposit: Deposit,
    pub pending: u64,
    pub credited: bool,
    pub private: u64,
    pub exits: u64,
    pub fees: u64,
    pub reserve: u64,
    pub claims: BTreeMap<[u8; 32], (u64, Script)>,
    pub cursor: u64,
    pub activity: [u8; 32],
}
pub fn capacity(count: u64, mode: u8) -> Result<()> {
    ensure!(count <= 1u64 << 32, "invalid tree count");
    ensure!(mode <= 1, "unknown append mode");
    ensure!(
        mode == 1 || count.checked_add(2).is_some_and(|n| n <= 1u64 << 32),
        "tree capacity"
    );
    Ok(())
}
impl State {
    pub fn genesis(credit: &Intent) -> Result<Self> {
        let d = credit.deposit.clone().context("synthetic deposit")?;
        Ok(Self {
            ids: credit.ids.clone(),
            tree: Tree::default(),
            allowed: [Anchor::empty_tree().to_bytes()].into_iter().collect(),
            spent: BTreeSet::new(),
            deposit: d,
            pending: credit.principal,
            credited: false,
            private: 0,
            exits: 0,
            fees: 0,
            reserve: credit.principal,
            claims: BTreeMap::new(),
            cursor: 0,
            activity: [0; 32],
        })
    }
    pub fn economic_bytes(&self) -> Vec<u8> {
        let mut b = b"KPI/offline/synthetic-economic-state/v1".to_vec();
        for id in &self.ids {
            b.extend(id)
        }
        b.extend((self.tree.leaves.len() as u64).to_le_bytes());
        for leaf in &self.tree.leaves {
            b.extend(leaf)
        }
        b.extend((self.allowed.len() as u64).to_le_bytes());
        for a in &self.allowed {
            b.extend(a)
        }
        b.extend((self.spent.len() as u64).to_le_bytes());
        for nf in &self.spent {
            b.extend(nf)
        }
        b.extend(self.deposit.tx);
        b.extend(self.deposit.index.to_le_bytes());
        b.extend(self.deposit.descriptor);
        b.extend(self.deposit.key);
        b.push(u8::from(self.credited));
        for n in [
            self.pending,
            self.private,
            self.exits,
            self.fees,
            self.reserve,
        ] {
            b.extend(n.to_le_bytes())
        }
        b.extend((self.claims.len() as u64).to_le_bytes());
        for (id, (n, s)) in &self.claims {
            b.extend(id);
            b.extend(n.to_le_bytes());
            b.extend(s.version.to_le_bytes());
            b.extend((s.bytes.len() as u32).to_le_bytes());
            b.extend(&s.bytes)
        }
        b
    }
    pub fn commitment(&self) -> [u8; 32] {
        let mut b = self.economic_bytes();
        b.extend(self.cursor.to_le_bytes());
        b.extend(self.activity);
        hash(&b)
    }
    fn transition(&self, i: &Intent, auth: &[u8], receipt: &Receipt) -> Result<Self> {
        // Prior state is trusted synthetic fixture policy, never a value
        // supplied by this operation or extracted from the receipt journal.
        ensure!(i.ids == self.ids, "wrong immutable context/policy");
        let image = Digest::try_from(self.ids[7].as_slice())?;
        proof::verify(receipt, image, &i.journal(auth)?)?;
        ensure!(self.allowed.contains(&i.anchor), "anchor not allowed");
        ensure!(
            i.expiry.is_none_or(|e| self.cursor <= e),
            "expired operation"
        );
        ensure!(
            i.nf[0] != i.nf[1] && i.nf.iter().all(|nf| !self.spent.contains(nf)),
            "already spent nullifier"
        );
        capacity(self.tree.leaves.len() as u64, i.mode)?;
        let mut next = self.clone();
        match i.kind {
            0 => {
                ensure!(
                    !self.credited
                        && self.pending > 0
                        && i.deposit.as_ref() == Some(&self.deposit)
                        && i.principal == self.pending,
                    "deposit not pending/exact"
                );
                next.private = next
                    .private
                    .checked_add(self.pending)
                    .context("private ledger overflow")?;
                next.pending = 0;
                next.credited = true;
            }
            1 => {
                next.private = next
                    .private
                    .checked_sub(i.fee)
                    .context("private fee underflow")?;
            }
            2 => {
                let sum = i
                    .exited
                    .checked_add(i.fee)
                    .context("public principal overflow")?;
                next.private = next.private.checked_sub(sum).context("exit underflow")?;
                next.exits = next
                    .exits
                    .checked_add(i.exited)
                    .context("exit liability overflow")?;
            }
            _ => anyhow::bail!("unknown kind"),
        }
        next.fees = next
            .fees
            .checked_add(i.fee)
            .context("fee liability overflow")?;
        for (ordinal, principal, script) in [(0u8, i.exited, &i.exit), (1u8, i.fee, &i.fee_script)]
        {
            if principal > 0 {
                let mut id = b"KPI/offline/synthetic-claim/v1".to_vec();
                id.extend(&self.ids[1]);
                id.extend(self.cursor.to_le_bytes());
                id.extend(hash(&i.encode()?));
                id.push(ordinal);
                ensure!(
                    next.claims
                        .insert(
                            hash(&id),
                            (principal, script.clone().context("claim script")?)
                        )
                        .is_none(),
                    "duplicate claim"
                );
            }
        }
        next.spent.extend(i.nf);
        next.tree.append(i);
        next.allowed.insert(next.tree.root_path(None)?.0);
        next.reconcile()?;
        Ok(next)
    }
    pub fn reconcile(&self) -> Result<()> {
        let liabilities =
            self.pending as u128 + self.private as u128 + self.exits as u128 + self.fees as u128;
        ensure!(
            liabilities == self.reserve as u128,
            "synthetic backing/conservation"
        );
        ensure!(
            self.claims.values().map(|(n, _)| *n as u128).sum::<u128>()
                == self.exits as u128 + self.fees as u128,
            "claims/liabilities mismatch"
        );
        Ok(())
    }
    pub fn apply(
        &mut self,
        intent: &[u8],
        auth: &[u8],
        receipt: &Receipt,
    ) -> Result<(bool, String)> {
        let cursor = self
            .cursor
            .checked_add(1)
            .context("cursor overflow: atomic halt")?;
        let result = Intent::decode(intent).and_then(|i| self.transition(&i, auth, receipt));
        let (mut next, valid, reason) = match result {
            Ok(n) => (n, true, "accepted".to_owned()),
            Err(e) => (self.clone(), false, e.to_string()),
        };
        let mut activity = b"KPI/offline/synthetic-activity/v1".to_vec();
        activity.extend(self.activity);
        activity.extend(self.cursor.to_le_bytes());
        activity.extend(hash(intent));
        activity.extend(hash(auth));
        activity.extend(hash(&bincode::serialize(receipt)?));
        activity.push(u8::from(valid));
        next.cursor = cursor;
        next.activity = hash(&activity);
        *self = next;
        Ok((valid, reason))
    }
}
