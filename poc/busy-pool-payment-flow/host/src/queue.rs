//! Local coordinator scheduling only. This confers no authority over the bank.
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Withdrawal,
    Payment,
}
#[derive(Clone, Debug)]
pub struct Job<T> {
    ticket: u64,
    pub kind: Kind,
    pub payload: T,
}
pub struct Queue<T> {
    next: u64,
    pending: BTreeMap<u64, Job<T>>,
    active: BTreeSet<u64>,
}
impl<T> Default for Queue<T> {
    fn default() -> Self {
        Self {
            next: 0,
            pending: BTreeMap::new(),
            active: BTreeSet::new(),
        }
    }
}
impl<T> Queue<T> {
    pub fn push(&mut self, kind: Kind, payload: T) -> Result<(), &'static str> {
        let ticket = self.next;
        self.next = self.next.checked_add(1).ok_or("ticket exhausted")?;
        self.pending.insert(
            ticket,
            Job {
                ticket,
                kind,
                payload,
            },
        );
        Ok(())
    }
    /// Freeze a work item. Later requests cannot alter the returned job's payload.
    pub fn lease(&mut self, max_payments: usize) -> Result<Vec<Job<T>>, &'static str> {
        if !self.active.is_empty() {
            return Err("coordinator already proving a work item");
        }
        if max_payments == 0 || max_payments > 32 {
            return Err("payment batch limit");
        }
        let Some((_, first)) = self.pending.first_key_value() else {
            return Ok(vec![]);
        };
        let kind = first.kind;
        let limit = if kind == Kind::Withdrawal {
            1
        } else {
            max_payments
        };
        let tickets = self
            .pending
            .iter()
            .take_while(|(_, j)| j.kind == kind)
            .take(limit)
            .map(|(t, _)| *t)
            .collect::<Vec<_>>();
        Ok(tickets
            .into_iter()
            .map(|t| {
                self.active.insert(t);
                self.pending.remove(&t).unwrap()
            })
            .collect())
    }
    /// A stale bank requires new proving, not a new request age or owner consent.
    pub fn retry(&mut self, jobs: Vec<Job<T>>) -> Result<(), &'static str> {
        if jobs.iter().map(|j| j.ticket).collect::<BTreeSet<_>>() != self.active
            || jobs.len() != self.active.len()
        {
            return Err("retry must match complete active work item");
        }
        for j in jobs {
            self.pending.insert(j.ticket, j);
        }
        self.active.clear();
        Ok(())
    }
    /// Call only after the complete corresponding native transaction was accepted.
    pub fn accepted(&mut self, jobs: &[Job<T>]) -> Result<(), &'static str> {
        if jobs.iter().map(|j| j.ticket).collect::<BTreeSet<_>>() != self.active
            || jobs.len() != self.active.len()
            || jobs.is_empty()
        {
            return Err("accept must match complete active work item");
        }
        self.active.clear();
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_retry_keeps_age_and_frozen_payload() {
        let mut q = Queue::default();
        q.push(Kind::Withdrawal, vec![42u8]).unwrap();
        let work = q.lease(32).unwrap();
        q.push(Kind::Payment, vec![1]).unwrap();
        q.push(Kind::Payment, vec![2]).unwrap();
        assert!(q.lease(32).is_err());
        assert_eq!(work[0].payload, vec![42]);
        q.retry(work).unwrap();
        let work = q.lease(32).unwrap();
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].kind, Kind::Withdrawal);
        assert_eq!(work[0].ticket, 0);
        q.accepted(&work).unwrap();
        let batch = q.lease(32).unwrap();
        assert_eq!(
            batch.iter().map(|j| j.payload[0]).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }
    #[test]
    fn payment_batch_never_passes_older_withdrawal() {
        let mut q = Queue::default();
        for (k, p) in [
            (Kind::Payment, 1),
            (Kind::Payment, 2),
            (Kind::Withdrawal, 3),
            (Kind::Payment, 4),
        ] {
            q.push(k, p).unwrap();
        }
        let batch = q.lease(32).unwrap();
        assert_eq!(batch.len(), 2);
        q.accepted(&batch).unwrap();
        let next = q.lease(32).unwrap();
        assert_eq!(next[0].payload, 3);
    }
    #[test]
    fn partial_accept_duplicate_retry_and_invalid_batch_fail() {
        let mut q = Queue::default();
        q.push(Kind::Payment, 1).unwrap();
        q.push(Kind::Payment, 2).unwrap();
        assert!(q.lease(0).is_err());
        assert!(q.lease(33).is_err());
        let work = q.lease(32).unwrap();
        assert!(q.accepted(&work[..1]).is_err());
        assert!(q.retry(work[..1].to_vec()).is_err());
        q.retry(work.clone()).unwrap();
        assert!(q.retry(work).is_err());
    }
}
