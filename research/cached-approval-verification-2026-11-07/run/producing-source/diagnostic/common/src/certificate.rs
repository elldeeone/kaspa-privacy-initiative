use crate::*;
use std::collections::BTreeSet;

/// Commits proof validity only. Current state acceptance is deliberately absent.
pub fn authorization_journal(input:&Input)->Result<Vec<u8>,String>{
 ensure(input.state.pool!=[0;32],"certificate pool")?;
 ensure(input.state.wallet_vk==include_bytes!("../../../reusable-withdrawal-approvals/pins/vk-compressed.bin"),"certificate pinned verifier")?;
 ensure(hash(&input.state.wallet_vk)==input.state.ledger.verifier,"certificate verifier identity")?;
 ensure((1..=32).contains(&input.packet.operations.len()),"certificate operation count")?;
 let mut j=hash(&[b"KPI-cached-wallet-proof-validity-v1\0".as_slice(),&domain()].concat()).to_vec();
 j.extend(input.state.pool);j.extend(input.state.ledger.verifier);j.extend(hash(&input.packet.bytes()));Ok(j)
}
pub fn authorize_packet(input:&Input)->Result<Vec<u8>,String>{
 let journal=authorization_journal(input)?;
 let verifier=Verifier::new(&input.state.wallet_vk)?;
 for op in &input.packet.operations{verifier.verify(op)?;}
 Ok(journal)
}
struct CertifiedVerifier{id:H,operations:BTreeSet<H>}
impl ProofVerifier for CertifiedVerifier{
 fn id(&self)->H{self.id}
 fn verify(&self,op:&Operation)->Result<(),String>{
  op.check_public(self.id)?;
  ensure(self.operations.contains(&hash(&bincode::serialize(op).map_err(|e|e.to_string())?)),"operation absent from verified certificate")
 }
}
/// The pinned guest supplies env::verify, which creates an assumption. The host
/// must supply the actual Proven receipt and resolve it. A caller-provided bool,
/// Claim-only or unresolved receipt is NOT native settlement authority.
pub fn execute_with_certificate<F>(input:&Input,journal:&[u8],verify_certificate:F)->Result<Output,String>
where F:FnOnce(&[u8])->Result<(),String>{
 ensure(journal==authorization_journal(input)?,"certificate exact journal")?;
 verify_certificate(journal)?;
 let operations=input.packet.operations.iter().map(|op|bincode::serialize(op).map(|b|hash(&b)).map_err(|e|e.to_string())).collect::<Result<BTreeSet<_>,_>>()?;
 let verifier=CertifiedVerifier{id:input.state.ledger.verifier,operations};
 execute_with_verifier(input,&verifier)
}
