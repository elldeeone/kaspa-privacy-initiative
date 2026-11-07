#![no_main]
risc0_zkvm::guest::entry!(main);
#[cfg(feature="offline")]
const AUTH_IMAGE:&[u8;32]=include_bytes!("../../pins/authorization-image.bin");
#[cfg(feature="testnet")]
const AUTH_IMAGE:&[u8;32]=include_bytes!("../../testnet-pins/authorization-image.bin");
fn main(){
 let mut method=[0u32;1];risc0_zkvm::guest::env::read_slice(&mut method);
 let mut size=[0u32;1];risc0_zkvm::guest::env::read_slice(&mut size);
 let mut bytes=vec![0u8;size[0] as usize];risc0_zkvm::guest::env::read_slice(&mut bytes);
 use bincode::Options;
 let input:kpi_batched_payment_core::Input=bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes().deserialize(&bytes).unwrap();
 let output=match method[0]{
 0=>kpi_batched_payment_core::execute(&input).unwrap(),
 1=>{let journal=kpi_batched_payment_core::authorization_journal(&input).unwrap();
 kpi_batched_payment_core::execute_with_certificate(&input,&journal,|j|{
  risc0_zkvm::guest::env::verify(risc0_zkvm::sha::Digest::from_bytes(*AUTH_IMAGE),j).map_err(|e|e.to_string())
 }).unwrap()},
 _=>panic!("unknown verification method")};
 risc0_zkvm::guest::env::commit_slice(&output.journal);
}
