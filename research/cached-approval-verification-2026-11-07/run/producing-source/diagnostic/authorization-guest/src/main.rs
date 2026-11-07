#![no_main]
risc0_zkvm::guest::entry!(main);
fn main(){
 let mut size=[0u32;1];risc0_zkvm::guest::env::read_slice(&mut size);
 let mut bytes=vec![0u8;size[0] as usize];risc0_zkvm::guest::env::read_slice(&mut bytes);
 use bincode::Options;
 let input:kpi_batched_payment_core::Input=bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes().deserialize(&bytes).unwrap();
 let journal=kpi_batched_payment_core::authorize_packet(&input).unwrap();
 risc0_zkvm::guest::env::commit_slice(&journal);
}
