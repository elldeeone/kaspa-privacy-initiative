//! Test adapter only: the pinned SDK's zero-padded keyed BLAKE3 domain hashes.
//! No transaction validation, proof generation, secret material or network I/O.
use std::io::{self, Read};
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(args.len(), 1);
    assert!(["PayloadDigest", "TransactionRest", "TransactionV1Id"].contains(&args[0].as_str()));
    let mut bytes = Vec::new();
    io::stdin().take(1_048_577).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 1_048_576);
    let mut key = [0u8; 32];
    key[..args[0].len()].copy_from_slice(args[0].as_bytes());
    println!("{}", blake3::keyed_hash(&key, &bytes).to_hex());
}
