//! ADR0081 owner-local fixed-width handoff; no private-content commitment.
use ark_bn254::Fr;
use ark_serialize::CanonicalSerialize;
use std::io::Write;
pub const MAGIC: &[u8; 16] = b"KPB_OWNER_FR32V2";
pub const HEADER_BYTES: u64 = 32;
pub fn encoded_bytes(count: u64) -> Result<u64, &'static str> {
    if count == 0 { return Err("OWNER_FILE_COUNT"); }
    count.checked_mul(32).and_then(|n| n.checked_add(HEADER_BYTES)).ok_or("OWNER_FILE_COUNT")
}
pub fn write_owner_file<'a, W: Write, I: IntoIterator<Item=&'a Fr>>(
    output: &mut W, owner: u64, count: u64, values: I,
) -> Result<(), &'static str> {
    if owner > 2 { return Err("OWNER_FILE_ROLE"); }
    let _ = encoded_bytes(count)?;
    output.write_all(MAGIC).map_err(|_| "PRIVATE_OUTPUT")?;
    output.write_all(&owner.to_le_bytes()).map_err(|_| "PRIVATE_OUTPUT")?;
    output.write_all(&count.to_le_bytes()).map_err(|_| "PRIVATE_OUTPUT")?;
    let mut written = 0u64;
    for value in values {
        if written == count { return Err("OWNER_FILE_COUNT"); }
        let mut bytes = [0u8; 32];
        value.serialize_compressed(&mut bytes[..]).map_err(|_| "PRIVATE_OUTPUT")?;
        output.write_all(&bytes).map_err(|_| "PRIVATE_OUTPUT")?;
        written += 1;
    }
    if written != count { return Err("OWNER_FILE_COUNT"); }
    Ok(())
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn canonical_fixed_shape_and_refusals() {
        let a = [Fr::from(0u64), Fr::from(1u64), -Fr::from(1u64)];
        let b = [Fr::from(1u64); 3];
        let mut av = Vec::new(); let mut bv = Vec::new();
        write_owner_file(&mut av, 0, 3, &a).unwrap(); write_owner_file(&mut bv, 0, 3, &b).unwrap();
        assert_eq!(av.len(), 128); assert_eq!(av.len(), bv.len()); assert_ne!(av, bv);
        assert_eq!(&av[..16], MAGIC); assert_eq!(&av[24..32], &3u64.to_le_bytes());
        assert_eq!(&av[32..64], &[0; 32]); assert_eq!(av[64], 1); assert!(av[65..96].iter().all(|v| *v == 0));
        assert!(write_owner_file(&mut Vec::new(), 3, 3, &a).is_err());
        assert!(write_owner_file(&mut Vec::new(), 0, 2, &a).is_err());
        assert!(write_owner_file(&mut Vec::new(), 0, 4, &a).is_err());
        assert!(encoded_bytes(0).is_err()); assert!(encoded_bytes(u64::MAX).is_err());
        assert_eq!(encoded_bytes(2_635_409).unwrap(), 84_333_120);
    }
}
