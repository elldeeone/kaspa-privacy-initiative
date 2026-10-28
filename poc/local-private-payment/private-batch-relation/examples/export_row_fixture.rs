//! Tiny PUBLIC canonical transport fixture, including zero/duplicate terms.
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use auth::join::R1cs;
use kpi_private_batch_relation::row_transport;
use serde_json::json;
use sha2::Digest;
use std::{fs, path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::args().nth(1).ok_or("fresh output directory")?);
    fs::create_dir(&root)?;
    let cs = R1cs {
        instances: 3,
        witnesses: 2,
        matrices: [
            vec![vec![(Fr::ONE, 4), (Fr::ZERO, 0), (-Fr::ONE, 4)]],
            vec![vec![]],
            vec![vec![(Fr::from(9u64), 2)]],
        ],
    };
    let names = ["A.r1cs.bin.gz", "B.r1cs.bin.gz", "C.r1cs.bin.gz"];
    let mut axes = Vec::new();
    let mut hash = row_transport::fingerprint_start(&cs)?;
    for axis in 0..3 {
        let r =
            row_transport::gzip_axis(&cs, axis, Some(&root.join(names[axis])), Some(&mut hash))?;
        axes.push(json!({"axis":axis,"file":names[axis],"uncompressed_bytes":r.raw_bytes,"uncompressed_sha256":r.raw_sha256,"compressed_bytes":r.compressed_bytes,"compressed_sha256":r.compressed_sha256}));
    }
    let fp = hex::encode(hash.finalize());
    if fp != auth::join::fingerprint(&cs).map_err(|_| "matrix fingerprint")? {
        return Err("fingerprint differs".into());
    }
    fs::write(
        root.join("PUBLIC-ROWS-MANIFEST.json"),
        serde_json::to_vec_pretty(
            &json!({"schema":"kpi-r1cs-axis-gzip/v1","classification":"PUBLIC_TINY_TRANSPORT_CONTROL_NO_SETUP_PROOF","magic_ascii":"KPI_R1CS_AXIS_V1","field_decimal":Fr::MODULUS.to_string(),"num_instances":3,"num_witnesses":2,"num_constraints":1,"model_variables":5,"canonical_r1cs_fingerprint":fp,"axes":axes,"private_assignment_included":false}),
        )?,
    )?;
    println!("PUBLIC_ROW_FIXTURE_WRITTEN");
    Ok(())
}
