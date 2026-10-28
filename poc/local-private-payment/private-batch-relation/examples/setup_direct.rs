//! Fresh stock Ark parameters from restricted PUBLIC source. No private witness.
//! Standard setup toxic waste exists transiently inside stock Ark; this local
//! research setup is not a multiparty ceremony or production-safety evidence.
#[path = "qualify_joint_core.rs"]
mod qualifier;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, R1CS_PREDICATE_LABEL, SynthesisError,
};
use ark_serialize::CanonicalSerialize;
use kpi_private_batch_relation::joined_source::JoinedSourceCircuit;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Instant,
};
struct CheckedSource {
    source: JoinedSourceCircuit,
    fingerprint: String,
    rows: usize,
    variables: usize,
}
impl ConstraintSynthesizer<Fr> for CheckedSource {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        self.source.generate_with_shape(cs.clone())?;
        cs.finalize();
        let mut groups = cs.to_matrices()?;
        if groups.len() != 1 {
            return Err(SynthesisError::Unsatisfiable);
        }
        let r = auth::join::R1cs {
            instances: cs.num_instance_variables(),
            witnesses: cs.num_witness_variables(),
            matrices: groups
                .remove(R1CS_PREDICATE_LABEL)
                .ok_or(SynthesisError::Unsatisfiable)?
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
        };
        let fp = auth::join::fingerprint(&r).map_err(|_| SynthesisError::Unsatisfiable)?;
        if r.instances != 3
            || r.constraints() != self.rows
            || r.variables().map_err(|_| SynthesisError::Unsatisfiable)? != self.variables
            || fp != self.fingerprint
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        println!(
            "{}",
            json!({"stage":"stock_setup_actual_source_rows_checked","canonical_r1cs_fingerprint":fp,"rows":r.constraints(),"variables":self.variables,"private_assignment":false})
        );
        let _ = io::stdout().flush();
        Ok(())
    }
}
struct HashWriter<W> {
    inner: W,
    hash: Sha256,
    bytes: u64,
}
impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(b)?;
        self.hash.update(&b[..n]);
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("public serialization byte overflow"))?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
fn compressed_pk(pk: &ProvingKey<Bn254>, path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut gzip = Command::new("/usr/bin/gzip")
        .args(["-1", "-n", "-c"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = gzip.stdout.take().ok_or("gzip stdout")?;
    let reader = thread::spawn(move || -> io::Result<(u64, String)> {
        let mut sink = HashWriter {
            inner: BufWriter::new(file),
            hash: Sha256::new(),
            bytes: 0,
        };
        let mut buffer = [0; 65536];
        loop {
            let n = stdout.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            sink.write_all(&buffer[..n])?;
        }
        sink.flush()?;
        sink.inner.get_ref().sync_all()?;
        Ok((sink.bytes, hex::encode(sink.hash.finalize())))
    });
    let stdin = gzip.stdin.take().ok_or("gzip stdin")?;
    let mut raw = HashWriter {
        inner: BufWriter::new(stdin),
        hash: Sha256::new(),
        bytes: 0,
    };
    let serialized = pk.serialize_compressed(&mut raw);
    let flushed = raw.flush();
    let bytes = raw.bytes;
    let hash = hex::encode(raw.hash.finalize());
    drop(raw.inner);
    let status = gzip.wait()?;
    let (container_bytes, container_hash) = reader.join().map_err(|_| "gzip reader panic")??;
    serialized?;
    flushed?;
    if !status.success() {
        return Err("gzip process failed".into());
    }
    Ok(
        json!({"file":"AGGREGATE-PK.bin.gz","canonical_encoding":"stock Ark0.6 ProvingKey<Bn254>::serialize_compressed","uncompressed_sha256":hash,"uncompressed_bytes":bytes,"compressed_sha256":container_hash,"compressed_bytes":container_bytes,"single_gzip_member":true}),
    )
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 9 {
        return Err("usage: setup_direct PUBLIC-CONTEXT-HISTORY.json PUBLIC-SIGNATURE-MATRIX.json MATRIX-SHA MAP-SHA EXPECTED-R1CS-FINGERPRINT EXPECTED-ROWS EXPECTED-VARIABLES SETUP-SOURCE-SHA FRESH-OUTPUT".into());
    }
    let output = PathBuf::from(&args[8]);
    fs::create_dir(&output)?;
    let started = Instant::now();
    let v: Value = serde_json::from_slice(&fs::read(&args[0])?)?;
    let context = qualifier::context(
        hex::decode(v["context_hex"].as_str().ok_or("public context")?)?
            .try_into()
            .map_err(|_| "public context length")?,
    );
    let signature = auth::interchange::signature_matrix(&fs::read(&args[1])?, &args[2], &args[3])?;
    let source = JoinedSourceCircuit::from_public_context(
        context.clone(),
        core::array::from_fn(|_| signature.clone()),
    )?;
    println!(
        "{}",
        json!({"stage":"fresh_stock_ark_setup_start","source_sha256":args[7],"expected_r1cs_fingerprint":args[4],"entropy":"rand0.8.5 OsRng","seed_or_trapdoor_output":false})
    );
    io::stdout().flush()?;
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        CheckedSource {
            source,
            fingerprint: args[4].clone(),
            rows: args[5].parse()?,
            variables: args[6].parse()?,
        },
        &mut rand::rngs::OsRng,
    )?;
    if pk.vk.gamma_abc_g1.len() != 3 {
        return Err("public slots changed".into());
    }
    let canonical_bytes = pk.serialized_size(ark_serialize::Compress::Yes);
    println!(
        "{}",
        json!({"stage":"stock_parameters_generated","elapsed_seconds":started.elapsed().as_secs_f64(),"canonical_pk_bytes":canonical_bytes,"a_query":pk.a_query.len(),"b_g1_query":pk.b_g1_query.len(),"b_g2_query":pk.b_g2_query.len(),"h_query":pk.h_query.len(),"l_query":pk.l_query.len()})
    );
    io::stdout().flush()?;
    let mut vk = Vec::new();
    pk.vk.serialize_compressed(&mut vk)?;
    if vk.len() != 328 {
        return Err("VK ABI changed".into());
    }
    let vk_sha = hex::encode(Sha256::digest(&vk));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("AGGREGATE-VK.bin"))?;
    file.write_all(&vk)?;
    file.sync_all()?;
    let pk_receipt = compressed_pk(&pk, &output.join("AGGREGATE-PK.bin.gz"))?;
    if pk_receipt["uncompressed_bytes"].as_u64() != Some(canonical_bytes as u64) {
        return Err("canonical PK byte count changed".into());
    }
    let manifest = json!({"schema":"kpi-stock-financial-aggregate-setup/v1","classification":"FRESH_LOCAL_RESEARCH_SETUP_NOT_CEREMONY_OR_FINANCIAL_ACCEPTANCE","role":"Aggregate","domain_hex32":hex::encode(context.profile.domain),"wallet_profile_hex32":hex::encode(context.profile.wallet_profile),"pool_lineage_hex32":hex::encode(context.profile.pool_lineage),"setup_source_sha256":args[7],"canonical_r1cs_fingerprint":args[4],"num_constraints":args[5].parse::<usize>()?,"model_variables":args[6].parse::<usize>()?,"num_instance_slots":3,"original_signature_matrix_sha256":args[2],"original_signature_mapping_sha256":args[3],"entropy":"rand0.8.5 OsRng; no seed or trapdoor serialized","pk":pk_receipt,"vk":{"file":"AGGREGATE-VK.bin","bytes":vk.len(),"sha256":vk_sha},"public_prefix_policy":"two SHA limbs derived privately; release only after checked global validity","aggregate_proof_generated":false,"role_manifest_selected":false,"native_financial_acceptance":false});
    let raw = serde_json::to_vec_pretty(&manifest)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("PUBLIC-AGGREGATE-PARAMS.json"))?;
    file.write_all(&raw)?;
    file.sync_all()?;
    fs::File::open(&output)?.sync_all()?;
    println!(
        "{}",
        json!({"stage":"fresh_stock_setup_artifacts_complete","elapsed_seconds":started.elapsed().as_secs_f64(),"output":output,"vk_sha256":vk_sha,"canonical_pk_bytes":canonical_bytes,"setup_manifest_sha256":hex::encode(Sha256::digest(raw)),"aggregate_proof_or_financial_acceptance":false})
    );
    Ok(())
}
