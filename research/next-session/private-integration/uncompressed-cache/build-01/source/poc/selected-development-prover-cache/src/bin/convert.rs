//! One originating selected development key -> official uncompressed cache.
#[path = "../original_key.rs"]
mod original_key;
use ark_serialize::CanonicalSerialize;
use original_key::{Result, digest};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
    time::Instant,
};

fn save_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn main() -> Result<()> {
    let total = Instant::now();
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 {
        return Err("usage: convert ORIGINAL_SELECTION_JSON NEW_CACHE_FILE NEW_OUT".into());
    }
    let selection = Path::new(&args[1]);
    let cache = Path::new(&args[2]);
    let out = Path::new(&args[3]);
    fs::create_dir(out)?;
    let mut times = Map::<String, Value>::new();
    let pk = original_key::load(selection, &mut times)?;
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(cache)?;
    let started = Instant::now();
    let mut writer = BufWriter::new(file);
    pk.serialize_uncompressed(&mut writer)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    let mut file = writer.into_inner()?;
    fs::File::open(cache.parent().ok_or("cache parent")?)?.sync_all()?;
    times.insert(
        "official_uncompressed_serialize_fsync_seconds".into(),
        started.elapsed().as_secs_f64().into(),
    );
    let bytes = file.metadata()?.len();
    if bytes != 2_012_802_352 {
        return Err("unexpected official uncompressed cache length".into());
    }
    let started = Instant::now();
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut read = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        read += n as u64;
    }
    if read != bytes {
        return Err("cache full hash length mismatch".into());
    }
    let cache_sha = hex::encode(hasher.finalize());
    times.insert(
        "complete_cache_sha256_seconds".into(),
        started.elapsed().as_secs_f64().into(),
    );
    let vk = kpi_future_private_payment::verification_key(&pk)?;
    if &vk != original_key::SELECTED_VK {
        return Err("conversion fixed VK mismatch".into());
    }
    drop(pk);
    let report = json!({"schema":"kpx2-uncompressed-conversion-provenance/v1",
        "classification":"PUBLIC_SYNTHETIC_DO_NOT_FUND","format":"arkworks0.6-uncompressed",
        "originating_selection_sha256":original_key::SELECTION_SHA256,"originating_pk_sha256":original_key::PK_SHA256,
        "vk_sha256":digest(&vk),"cache_sha256":cache_sha,"cache_bytes":bytes,
        "cache_local_only_path":cache.canonicalize()?.to_string_lossy(),"phase_wall_seconds":times,
        "total_seconds":total.elapsed().as_secs_f64(),"root_selected_cache_authority":false,
        "trust":"Derived exact selected PK after retained checked baseline; this report does not select the cache.",
        "setup_or_proof_generated":false});
    save_new(
        &out.join("conversion-provenance.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    save_new(&out.join("verification-key.bin"), &vk)?;
    fs::File::open(out)?.sync_all()?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
