#[cfg(feature = "s7-native-policy")]
fn main() -> kpi_shared_pool::Result<()> {
    use kpi_shared_pool::{s7_lifecycle::native as n, two_input::tree::PublicState};
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err(
            "usage: kpi_s7_policy_shape POLICY.json OUTPUT_DIRECTORY (source-shape only)".into(),
        );
    }
    let policy: n::Policy = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    policy.validate()?;
    let state = PublicState::initial([1; 32])?;
    let bytes = n::state_bytes(&state)?;
    let code = n::redeem(&policy, &bytes)?;
    let signature = n::signature(&[0; 128], &code)?;
    assert_eq!(code.len(), n::REDEEM_LEN);
    assert_eq!(signature.len(), n::WITNESS_LEN);
    assert_eq!(&signature[..2], &[0x4c, 0x80]);
    assert_eq!(&signature[130..133], &[0x4d, 0, 0x60]);
    assert_eq!(
        &code[..34],
        &[&[0x20][..], &policy.pool_id, &[0x75]].concat()
    );
    assert_eq!(&code[36..141], &bytes);
    let mut wrong = policy.clone();
    wrong.outer.id[0] ^= 1;
    assert!(wrong.validate().is_err());
    let mut wrong = policy.clone();
    wrong.outer.root[0][0] ^= 1;
    assert!(wrong.validate().is_err());
    let mut wrong = policy.clone();
    wrong.outer.post[0] ^= 1;
    assert!(wrong.validate().is_err());
    let mut wrong = policy.clone();
    wrong.pool_id = wrong.domain;
    assert!(wrong.validate().is_err());
    let mut wrong_state = bytes;
    wrong_state[0] = 6;
    assert!(n::redeem(&policy, &wrong_state).is_err());
    let out = std::path::Path::new(&args[2]);
    std::fs::create_dir_all(out)?;
    std::fs::write(out.join("source-shape-redeem.bin"), &code)?;
    let report = serde_json::json!({
      "scope":"SOURCE_SHAPE_ONLY; no accepted state, genuine proof, native execution or fresh profile qualification",
      "unpadded_redeem_bytes":n::emitted_length(&policy,&bytes)?,
      "redeem_bytes":code.len(),"script_sig_bytes":signature.len(),
      "ordinary_payload_bytes":n::ORDINARY_LEN,"paired_payload_bytes":n::PAIRED_LEN,
      "declared_budget":n::BUDGET,"shape_controls_passed":5,
      "redeem_sha256":hex::encode(kpi_shared_pool::protocol::hash(&code)),
      "policy_sha256":hex::encode(kpi_shared_pool::protocol::hash(&std::fs::read(&args[1])?))
    });
    std::fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
#[cfg(not(feature = "s7-native-policy"))]
fn main() {
    eprintln!("requires --features s7-native-policy");
    std::process::exit(2);
}
