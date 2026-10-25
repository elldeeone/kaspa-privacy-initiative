//! Public synthetic profile and CLI refusal controls. No setup or wallet input.
#![cfg(feature = "prover")]
use kpi_local_private_payment_relation::*;
use std::{
    fs,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const OLD_DOMAIN: H = [
    0xbe, 0x2c, 0x62, 0xd1, 0xca, 0x87, 0x14, 0xbc, 0xce, 0x51, 0x65, 0x9d, 0xfe, 0x12, 0xc1, 0x90,
    0xac, 0xc4, 0x22, 0x34, 0xc6, 0xb1, 0xc2, 0xff, 0x3c, 0x0f, 0xa6, 0x0c, 0xf6, 0x53, 0xe4, 0x80,
];

#[test]
fn domain_and_all_statement_tags_are_fresh_and_exact() {
    assert_eq!(
        DOMAIN,
        hash(&[b"KaspaPrivacyInitiative/local-native-kas-payment/1x2/v1/2026-10-25"])
    );
    assert_ne!(DOMAIN, OLD_DOMAIN);
    let (spend, output) = circuit::fixture();
    let exit = circuit::exit_fixture();
    assert_eq!(&spend.statement.bytes()[..8], b"KPXASP01");
    assert_eq!(&output.statement.bytes()[..8], b"KPXAOU01");
    assert_eq!(&exit.statement.bytes()[..8], b"KPXAEX01");
    let mut old_spend = spend.statement.bytes();
    old_spend[..8].copy_from_slice(b"KPX8SP01");
    assert_eq!(SpendStatement::parse(&old_spend), Err(Error::Encoding));
    let mut old_output = output.statement.bytes();
    old_output[..8].copy_from_slice(b"KPX8OU01");
    assert_eq!(OutputStatement::parse(&old_output), Err(Error::Encoding));
    let mut old_exit = exit.statement.bytes();
    old_exit[..8].copy_from_slice(b"KPX8EX01");
    assert_eq!(ExitStatement::parse(&old_exit), Err(Error::Encoding));
    old_spend = spend.statement.bytes();
    old_spend[8..40].copy_from_slice(&OLD_DOMAIN);
    assert_eq!(SpendStatement::parse(&old_spend), Err(Error::Domain));
    old_output = output.statement.bytes();
    old_output[8..40].copy_from_slice(&OLD_DOMAIN);
    assert_eq!(OutputStatement::parse(&old_output), Err(Error::Domain));
    old_exit = exit.statement.bytes();
    old_exit[8..40].copy_from_slice(&OLD_DOMAIN);
    assert_eq!(ExitStatement::parse(&old_exit), Err(Error::Domain));
}

#[test]
fn cli_refuses_invalid_selected_parameters_before_reading_stdin() {
    let base = std::env::temp_dir().join(format!("kpxa-public-cli-refusal-{}", std::process::id()));
    fs::create_dir(&base).unwrap();
    let manifest = base.join("manifest.json");
    // A fully pinned but malformed public manifest must fail before stdin.
    let raw = b"{}";
    fs::write(&manifest, raw).unwrap();
    let (spend, output) = circuit::fixture();
    let exit = circuit::exit_fixture();
    for role in ["spend", "output", "exit"] {
        let statement = match role {
            "spend" => hex::encode(spend.statement.bytes()),
            "output" => hex::encode(output.statement.bytes()),
            _ => hex::encode(exit.statement.bytes()),
        };
        let mut child = Command::new(env!("CARGO_BIN_EXE_kpi-local-private-payment-relation"))
            .args([
                format!("prove-{role}"),
                "--pk".into(),
                base.join("unused.pk").display().to_string(),
                "--pk-sha256".into(),
                "00".repeat(32),
                "--manifest".into(),
                manifest.display().to_string(),
                "--manifest-sha256".into(),
                hex::encode(hash(&[raw])),
                "--statement".into(),
                statement,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Keep stdin open with no input: attempting to read a witness blocks.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("CLI read stdin before refusing invalid parameters");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"local-private-operation-refused\n");
    }
    fs::remove_dir_all(base).unwrap();
}
