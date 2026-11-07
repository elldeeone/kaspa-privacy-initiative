#[allow(dead_code)]
mod bench {
    include!("../../../reusable-withdrawal-approvals/host/src/legacy_bench.rs");
    include!("../../../reusable-withdrawal-approvals/host/src/experiment.rs");
    include!("diagnostic.rs");
    include!("flow-support.rs");
    include!("flow.rs");
    include!("live.rs");
    include!("replay.rs");
}

mod actor;
#[cfg(feature = "round-agreement")]
#[path = "../../../separated-withdrawal/host/src/agreement.rs"]
mod agreement;
#[cfg(feature = "round-agreement")]
#[path = "../../../separated-withdrawal/host/src/timed.rs"]
mod timed;
#[cfg(feature = "round-agreement")]
fn read(path: &std::path::Path) -> prover::Result<serde_json::Value> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/circuit.rs"]
mod circuit;
mod controls;
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/native.rs"]
mod native;
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/prover.rs"]
mod original_prover;
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/proof.rs"]
mod proof;
mod prover;

#[allow(dead_code)]
mod anonymous;

#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/receipt_script.rs"]
mod receipt_script;
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/registration.rs"]
mod registration;
fn main() -> prover::Result<()> {
    use std::path::Path;
    let args = std::env::args().collect::<Vec<_>>();
    let path = |index: usize| {
        args.get(index)
            .map(Path::new)
            .ok_or("missing path argument")
    };
    match args.get(1).map(String::as_str) {
        Some("fresh-trial") => bench::fresh_trial(path(2)?, path(3)?, path(4)?)?,
        Some("fresh-board-trial") => bench::fresh_board_trial(path(2)?, path(3)?, path(4)?)?,
        Some("ordinary-test-funding") => {
            bench::ordinary_test_funding(path(2)?, path(3)?, path(4)?, path(5)?)?
        }
        #[cfg(feature = "round-agreement")]
        Some("bundle-build") => bench::bundle_build(path(2)?, path(3)?, path(4)?, path(5)?)?,
        Some("sweep-prior-test-payouts") => bench::sweep_prior_test_payouts(path(2)?, path(3)?, path(4)?, path(5)?)?,
        Some("live-build") => {
            bench::live_build(path(2)?, args.get(3).ok_or("missing phase")?, path(4)?)?
        }
        Some("live-accept") => {
            bench::live_accept(path(2)?, args.get(3).ok_or("missing phase")?, path(4)?)?
        }
        Some("live-approvals") => bench::live_approvals(path(2)?, path(3)?)?,
        Some("live-recovery") => bench::live_recovery(path(2)?, path(3)?)?,
        Some("reclaim-build") => bench::reclaim_build(path(2)?, path(3)?)?,
        Some("reclaim-accept") => bench::reclaim_accept(path(2)?, path(3)?)?,
        Some("sweep-reclaimed-test-kas") => bench::sweep_reclaimed_test_kas(path(2)?, path(3)?, path(4)?, path(5)?)?,
        Some("actor") => actor::run(path(2)?, path(3)?)?,
        Some("serve") => anonymous::serve(
            path(2)?,
            path(3)?,
            path(4)?,
            args.get(5).ok_or("missing port")?.parse()?,
        )?,
        #[cfg(feature = "round-agreement")]
        Some("serve-board") => timed::serve(
            path(2)?, path(3)?, path(4)?,
            args.get(5).ok_or("missing port")?.parse()?, "board", Some(path(6)?),
        )?,
        Some("combined") => bench::run_combined(path(2)?, path(3)?, path(4)?, path(5)?)?,
        Some("verify-registration") => anonymous::verify_logs(path(2)?, path(3)?, path(4)?)?,
        Some("replay-live") => bench::replay_live(path(2)?,path(3)?)?,
        Some("replay-combined") => bench::replay_combined(path(2)?, path(3)?)?,
        Some("reference-recovery") => bench::reference_recovery(path(2)?)?,
        Some("cold-reference") => bench::cold_reference(path(2)?, path(3)?, path(4)?)?,
        Some("replay-diagnostic") => bench::replay_diagnostic(path(2)?, path(3)?)?,
        Some("unresolved-control") => {
            prover::unresolved_control(path(2)?, path(3)?, path(4)?, path(5)?)?
        }
        Some("conditional-native") => bench::conditional_native(path(2)?, path(3)?, path(4)?)?,
        Some("receipt-controls") => prover::receipt_controls(path(2)?, path(3)?, path(4)?)?,
        Some("native-controls") => bench::native_controls(path(2)?, path(3)?, path(4)?)?,
        Some("controls") => controls::run(path(2)?, path(3)?)?,
        Some("wrap") => {
            let program = risc0_binfmt::ProgramBinary::new(
                &std::fs::read(path(2)?)?,
                risc0_zkos_v1compat::V1COMPAT_ELF,
            )
            .encode();
            prover::write(path(3)?, &program)?;
            let image = risc0_zkvm::compute_image_id(&program)?;
            if let Some(pin) = args.get(4) {
                prover::write(Path::new(pin), image.as_bytes())?;
            }
            println!("{image}");
        }
        Some("cases") => bench::prepare_cases(path(2)?, path(3)?, path(4)?)?,
        Some("direct") => {
            prover::direct(path(2)?, path(3)?, path(4)?)?;
        }
        Some("authorize") => {
            prover::authorize(path(2)?, path(3)?, path(4)?)?;
        }
        Some("settle") => {
            prover::settle(path(2)?, path(3)?, path(4)?, path(5)?, path(6)?)?;
        }
        Some("native") => bench::check_case(path(2)?, path(3)?, path(4)?)?,
        _ => {
            return Err(
                "see poc/cached-approval-verification/README.md for finite research commands"
                    .into(),
            );
        }
    }
    Ok(())
}
