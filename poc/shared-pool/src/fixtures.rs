use kpi_shared_pool::{Result, circuit::SpendCircuit, native, protocol::*};
pub fn sample() -> Result<SpendCircuit> {
    let d = hash(b"KPI/shared-pool/unfunded-fixture/v2");
    let a = Wallet {
        spending: [1; 32],
        viewing: [2; 32],
        native: [3; 32],
    };
    let b = Wallet {
        spending: [4; 32],
        viewing: [5; 32],
        native: [6; 32],
    };
    let input = a.receive(&d).note(RESERVE)?;
    let fee = native::fee_for(1)?;
    let outputs = [
        b.receive(&d).note(PAYMENT)?,
        a.receive(&d).note(RESERVE - PAYMENT - fee)?,
    ];
    let old = State {
        commitments: vec![input.commitment(&d)],
        nullifiers: vec![],
    };
    let new = old.spend(&d, &a.spending, &input, &outputs)?;
    let transition = Transition {
        domain: d,
        old,
        txid: [7; 32],
        index: 0,
        reserve_in: RESERVE,
        reserve_out: RESERVE - fee,
        payout: 0,
        payout_spk: vec![0; 36],
        deposit: vec![0; 84],
        payload: payload(1, &new, &[outputs[0].encrypt(&d)?, outputs[1].encrypt(&d)?])?,
    };
    Ok(SpendCircuit {
        public: transition.inputs(),
        transition,
        secret: a.spending,
        input,
        outputs,
        fee,
    })
}
