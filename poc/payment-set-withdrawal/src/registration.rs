//! Real RFC9474 operations. This issuer can deny coordination, never spend KAS.
use crate::native::PRINCIPAL;
use crate::proof::{self, Authorization, Engine, H};
use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, DefaultRng, KeyPair, MessageRandomizer, PSS,
    PublicKey, Randomized, SecretKey, Sha384, Signature,
};
use rand::{RngCore, rngs::OsRng, seq::SliceRandom};
use serde_json::{Value, json};
use std::collections::BTreeSet;

type Pk = PublicKey<Sha384, PSS, Randomized>;
type Sk = SecretKey<Sha384, PSS, Randomized>;
const MODE: &[u8] = b"RFC9474-RSABSSA-SHA384-PSS-Randomized";
const TAG: &[u8] = b"KPI-output-registration-v1\0";
fn fresh() -> H {
    let mut h = [0; 32];
    OsRng.fill_bytes(&mut h);
    h
}
fn owner(i: usize) -> String {
    format!("owner-{}", i + 1)
}

#[derive(Clone)]
pub struct Config {
    pub round: H,
    pub issuer: H,
    pub pk: Pk,
}
impl Config {
    fn message(&self, key: &H) -> Vec<u8> {
        let mut m = TAG.to_vec();
        m.extend(self.round);
        m.extend(self.issuer);
        m.extend(PRINCIPAL.to_le_bytes());
        m.extend(key);
        m
    }
    fn parse(&self, msg: &[u8]) -> Result<H, String> {
        let start = TAG.len();
        if msg.len() != start + 104 || !msg.starts_with(TAG) {
            return Err("registration framing".into());
        }
        if msg[start..start + 32] != self.round
            || msg[start + 32..start + 64] != self.issuer
            || msg[start + 64..start + 72] != PRINCIPAL.to_le_bytes()
        {
            return Err("registration round/key/mode/denomination".into());
        }
        let key: H = msg[start + 72..].try_into().unwrap();
        secp256k1::XOnlyPublicKey::from_slice(&key).map_err(|_| "invalid native recipient key")?;
        Ok(key)
    }
    fn issue_context(&self, claim: &H, blind: &BlindMessage) -> H {
        let mut b = b"KPI-registration-eligibility-v1\0".to_vec();
        b.extend(self.round);
        b.extend(self.issuer);
        b.extend(claim);
        b.extend(&blind.0);
        proof::hash(&b)
    }
    fn register_identified(&self, owner: &str, message: &[u8]) -> Result<Value, String> {
        let key = self.parse(message)?;
        // Deliberately linkable control API: unlike redeem(), this call
        // actually receives the owner together with the plaintext output.
        Ok(json!({"owner":owner,"message":hex::encode(message),"recipientKey":hex::encode(key)}))
    }
}
struct Client {
    message: Vec<u8>,
    state: BlindingResult,
    signature: Option<Signature>,
}
pub struct Coordinator {
    pub config: Config,
    sk: Sk,
    claims: [H; 3],
    issued: BTreeSet<usize>,
    redeemed: BTreeSet<H>,
    pub events: Vec<Value>,
}
impl Coordinator {
    fn new(claims: [H; 3]) -> Self {
        let keys = KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 2048).unwrap();
        let mut id = MODE.to_vec();
        id.extend(keys.pk.to_der().unwrap());
        Self {
            config: Config {
                round: fresh(),
                issuer: proof::hash(&id),
                pk: keys.pk,
            },
            sk: keys.sk,
            claims,
            issued: BTreeSet::new(),
            redeemed: BTreeSet::new(),
            events: vec![],
        }
    }
    fn issue(
        &mut self,
        index: usize,
        blind: &BlindMessage,
        auth: &Authorization,
        engine: &Engine,
        anchor: H,
    ) -> Result<BlindSignature, String> {
        if index >= 3 || self.issued.contains(&index) {
            return Err("unknown/duplicate eligibility".into());
        }
        if auth.statement.nullifier != self.claims[index]
            || auth.statement.exit_destination
                != self.config.issue_context(&self.claims[index], blind)
            || auth.statement.anchor != anchor
            || auth.statement.kind != kpi_private_note_wallet::protocol::EXIT
            || auth.statement.exit_value != PRINCIPAL
            || !engine.verify(auth)
        {
            return Err("eligibility authorization".into());
        }
        let sig = self
            .sk
            .blind_sign(blind)
            .map_err(|e| format!("blind signing:{e}"))?;
        self.issued.insert(index);
        // Crucially: no client message, recipient, blinding factor or randomizer
        // is passed into this method or placed in its identified transcript.
        self.events.push(json!({"kind":"issue","owner":owner(index),"claim":hex::encode(auth.statement.nullifier),"context":hex::encode(auth.statement.exit_destination),"walletOperation":auth,"blindMessage":hex::encode(&blind.0),"blindSignature":hex::encode(&sig.0)}));
        Ok(sig)
    }
    fn redeem(
        &mut self,
        message: &[u8],
        signature: &Signature,
        randomizer: Option<MessageRandomizer>,
    ) -> Result<H, String> {
        if self.issued.len() != 3 {
            return Err("issuance barrier not reached".into());
        }
        let key = self.config.parse(message)?;
        if randomizer.is_none() {
            return Err("randomized mode required".into());
        }
        self.config
            .pk
            .verify(signature, randomizer, message)
            .map_err(|e| format!("credential verification:{e}"))?;
        if self.redeemed.contains(&key) {
            return Err("duplicate output registration".into());
        }
        self.redeemed.insert(key);
        self.events.push(json!({"kind":"redeem","message":hex::encode(message),"signature":hex::encode(&signature.0),"randomizer":hex::encode(randomizer.unwrap().0),"recipientKey":hex::encode(key),"valueSompi":PRINCIPAL}));
        Ok(key)
    }
}
pub struct RegistrationResult {
    pub candidate: Value,
    pub baseline: Value,
    pub controls: Vec<Value>,
    pub round: H,
    pub randomizers: [H; 3],
}
pub fn run(
    engine: &mut Engine,
    witnesses: &[kpi_private_note_wallet::circuit::Witness; 3],
    anchor: H,
    claims: [H; 3],
    keys: [H; 3],
) -> RegistrationResult {
    let mut controls = vec![];
    let mut service = Coordinator::new(claims);
    let config = service.config.clone();
    let mut clients = Vec::new();
    for key in &keys {
        let message = config.message(key);
        let state = config.pk.blind(&mut DefaultRng, &message).unwrap();
        clients.push(Client {
            message,
            state,
            signature: None,
        });
    }
    // The service cannot admit a redemption while eligibility is still being
    // issued. This prevents a trivial issue-A/redeem-A chronology.
    let early = service
        .redeem(
            &clients[0].message,
            &Signature(vec![0; 256]),
            clients[0].state.msg_randomizer,
        )
        .unwrap_err();
    controls.push(json!({"case":"redeem_before_all_issuance","rejection":early}));
    for i in 0..3 {
        let ctx = config.issue_context(&claims[i], &clients[i].state.blind_message);
        let auth = engine.authorize(&witnesses[i], ctx, anchor);
        let sig = service
            .issue(i, &clients[i].state.blind_message, &auth, engine, anchor)
            .unwrap();
        assert!(
            service
                .issue(i, &clients[i].state.blind_message, &auth, engine, anchor)
                .is_err()
        );
        let mut bad = sig.clone();
        bad.0[0] ^= 1;
        assert!(
            config
                .pk
                .finalize(&bad, &clients[i].state, &clients[i].message)
                .is_err()
        );
        let final_sig = config
            .pk
            .finalize(&sig, &clients[i].state, &clients[i].message)
            .unwrap();
        clients[i].signature = Some(final_sig);
    }
    controls
        .push(json!({"case":"duplicate_eligibility_and_changed_blind_signature","rejected":true}));
    let c = &clients[0];
    let sig = c.signature.as_ref().unwrap();
    let randomizer = c.state.msg_randomizer;
    let mut wrong_round = c.message.clone();
    wrong_round[TAG.len()] ^= 1;
    let mut wrong_amount = c.message.clone();
    wrong_amount[TAG.len() + 64] ^= 1;
    for (name, msg) in [
        ("wrong_round", wrong_round),
        ("wrong_denomination", wrong_amount),
    ] {
        let error = service.redeem(&msg, sig, randomizer).unwrap_err();
        controls.push(json!({"case":name,"rejection":error}));
    }
    let mut changed = c.message.clone();
    changed.pop();
    assert!(service.redeem(&changed, sig, randomizer).is_err());
    let mut wrong_key = c.message.clone();
    let n = wrong_key.len();
    wrong_key[n - 32..].copy_from_slice(&keys[1]);
    let error = service.redeem(&wrong_key, sig, randomizer).unwrap_err();
    assert!(error.starts_with("credential verification:"));
    controls.push(
        json!({"case":"changed_recipient_reaches_real_credential_verification","rejection":error}),
    );
    assert!(service.redeem(&c.message, sig, None).is_err());
    controls.push(json!({"case":"missing_randomizer_and_truncated_message","rejected":true}));
    let mut order = vec![0, 1, 2];
    order.shuffle(&mut OsRng);
    for i in order {
        let c = &clients[i];
        service
            .redeem(
                &c.message,
                c.signature.as_ref().unwrap(),
                c.state.msg_randomizer,
            )
            .unwrap();
    }
    assert!(service.redeem(&c.message, sig, randomizer).is_err());
    controls.push(json!({"case":"replayed_credential_output","rejected":true}));
    let randomizers = std::array::from_fn(|i| clients[i].state.msg_randomizer.unwrap().0);
    let candidate = json!({"schema":"common-set-observation-v1","observer":"application-transcript-and-native-public-data","mode":String::from_utf8(MODE.to_vec()).unwrap(),"issuerDer":hex::encode(config.pk.to_der().unwrap()),"issuerFingerprint":hex::encode(config.issuer),"round":hex::encode(config.round),"denominationSompi":PRINCIPAL,"owners":(0..3).map(owner).collect::<Vec<_>>(),"events":service.events,"explicitOwnerLinks":[],"network":"not observed; separate anonymous logical redemption interface is an assumption"});
    let mut baseline = candidate.clone();
    baseline["identifiedOutputRegistrations"] = json!(
        (0..3)
            .map(|i| config
                .register_identified(&owner(i), &clients[i].message)
                .unwrap())
            .collect::<Vec<_>>()
    );
    baseline["observer"] = json!("identified individual output registration control");
    RegistrationResult {
        candidate,
        baseline,
        controls,
        round: config.round,
        randomizers,
    }
}
