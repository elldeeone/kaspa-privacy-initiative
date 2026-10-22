use super::*;
use tree::*;

#[test]
fn tree_paths_unsigned_order_and_indexed_set() -> Result<()> {
    // Independent dense root for a full depth-16 tree, including boundary paths.
    let leaves=(0..513u32).map(|i|hash(&i.to_le_bytes())).collect::<Vec<_>>();
    let t=Tree::new(leaves.clone())?;let mut dense=leaves.clone();dense.resize(LIMIT,[0;32]);
    while dense.len()>1 {dense=dense.chunks_exact(2).map(|p|node(&p[0],&p[1])).collect();}
    assert_eq!(t.root(),dense[0]);
    for i in [0,1,255,256,512,513,65535] {
        assert_eq!(root_from(leaves.get(i).copied().unwrap_or([0;32]),i as u32,&t.path(i as u32)?),t.root());
    }
    assert!(t.path(65536).is_err()); assert!(Tree::new(vec![[0;32];LIMIT+1]).is_err());
    let mut keys=vec![[0;32],[255;32]];
    for byte in 0..32 {for v in [1,127,128,255] {let mut k=[0;32];k[byte]=v;keys.push(k);}}
    for a in &keys {for b in &keys {
        let independent=(0..32).rev().find(|i|a[*i]!=b[*i]).map(|i|a[i]<b[i]).unwrap_or(false);
        assert_eq!(less(a,b),independent);
    }}
    let mut s=PublicState::initial([9;32])?;
    for i in 1..=110u32 {
        let nf=hash(&i.to_le_bytes());
        let a=Authorization {domain:[1;32],count:s.commitments.len() as u32,anchor:s.cm_tree()?.root(),nullifier:nf,outputs:[hash(&[i as u8,1]),hash(&[i as u8,2])],mode:1,payout:0,fee:1,spk:[0;36],bootstrap:0,cipher_hash:hash(&[0;370])};
        let next=s.witness(&a)?.0;assert!(next.witness(&a).is_err());
        let mut index=0;let mut seen=std::collections::BTreeSet::new();
        loop {assert!(seen.insert(index));let l=&next.nullifiers[index];if l.next_value==[0;32]{assert_eq!(l.next_index,0);break;}
            assert!(less(&l.value,&l.next_value));index=l.next_index as usize;assert_eq!(next.nullifiers[index].value,l.next_value);
        }
        assert_eq!(seen.len(),next.nullifiers.len());s=next;
    }
    assert_eq!(s.compact()?.cm_count,221);
    Ok(())
}

#[test]
fn positioned_membership_and_authorization_negatives() -> Result<()> {
    let (c,_)=experiment::fixture()?; assert!(c.check()?.1);
    let mut cases=Vec::new();
    let mut bad=c.clone();bad.position=1;cases.push(("wrong private index",bad));
    let mut bad=c.clone();bad.position=65536;cases.push(("out of range private index",bad));
    let mut bad=c.clone();bad.path[15][0]^=1;cases.push(("wrong membership path",bad));
    let mut bad=c.clone();bad.secret[0]^=1;cases.push(("wrong owner",bad));
    let mut bad=c.clone();bad.auth.domain[0]^=1;cases.push(("cross domain",bad));
    let mut bad=c.clone();bad.auth.count=0;cases.push(("empty anchor",bad));
    let mut bad=c.clone();bad.outputs[0].value+=1;cases.push(("one sompi inflation",bad));
    let mut bad=c.clone();bad.auth.fee=0;cases.push(("zero fee",bad));
    let mut bad=c.clone();bad.input.value=MAX_SOMPI+1;cases.push(("over max input",bad));
    for (name,mut bad) in cases {bad.public=bad.auth.inputs();assert!(!bad.check().map(|x|x.1).unwrap_or(false),"accepted {name}");}
    // Same commitment at distinct funded positions: private indices and NFs
    // differ; each remains a valid ownership/membership authorization.
    let d=[3;32];let w=Wallet::fresh();let note=w.receive(&d).note(200_000_000)?;
    let cm=note.commitment(&d);let mut s=PublicState::initial(cm)?;
    s.commitments=vec![cm,cm,cm];s.roots.push(s.cm_tree()?.root());
    let f=experiment::fees()?;
    for pos in [0,1,2] {
        let (c,_)=experiment::authorization(&w,&note,&s,pos,[Note::dummy(),Note::dummy()],d,f.exit,note.value-f.exit,native::encode_spk(&native::p2pk(&[7;32])?).try_into().unwrap(),0)?;
        assert!(c.check()?.1);
    }
    assert_ne!(nullifier(&d,&w.spending,&cm,0),nullifier(&d,&w.spending,&cm,1));
    Ok(())
}

#[test]
fn framing_capacity_and_fee_floor() -> Result<()> {
    let (c,b)=experiment::fixture()?;
    assert_eq!(c.auth.bytes().len(),AUTH_LEN);
    assert_eq!(Authorization::parse(&c.auth.bytes())?.bytes(),c.auth.bytes());
    assert!(Authorization::parse(&c.auth.bytes()[..AUTH_LEN-1]).is_err());
    let initial=PublicState::initial(c.input.commitment(&c.auth.domain))?;
    let (next,w)=initial.witness(&c.auth)?;let state=next.compact()?;
    assert_eq!(State::parse(&state.bytes())?,state);
    assert_eq!(b.payload(&state,&w)?.len(),PAYLOAD_SIZE);
    let mut bad=state.clone();bad.cm_count=65536;assert!(bad.check().is_err());
    bad.cm_count=65535;bad.nf_count=65535;assert!(bad.check().is_ok());
    bad.nf_count=65536;assert!(bad.check().is_err());
    assert!(NOTE_FLOOR>=experiment::fees()?.exit+PAYOUT_FLOOR);
    Ok(())
}

#[test]
fn native_unsigned_comparison_boundaries() -> Result<()> {
    let script=covenant::comparison_script();
    let mut keys=vec![[0;32],[255;32]];
    for byte in [0,6,7,13,14,20,21,27,28,31] {for value in [1,127,128,255] {let mut k=[0;32];k[byte]=value;keys.push(k);}}
    for a in &keys {for b in &keys {
        let mut sb=kaspa_txscript::script_builder::ScriptBuilder::new();sb.add_data(&script)?;
        let u=native::Utxo {txid:hex::encode([8;32]),index:0,amount:100_000_000,spk:hex::encode(native::encode_spk(&pay_to_script_hash_script(&script))),daa:0,is_coinbase:false};
        let tx=Transaction::new(1,vec![TransactionInput::new_with_compute_budget(u.outpoint()?,sb.drain(),u64::MAX,10)],vec![TransactionOutput::new(90_000_000,native::p2pk(&[7;32])?)],0,Default::default(),0,[a.as_slice(),b.as_slice()].concat());
        let entries=vec![u.entry()?];native::set_mass(&tx,&entries)?;
        assert_eq!(native::validate(&tx,&entries).is_ok(),less(a,b),"native unsigned comparison differs");
    }}
    Ok(())
}

#[test]
fn relation_economic_boundaries_with_matching_commitments() -> Result<()> {
    let d=[5;32];let w=Wallet::fresh();
    let spk=native::encode_spk(&native::p2pk(&[7;32])?).try_into().unwrap();
    let f=experiment::fees()?;
    for (value,payout,expected) in [
        (NOTE_FLOOR,NOTE_FLOOR-f.exit,true),
        (NOTE_FLOOR-1,NOTE_FLOOR-1-f.exit,false),
        (MAX_SOMPI,MAX_SOMPI-f.exit,true),
        (MAX_SOMPI+1,MAX_SOMPI+1-f.exit,false),
        (NOTE_FLOOR,PAYOUT_FLOOR,true),
        (NOTE_FLOOR,PAYOUT_FLOOR-1,false),
        (NOTE_FLOOR,NOTE_FLOOR,false),
    ] {
        let mut n=w.receive(&d).note(NOTE_FLOOR)?;n.value=value;
        let s=PublicState::initial(n.commitment(&d))?;
        let (c,_)=experiment::authorization(&w,&n,&s,0,[Note::dummy(),Note::dummy()],d,value-payout,payout,spk,0)?;
        assert_eq!(c.check()?.1,expected,"input={value} payout={payout}");
    }
    for output in [NOTE_FLOOR-1,NOTE_FLOOR] {
        let n=w.receive(&d).note(RESERVE)?;let s=PublicState::initial(n.commitment(&d))?;
        let outputs=[w.receive(&d).note(output)?,w.receive(&d).note(RESERVE-output-f.transfer)?];
        let (c,_)=experiment::authorization(&w,&n,&s,0,outputs,d,f.transfer,0,[0;36],RESERVE)?;
        assert_eq!(c.check()?.1,output==NOTE_FLOOR);
    }
    Ok(())
}
