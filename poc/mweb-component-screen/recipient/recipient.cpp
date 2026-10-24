// Independent recipient fixture using existing MWEB APIs/known-address recovery.
// Recovery steps follow production Keychain::RewindOutput and Test_Keychain.cpp.
// No wallet DB, new primitive, consensus condition or validation modification.
#include <mw/wallet/TxBuilder.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/models/tx/OutputMask.h>
#include <mw/exceptions/CryptoException.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
static void require(bool value,const char* code){if(!value)throw std::runtime_error(code);}
static std::vector<uint8_t> read_public(const std::string& path){
    std::ifstream f(path,std::ios::binary);require(f.good(),"public_input_open");
    return {std::istreambuf_iterator<char>(f),std::istreambuf_iterator<char>()};
}
static void write_public(const std::string& path,const std::vector<uint8_t>& bytes){
    std::ofstream f(path,std::ios::binary);require(f.good(),"public_output_open");
    f.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());require(f.good(),"public_output_write");
}
static mw::Transaction load(const std::string& path){
    auto raw=read_public(path);auto tx=mw::Transaction::Deserialize(raw);
    require(tx.Serialized()==raw,"canonical_public_transaction");return tx;
}
static StealthAddress address(const SecretKey& scan,const SecretKey& spend){
    auto B=PublicKey::From(spend);return StealthAddress(B.Mul(scan),B);
}
static bool rewind_known(const Output& output,const SecretKey& scan,const SecretKey& spend,const StealthAddress& own,mw::Coin& coin){
    if(!output.HasStandardFields()||!output.Ko().IsValid()||!output.Ke().IsValid())return false;
    try{
        auto shared=output.Ke().Mul(scan);
        if(Hashed(EHashTag::TAG,shared)[0]!=output.GetViewTag())return false;
        auto t=SecretKey::FromHash(Hashed(EHashTag::DERIVE,shared));
        auto Bi=output.Ko().Div(SecretKey::FromHash(Hashed(EHashTag::OUT_KEY,t)));
        if(Bi!=own.B()||Bi.Mul(scan)!=own.A())return false;
        auto mask=OutputMask::FromShared(t);
        uint64_t value=mask.MaskValue(output.GetMaskedValue());
        if(value>static_cast<uint64_t>(MAX_MONEY))return false;
        auto nonce=mask.MaskNonce(output.GetMaskedNonce());
        if(mask.SwitchCommit(value)!=output.GetCommitment())return false;
        auto s=SecretKey::FromHash(Hasher(EHashTag::SEND_KEY).Append(own.A()).Append(own.B()).Append(value).Append(nonce).hash());
        if(output.Ke()!=own.B().Mul(s))return false;
        auto key=SecretKeys::From(spend).Mul(SecretKey::FromHash(Hashed(EHashTag::OUT_KEY,t))).Total();
        if(PublicKey::From(key)!=output.Ko())return false;
        coin.address_index=mw::CUSTOM_KEY;coin.blind=mask.GetRawBlind();coin.amount=static_cast<CAmount>(value);
        coin.output_id=output.GetOutputID();coin.address=own;coin.shared_secret=t;coin.spend_key=key;
        return true;
    }catch(const CryptoException&){return false;}
}
static void sender(const std::string& prefix,const std::string& invoice,int64_t amount,int64_t payment,int64_t change){
    require(amount==payment+change+1&&payment>1&&change>0,"declared_amount_equation");
    auto invoice_bytes=read_public(invoice);require(invoice_bytes.size()==66,"public_invoice_width");
    auto target=StealthAddress::Deserialize(invoice_bytes);require(target.Serialized()==invoice_bytes,"canonical_public_invoice");
    require(target.A().IsValid()&&target.B().IsValid(),"valid_public_invoice_keys");
    auto own_scan=SecretKey::Random(),own_spend=SecretKey::Random();auto own=address(own_scan,own_spend);
    std::vector<mw::Coin> funding_coins;
    auto funding=::TxBuilder::BuildTx({},{{amount,own}},{},boost::optional<CAmount>(amount),0,funding_coins);
    funding->Validate();require(funding->GetOutputs().size()==1,"declared_funding_shape");
    mw::Coin input;require(rewind_known(funding->GetOutputs()[0],own_scan,own_spend,own,input),"owned_synthetic_funding_recovered");
    require(input.amount==amount,"owned_input_amount");
    std::vector<mw::Coin> sent;
    auto tx=::TxBuilder::BuildTx({input},{{payment,target},{change,own}},{},boost::none,1,sent);
    tx->Validate();require(sent.size()==2&&tx->GetInputs().size()==1,"payment_change_shape");
    write_public(prefix+".tx",tx->Serialized());write_public(prefix+".funding",funding->Serialized());
    std::cout<<"{\"mode\":\"production_sender_public_recipient_invoice\",\"valid\":true,\"public_recipient_address_bytes\":66,\"recipient_secret_keys_received\":false,\"declared_input\":"<<amount
      <<",\"payment\":"<<payment<<",\"change\":"<<change<<",\"fee\":1,\"expected_payment_output_id\":\""<<sent[0].output_id.ToHex()<<"\"}\n";
}
static void recipient(const std::string& invoice){
    // These keys never leave this process, including while it waits for senders.
    auto scan=SecretKey::Random(),spend=SecretKey::Random();auto own=address(scan,spend);
    write_public(invoice,own.Serialized());
    std::cout<<"{\"event\":\"recipient_public_address_ready\",\"public_address_bytes\":66,\"secret_keys_exported\":false}"<<std::endl;
    std::string line;require(static_cast<bool>(std::getline(std::cin,line)),"public_scan_command");
    std::istringstream command(line);std::string aggregate_path,spend_path;int64_t expected=0;
    require(static_cast<bool>(command>>aggregate_path>>spend_path>>expected)&&expected>1,"public_scan_arguments");
    auto aggregate=load(aggregate_path);aggregate.Validate();
    size_t matches=0;mw::Coin recovered;
    for(const auto& output:aggregate.GetOutputs()){
        mw::Coin current;if(rewind_known(output,scan,spend,own,current)){++matches;recovered=std::move(current);}
    }
    require(matches==1&&recovered.amount==expected&&recovered.spend_key&&recovered.blind,"one_actual_owned_received_output");
    std::vector<mw::Coin> outputs;
    auto next=::TxBuilder::BuildTx({recovered},{{expected-1,own}},{},boost::none,1,outputs);
    next->Validate();require(next->GetInputs().size()==1&&next->GetOutputs().size()==1,"recipient_spend_shape");
    require(next->GetInputs()[0].GetOutputID()==recovered.output_id,"recipient_spends_actual_received_output");
    write_public(spend_path,next->Serialized());
    std::cout<<"{\"event\":\"recipient_recovered_and_spent\",\"owned_outputs_recovered\":1,\"other_outputs_accepted\":0,\"scanned_outputs\":"<<aggregate.GetOutputs().size()
      <<",\"recovered_amount\":"<<recovered.amount<<",\"received_output_id\":\""<<recovered.output_id.ToHex()
      <<"\",\"spend_key_matches_received_authorization_key\":true,\"production_recipient_spend_valid\":true,\"spend_output_amount\":"<<expected-1
      <<",\"spend_fee\":1,\"private_keys_or_blinds_exported\":false}"<<std::endl;
}
int main(int argc,char** argv){
    try{
        require(argc>=3,"arguments");std::string mode=argv[1];
        if(mode=="recipient"&&argc==3)recipient(argv[2]);
        else if(mode=="sender"&&argc==7)sender(argv[2],argv[3],std::stoll(argv[4]),std::stoll(argv[5]),std::stoll(argv[6]));
        else throw std::runtime_error("arguments");return 0;
    }catch(const std::exception& error){std::cerr<<"recipient_component_failed:"<<error.what()<<'\n';return 1;}
}
