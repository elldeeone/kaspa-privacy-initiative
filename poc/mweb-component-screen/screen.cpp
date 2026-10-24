// Unfunded upstream-component screen, not a protocol implementation.
// API sequence adapted from Litecoin Core Test_Aggregation.cpp (MIT).
#include <mw/consensus/Aggregation.h>
#include <mw/consensus/KernelSumValidator.h>
#include <mw/consensus/StealthSumValidator.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/crypto/Blinds.h>
#include <test_framework/TxBuilder.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
static void require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
static std::vector<uint8_t> read_public(const std::string& path) {
    std::ifstream file(path, std::ios::binary); require(file.good(), "public_input_open");
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
static void write_public(const std::string& path, const std::vector<uint8_t>& bytes) {
    std::ofstream file(path, std::ios::binary); require(file.good(), "public_output_open");
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); require(file.good(), "public_output_write");
}
static mw::Transaction::CPtr load(const std::string& path) {
    const auto raw = read_public(path); auto value = mw::Transaction::Deserialize(raw);
    require(value.Serialized() == raw, "canonical_public_roundtrip");
    return std::make_shared<const mw::Transaction>(std::move(value));
}
static void ids(const std::vector<mw::Hash>& values) {
    std::cout << '[';
    for (size_t i=0; i<values.size(); ++i) { if (i) std::cout << ','; std::cout << '"' << values[i].ToHex() << '"'; }
    std::cout << ']';
}
static void public_report(const mw::Transaction::CPtr& tx) {
    std::cout << "\"input_ids\":"; ids(tx->GetBody().GetSpentIDs());
    std::cout << ",\"output_ids\":"; ids(tx->GetBody().GetOutputIDs());
    std::cout << ",\"kernel_ids\":"; ids(tx->GetBody().GetKernelIDs());
    std::cout << ",\"input_count\":" << tx->GetInputs().size() << ",\"output_count\":" << tx->GetOutputs().size()
              << ",\"kernel_count\":" << tx->GetKernels().size() << ",\"serialized_bytes\":" << tx->Serialized().size();
}
static void upstream_equivalent(const std::string& output) {
    auto a=test::TxBuilder().AddInput(10).AddInput(20).AddOutput(25).AddPlainKernel(5,true).Build().GetTransaction();
    auto b=test::TxBuilder().AddInput(20).AddOutput(15).AddPlainKernel(5,true).Build().GetTransaction();
    a->Validate(); b->Validate(); auto merged=Aggregation::Aggregate({a,b}); merged->Validate();
    auto inputs=a->GetInputs(); inputs.insert(inputs.end(),b->GetInputs().begin(),b->GetInputs().end()); std::sort(inputs.begin(),inputs.end(),InputSort);
    auto outputs=a->GetOutputs(); outputs.insert(outputs.end(),b->GetOutputs().begin(),b->GetOutputs().end()); std::sort(outputs.begin(),outputs.end(),OutputSort);
    auto kernels=a->GetKernels(); kernels.insert(kernels.end(),b->GetKernels().begin(),b->GetKernels().end()); std::sort(kernels.begin(),kernels.end(),KernelSort);
    require(merged->GetInputs()==inputs && merged->GetOutputs()==outputs && merged->GetKernels()==kernels,"upstream_sorted_union");
    require(merged->GetKernelOffset()==Blinds().Add(a->GetKernelOffset()).Add(b->GetKernelOffset()).Total(),"kernel_offset_sum");
    require(merged->GetStealthOffset()==Blinds().Add(a->GetStealthOffset()).Add(b->GetStealthOffset()).Total(),"stealth_offset_sum");
    write_public(output,merged->Serialized());
    std::cout << "{\"test\":\"upstream_TestAggregation_equivalent_API_sequence\",\"valid\":true,"; public_report(merged); std::cout << "}\n";
}
static void owner(const std::string& prefix, int64_t input, int64_t payment, int64_t change) {
    require(input==payment+change+1 && payment>0 && change>0,"declared_payment_change_fee_equation");
    // Declared synthetic peg-in: owned local fixture, no canonical chain backing.
    const auto funding=test::TxBuilder().AddPeginKernel(input,0,true).AddOutput(input).Build();
    funding.GetTransaction()->Validate();
    const auto built=test::TxBuilder().AddInput(funding.GetOutputs()[0]).AddOutput(payment).AddOutput(change).AddPlainKernel(1,true).Build();
    const auto tx=built.GetTransaction(); tx->Validate();
    const auto& spent=tx->GetInputs()[0]; const auto& funded=funding.GetOutputs()[0].GetOutput();
    require(spent.GetOutputID()==funded.GetOutputID() && spent.GetCommitment()==funded.GetCommitment()
        && spent.GetOutputPubKey()==funded.GetReceiverPubKey(),"owned_input_matches_funding");
    write_public(prefix+".tx",tx->Serialized()); write_public(prefix+".funding",funding.GetTransaction()->Serialized());
    std::cout << "{\"mode\":\"independent_owner_component\",\"valid\":true,\"owned_synthetic_input_matches\":true,\"amount\":" << input
              << ",\"payment\":" << payment << ",\"change\":" << change << ",\"fee\":1,\"legitimate_C1_payment_output_id\":\""
              << built.GetOutputs()[0].GetOutputID().ToHex() << "\","; public_report(tx); std::cout << "}\n";
}
static void aggregate(const std::string& left,const std::string& right,const std::string& output) {
    auto a=load(left),b=load(right); a->Validate(); b->Validate(); auto tx=Aggregation::Aggregate({a,b}); tx->Validate();
    std::set<PublicKey> senders; for(const auto& item:tx->GetOutputs()) senders.insert(item.GetSenderPubKey());
    require(senders.size()==tx->GetOutputs().size(),"distinct_output_sender_keys");
    require(tx->GetInputs().size()==2 && tx->GetOutputs().size()==4 && tx->GetKernels().size()==2,"two_payments_change_shape");
    write_public(output,tx->Serialized());
    std::cout << "{\"mode\":\"public_components_only_aggregation\",\"valid\":true,\"aggregate_arguments_have_no_spend_secrets\":true,\"distinct_per_output_sender_keys\":true,";
    public_report(tx); std::cout << "}\n";
}
static void fresh_verify(const std::string& path) {
    const auto tx=load(path); tx->Validate();
    std::cout << "{\"mode\":\"fresh_process_public_validation\",\"valid\":true,"; public_report(tx); std::cout << "}\n";
}
static void negatives(const std::string& path) {
    const auto good=load(path);good->Validate(); bool duplicate=false,missing=false,proof=false,signature=false;
    try { Aggregation::Aggregate({good,good})->Validate(); } catch(const ValidationException&) { duplicate=true; }
    auto outputs=good->GetOutputs();outputs.pop_back();
    try { mw::Transaction::Create(good->GetKernelOffset(),good->GetStealthOffset(),good->GetInputs(),outputs,good->GetKernels())->Validate(); }
    catch(const ValidationException&) { missing=true; }
    auto data=good->GetOutputs()[0].BuildProofData();auto bytes=data.pRangeProof->vec();bytes[0]^=1;
    data.pRangeProof=std::make_shared<const RangeProof>(std::move(bytes));proof=!Bulletproofs::BatchVerify({data});
    auto signed_msg=good->GetKernels()[0].BuildSignedMsg();
    SignedMessage invalid(signed_msg.GetMsgHash(),signed_msg.GetPublicKey(),Signature{});
    signature=!Schnorr::BatchVerify({invalid}); require(duplicate&&missing&&proof&&signature,"negative_validators_reject");
    std::cout << "{\"mode\":\"upstream_validation_negatives\",\"duplicate_inputs_kernels_rejected\":true,\"dropped_output_balance_rejected\":true,\"mutated_rangeproof_rejected\":true,\"invalid_signature_rejected\":true}\n";
}
int main(int argc,char** argv) {
    try {
        require(argc>=3,"arguments");const std::string op=argv[1];
        if(op=="upstream"&&argc==3)upstream_equivalent(argv[2]);
        else if(op=="owner"&&argc==6)owner(argv[2],std::stoll(argv[3]),std::stoll(argv[4]),std::stoll(argv[5]));
        else if(op=="aggregate"&&argc==5)aggregate(argv[2],argv[3],argv[4]);
        else if(op=="verify"&&argc==3)fresh_verify(argv[2]);
        else if(op=="negative"&&argc==3)negatives(argv[2]);
        else throw std::runtime_error("arguments");return 0;
    } catch(const std::exception& error) { std::cerr << "component_screen_failed:" << error.what() << '\n';return 1; }
}
