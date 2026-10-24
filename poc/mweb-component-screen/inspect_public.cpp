// Read-only inventory of already-created public serialized transaction fields.
// No owner builder, entropy draw, signing, proving or validation is invoked.
#include <mw/models/tx/Transaction.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
int main(int argc,char** argv) {
    try {
        if(argc!=2)throw std::runtime_error("public_input_argument");
        std::ifstream input(argv[1],std::ios::binary);
        if(!input.good())throw std::runtime_error("public_input_open");
        std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input),std::istreambuf_iterator<char>()};
        auto tx=mw::Transaction::Deserialize(bytes);
        if(tx.Serialized()!=bytes)throw std::runtime_error("canonical_public_roundtrip");
        std::cout << "{\"inspection_only\":true,\"public_kernel_offset_hex\":\"" << tx.GetKernelOffset().ToHex()
          << "\",\"public_stealth_offset_hex\":\"" << tx.GetStealthOffset().ToHex() << "\",\"inputs\":[";
        for(size_t i=0;i<tx.GetInputs().size();++i) {
            if(i)std::cout << ',';const auto& v=tx.GetInputs()[i];
            std::cout << "{\"spent_output_id\":\"" << v.GetOutputID().ToHex()
              << "\",\"commitment\":\"" << v.GetCommitment().ToHex()
              << "\",\"output_pubkey\":\"" << v.GetOutputPubKey().ToHex() << "\",\"input_ephemeral_pubkey\":";
            if(v.GetInputPubKey())std::cout << '"' << v.GetInputPubKey()->ToHex() << '"';else std::cout << "null";
            std::cout << '}';
        }
        std::cout << "],\"outputs\":[";
        std::set<PublicKey> senders,receivers;
        for(size_t i=0;i<tx.GetOutputs().size();++i) {
            if(i)std::cout << ',';const auto& v=tx.GetOutputs()[i];senders.insert(v.GetSenderPubKey());receivers.insert(v.GetReceiverPubKey());
            std::cout << "{\"output_id\":\"" << v.GetOutputID().ToHex()
              << "\",\"commitment\":\"" << v.GetCommitment().ToHex()
              << "\",\"sender_pubkey\":\"" << v.GetSenderPubKey().ToHex()
              << "\",\"receiver_pubkey\":\"" << v.GetReceiverPubKey().ToHex()
              << "\",\"key_exchange_pubkey\":\"" << v.GetKeyExchangePubKey().ToHex()
              << "\",\"view_tag\":" << (unsigned)v.GetViewTag()
              << ",\"masked_value\":" << v.GetMaskedValue()
              << ",\"masked_nonce_hex\":\"" << v.GetMaskedNonce().ToHex()
              << "\",\"features\":" << (unsigned)v.GetFeatures()
              << ",\"rangeproof_bytes\":" << v.GetRangeProof()->size() << '}';
        }
        std::cout << "],\"kernels\":[";
        for(size_t i=0;i<tx.GetKernels().size();++i) {
            if(i)std::cout << ',';const auto& v=tx.GetKernels()[i];
            std::cout << "{\"kernel_id\":\"" << v.GetKernelID().ToHex()
              << "\",\"features\":" << (unsigned)v.GetFeatures()
              << ",\"fee\":" << v.GetFee() << ",\"excess\":\"" << v.GetExcess().ToHex()
              << "\",\"stealth_excess_pubkey\":";
            if(v.HasStealthExcess())std::cout << '"' << v.GetStealthExcess().ToHex() << '"';else std::cout << "null";
            std::cout << '}';
        }
        std::cout << "],\"distinct_output_sender_keys\":" << senders.size()
          << ",\"distinct_output_receiver_keys\":" << receivers.size() << "}\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<"public_inspection_failed:"<<error.what()<<'\n';return 1;}
}
