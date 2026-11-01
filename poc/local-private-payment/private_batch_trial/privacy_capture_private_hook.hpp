#pragma once

#include "privacy_capture_hook.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace kpb::capture {

enum class RetryOutcome { Refused, Disconnected, Completed, Orphaned };
enum class RejectedStatus { Rejected, Orphaned };

namespace detail {
class CorruptServerChannel {
public:
    CorruptServerChannel(int, unsigned, const Binding&, const std::string&);
    ~CorruptServerChannel();
    void owner_input_preprocessing_share(
        unsigned, std::span<const unsigned char>);
    void owner_input_offset(unsigned, std::span<const unsigned char>);
    void mascot_message(std::span<const unsigned char>);
    void mac_key_share(std::span<const unsigned char>);
    void authenticated_share(std::span<const unsigned char>);
    void mac_share(std::span<const unsigned char>);
    void randomness_share(std::span<const unsigned char>);
    void randomness_mac(std::span<const unsigned char>);
    void field_opening(std::span<const unsigned char>);
    void authenticated_g1_state(
        unsigned, std::span<const unsigned char>);
    void authenticated_g2_state(
        unsigned, std::span<const unsigned char>);
    void masked_field_intermediate(std::span<const unsigned char>);
    void masked_g1_intermediate(std::span<const unsigned char>);
    void final_proof_g1(std::span<const unsigned char>);
    void final_proof_g2(std::span<const unsigned char>);
    void public_projection(std::span<const unsigned char>);
    void close_complete();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
class ColluderWalletChannel {
public:
    ColluderWalletChannel(int, unsigned, const Binding&,
                          const std::array<std::string, 3>&);
    ~ColluderWalletChannel();
    void original(const std::string&, std::uint64_t, const std::string&,
                  std::uint64_t, const std::string&, std::uint64_t);
    void issued_invoice(unsigned, const std::string&, std::uint64_t);
    void accepted_invoice(unsigned, const std::string&, std::uint64_t);
    void incoming_receipt(std::uint64_t, unsigned, const std::string&,
                          const std::string&, std::uint64_t);
    void change_receipt(std::uint64_t, const std::string&,
                        const std::string&, std::uint64_t);
    void retry(const std::string&, std::uint64_t, std::uint64_t,
               RetryOutcome);
    void close_complete();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
class TerminalChannel {
public:
    TerminalChannel(int, unsigned, const Binding&);
    ~TerminalChannel();
    void candidate_constructed(std::uint64_t, const std::string&);
    void native_full(std::uint64_t, const std::string&);
    void trial_closed(std::uint64_t, const std::string&);
    void hidden_group(const std::string&, const std::array<std::string, 3>&,
                      const std::array<std::string, 6>&);
    void retry(const std::string&, RetryOutcome, const std::string&);
    void rejected_or_orphaned(const std::string&, RejectedStatus);
    void reorg(const std::string&, const std::string&, std::uint64_t);
    void cross_round_link(const std::string&, unsigned, const std::string&);
    void close_complete();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}

template<int FixedFd, unsigned Round>
class CorruptServerHook final {
    static_assert(Round == 1 || Round == 2);
    static_assert(FixedFd == (Round == 1 ? 23 : 28));
public:
    CorruptServerHook(const Binding&, const std::string& protocol_source);
    ~CorruptServerHook();
    CorruptServerHook(const CorruptServerHook&) = delete;
    CorruptServerHook& operator=(const CorruptServerHook&) = delete;
    void owner_input_preprocessing_share(
        unsigned, std::span<const unsigned char>);
    void owner_input_offset(unsigned, std::span<const unsigned char>);
    void mascot_message(std::span<const unsigned char>);
    void mac_key_share(std::span<const unsigned char>);
    void authenticated_share(std::span<const unsigned char>);
    void mac_share(std::span<const unsigned char>);
    void randomness_share(std::span<const unsigned char>);
    void randomness_mac(std::span<const unsigned char>);
    void field_opening(std::span<const unsigned char>);
    void authenticated_g1_state(
        unsigned, std::span<const unsigned char>);
    void authenticated_g2_state(
        unsigned, std::span<const unsigned char>);
    void masked_field_intermediate(std::span<const unsigned char>);
    void masked_g1_intermediate(std::span<const unsigned char>);
    void final_proof_g1(std::span<const unsigned char>);
    void final_proof_g2(std::span<const unsigned char>);
    void public_projection(std::span<const unsigned char>);
    void close_complete();
private:
    std::unique_ptr<detail::CorruptServerChannel> channel_;
};

template<int FixedFd, unsigned Round>
class ColluderWalletHook final {
    static_assert(Round == 1 || Round == 2);
    static_assert(FixedFd == (Round == 1 ? 24 : 29));
public:
    ColluderWalletHook(const Binding&,
                       const std::array<std::string, 3>& stage_operations);
    ~ColluderWalletHook();
    ColluderWalletHook(const ColluderWalletHook&) = delete;
    ColluderWalletHook& operator=(const ColluderWalletHook&) = delete;
    void original(const std::string& input_nf, std::uint64_t input_amount,
                  const std::string& outgoing_tuple,
                  std::uint64_t outgoing_amount,
                  const std::string& change_tuple,
                  std::uint64_t change_amount);
    void issued_invoice(unsigned source_owner, const std::string& operation,
                        std::uint64_t amount);
    void accepted_invoice(unsigned target_owner, const std::string& operation,
                          std::uint64_t amount);
    void incoming_receipt(std::uint64_t index, unsigned creator,
                          const std::string& tuple, const std::string& cm,
                          std::uint64_t amount);
    void change_receipt(std::uint64_t index, const std::string& tuple,
                        const std::string& cm, std::uint64_t amount);
    void retry(const std::string& attempt, std::uint64_t start,
               std::uint64_t complete, RetryOutcome);
    void close_complete();
private:
    std::unique_ptr<detail::ColluderWalletChannel> channel_;
};

template<int FixedFd, unsigned Round>
class TerminalHook final {
    static_assert(Round == 1 || Round == 2);
    static_assert(FixedFd == (Round == 1 ? 21 : 26));
public:
    explicit TerminalHook(const Binding&);
    ~TerminalHook();
    TerminalHook(const TerminalHook&) = delete;
    TerminalHook& operator=(const TerminalHook&) = delete;
    void candidate_constructed(std::uint64_t, const std::string& candidate);
    void native_full(std::uint64_t, const std::string& candidate);
    void trial_closed(std::uint64_t, const std::string& candidate);
    void hidden_group(const std::string& group_id,
                      const std::array<std::string, 3>& nfs,
                      const std::array<std::string, 6>& tuples);
    void retry(const std::string& attempt, RetryOutcome,
               const std::string& candidate);
    void rejected_or_orphaned(const std::string& candidate,
                              RejectedStatus);
    void reorg(const std::string& old_head, const std::string& new_head,
               std::uint64_t depth);
    void cross_round_link(const std::string& nf, unsigned output_round,
                          const std::string& tuple);
    void close_complete();
private:
    std::unique_ptr<detail::TerminalChannel> channel_;
};

// Template definitions keep FD/round compile-time selected while the concrete
// channel implementations remain out of the public interface.
template<int F, unsigned R>
CorruptServerHook<F, R>::CorruptServerHook(
    const Binding& b, const std::string& s)
    : channel_(new detail::CorruptServerChannel(F, R, b, s)) {}
template<int F, unsigned R>
CorruptServerHook<F, R>::~CorruptServerHook() = default;
template<int F, unsigned R>
void CorruptServerHook<F, R>::owner_input_preprocessing_share(
    unsigned o, std::span<const unsigned char> p) {
    channel_->owner_input_preprocessing_share(o, p);
}
template<int F, unsigned R> void CorruptServerHook<F, R>::owner_input_offset(
    unsigned o, std::span<const unsigned char> p) {
    channel_->owner_input_offset(o, p);
}
template<int F, unsigned R> void CorruptServerHook<F, R>::mascot_message(
    std::span<const unsigned char> p) { channel_->mascot_message(p); }
template<int F, unsigned R> void CorruptServerHook<F, R>::mac_key_share(
    std::span<const unsigned char> p) { channel_->mac_key_share(p); }
template<int F, unsigned R> void CorruptServerHook<F, R>::authenticated_share(
    std::span<const unsigned char> p) { channel_->authenticated_share(p); }
template<int F, unsigned R> void CorruptServerHook<F, R>::mac_share(
    std::span<const unsigned char> p) { channel_->mac_share(p); }
template<int F, unsigned R> void CorruptServerHook<F, R>::randomness_share(
    std::span<const unsigned char> p) { channel_->randomness_share(p); }
template<int F, unsigned R> void CorruptServerHook<F, R>::randomness_mac(
    std::span<const unsigned char> p) { channel_->randomness_mac(p); }
template<int F, unsigned R> void CorruptServerHook<F, R>::field_opening(
    std::span<const unsigned char> p) { channel_->field_opening(p); }
template<int F, unsigned R> void CorruptServerHook<F, R>::authenticated_g1_state(
    unsigned s, std::span<const unsigned char> p) {
    channel_->authenticated_g1_state(s, p);
}
template<int F, unsigned R> void CorruptServerHook<F, R>::authenticated_g2_state(
    unsigned s, std::span<const unsigned char> p) {
    channel_->authenticated_g2_state(s, p);
}
template<int F, unsigned R>
void CorruptServerHook<F, R>::masked_field_intermediate(
    std::span<const unsigned char> p) {
    channel_->masked_field_intermediate(p);
}
template<int F, unsigned R> void CorruptServerHook<F, R>::masked_g1_intermediate(
    std::span<const unsigned char> p) { channel_->masked_g1_intermediate(p); }
template<int F, unsigned R> void CorruptServerHook<F, R>::final_proof_g1(
    std::span<const unsigned char> p) { channel_->final_proof_g1(p); }
template<int F, unsigned R> void CorruptServerHook<F, R>::final_proof_g2(
    std::span<const unsigned char> p) { channel_->final_proof_g2(p); }
template<int F, unsigned R> void CorruptServerHook<F, R>::public_projection(
    std::span<const unsigned char> p) { channel_->public_projection(p); }
template<int F, unsigned R> void CorruptServerHook<F, R>::close_complete() {
    channel_->close_complete();
}

template<int F, unsigned R>
ColluderWalletHook<F, R>::ColluderWalletHook(
    const Binding& b, const std::array<std::string, 3>& operations)
    : channel_(new detail::ColluderWalletChannel(F, R, b, operations)) {}
template<int F, unsigned R>
ColluderWalletHook<F, R>::~ColluderWalletHook() = default;
template<int F, unsigned R> void ColluderWalletHook<F, R>::original(
    const std::string& n, std::uint64_t a, const std::string& o,
    std::uint64_t oa, const std::string& c, std::uint64_t ca) {
    channel_->original(n, a, o, oa, c, ca);
}
template<int F, unsigned R> void ColluderWalletHook<F, R>::issued_invoice(
    unsigned o, const std::string& p, std::uint64_t a) {
    channel_->issued_invoice(o, p, a);
}
template<int F, unsigned R> void ColluderWalletHook<F, R>::accepted_invoice(
    unsigned o, const std::string& p, std::uint64_t a) {
    channel_->accepted_invoice(o, p, a);
}
template<int F, unsigned R> void ColluderWalletHook<F, R>::incoming_receipt(
    std::uint64_t i, unsigned o, const std::string& t,
    const std::string& c, std::uint64_t a) {
    channel_->incoming_receipt(i, o, t, c, a);
}
template<int F, unsigned R> void ColluderWalletHook<F, R>::change_receipt(
    std::uint64_t i, const std::string& t, const std::string& c,
    std::uint64_t a) { channel_->change_receipt(i, t, c, a); }
template<int F, unsigned R> void ColluderWalletHook<F, R>::retry(
    const std::string& i, std::uint64_t s, std::uint64_t c,
    RetryOutcome o) { channel_->retry(i, s, c, o); }
template<int F, unsigned R> void ColluderWalletHook<F, R>::close_complete() {
    channel_->close_complete();
}

template<int F, unsigned R>
TerminalHook<F, R>::TerminalHook(const Binding& b)
    : channel_(new detail::TerminalChannel(F, R, b)) {}
template<int F, unsigned R> TerminalHook<F, R>::~TerminalHook() = default;
template<int F, unsigned R> void TerminalHook<F, R>::candidate_constructed(
    std::uint64_t t, const std::string& c) { channel_->candidate_constructed(t, c); }
template<int F, unsigned R> void TerminalHook<F, R>::native_full(
    std::uint64_t t, const std::string& c) { channel_->native_full(t, c); }
template<int F, unsigned R> void TerminalHook<F, R>::trial_closed(
    std::uint64_t t, const std::string& c) { channel_->trial_closed(t, c); }
template<int F, unsigned R> void TerminalHook<F, R>::hidden_group(
    const std::string& g, const std::array<std::string, 3>& n,
    const std::array<std::string, 6>& t) { channel_->hidden_group(g, n, t); }
template<int F, unsigned R> void TerminalHook<F, R>::retry(
    const std::string& a, RetryOutcome o, const std::string& c) {
    channel_->retry(a, o, c);
}
template<int F, unsigned R> void TerminalHook<F, R>::rejected_or_orphaned(
    const std::string& c, RejectedStatus s) { channel_->rejected_or_orphaned(c, s); }
template<int F, unsigned R> void TerminalHook<F, R>::reorg(
    const std::string& o, const std::string& n, std::uint64_t d) {
    channel_->reorg(o, n, d);
}
template<int F, unsigned R> void TerminalHook<F, R>::cross_round_link(
    const std::string& n, unsigned r, const std::string& t) {
    channel_->cross_round_link(n, r, t);
}
template<int F, unsigned R> void TerminalHook<F, R>::close_complete() {
    channel_->close_complete();
}

} // namespace kpb::capture
