#include "privacy_terminal_capture_v2.hpp"
#include "native_terminal_mapping_source.hpp"
#include "../mpc-prover/financial/registered_driver_bridge.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <set>
#include <signal.h>
#include <span>
#include <string_view>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace kpb::capture {
namespace {

constexpr std::array<unsigned char, 8> MAGIC{
    'K', 'P', 'B', 'C', 'E', 'V', '0', '1'};

[[noreturn]] void refuse() { throw CaptureRefused(); }
void need(bool value) { if (!value) refuse(); }
bool lower_hex(char value) {
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f');
}
void word(const std::string& value) {
    need(value.size() == 64 &&
         std::all_of(value.begin(), value.end(), lower_hex));
}
void uuid(const std::string& value) {
    need(value.size() == 36);
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23)
            need(value[index] == '-');
        else need(lower_hex(value[index]));
    }
    need(value[14] == '4' && std::string_view("89ab").find(value[19]) !=
                                std::string_view::npos);
}
void selected(const Binding& value) {
    uuid(value.attempt_id); word(value.cohort_sha256);
    word(value.financial_run_id); uuid(value.capture_identity);
    word(value.projection_sha256);
    need(value.construction_classification == 1 ||
         value.construction_classification == 2);
    word(value.construction_attempt_sha256);
    word(value.capture_plan_sha256);
}
std::string quote(const std::string& value) {
    need(!value.empty() && std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
    }));
    return '"' + value + '"';
}
std::string optional(const std::string& value) {
    return value.empty() ? "null" : quote(value);
}
std::string string_array(std::span<const std::string> values) {
    std::string result = "[";
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index) result += ',';
        result += quote(values[index]);
    }
    return result + ']';
}
std::span<const unsigned char> bytes(const std::string& value) {
    return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}

std::string hex(std::span<const unsigned char> value) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2);
    for (const auto byte : value) {
        result.push_back(alphabet[byte >> 4]);
        result.push_back(alphabet[byte & 0x0f]);
    }
    return result;
}

std::string hash(std::span<const unsigned char> value) {
    std::array<unsigned char, 32> result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return hex(result);
}

class HashState final {
    EVP_MD_CTX* context_{EVP_MD_CTX_new()};
    bool finished_{};
public:
    HashState() {
        need(context_ != nullptr &&
             EVP_DigestInit_ex(context_, EVP_sha256(), nullptr) == 1);
    }
    HashState(const HashState&) = delete;
    HashState& operator=(const HashState&) = delete;
    ~HashState() { EVP_MD_CTX_free(context_); }
    void update(std::span<const unsigned char> value) {
        need(!finished_ && EVP_DigestUpdate(
            context_, value.data(), value.size()) == 1);
    }
    std::string finish() {
        need(!finished_); finished_ = true;
        std::array<unsigned char, 32> result{};
        unsigned length = 0;
        need(EVP_DigestFinal_ex(context_, result.data(), &length) == 1 &&
             length == result.size());
        return hex(result);
    }
};

struct WireClosure {
    std::string record_root;
    std::string end_frame;
    std::uint64_t record_count{};
    std::uint64_t payload_bytes{};
    std::uint64_t raw_wire_bytes{};
};

class SigpipeBlock final {
public:
    SigpipeBlock() {
        sigemptyset(&set_); sigaddset(&set_, SIGPIPE);
        need(pthread_sigmask(SIG_BLOCK, &set_, &old_) == 0);
        old_blocked_ = sigismember(&old_, SIGPIPE) == 1;
    }
    ~SigpipeBlock() { (void)pthread_sigmask(SIG_SETMASK, &old_, nullptr); }
    void consume() {
        if (old_blocked_) return;
        timespec zero{}; siginfo_t information{};
        while (sigtimedwait(&set_, &information, &zero) < 0 &&
               errno == EINTR) {}
    }
private:
    sigset_t set_{}; sigset_t old_{}; bool old_blocked_{};
};

void write_all(int fd, std::span<const unsigned char> value) {
    SigpipeBlock guard; std::size_t offset = 0;
    while (offset < value.size()) {
        const auto count = ::write(fd, value.data() + offset,
                                   value.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (errno == EPIPE) guard.consume();
            refuse();
        }
        offset += static_cast<std::size_t>(count);
    }
}
void close_noexcept(int& fd) noexcept {
    if (fd >= 0) { const int old = fd; fd = -1; (void)::close(old); }
}

class Writer final {
public:
    Writer(int fd, unsigned round, const Binding& binding)
        : fd_(fd) {
        try {
            need(fd_ >= 0 && (round == 1 || round == 2)); selected(binding);
            const auto hello = "{\"attempt_id\":" + quote(binding.attempt_id) +
                ",\"capture_identity\":" + quote(binding.capture_identity) +
                ",\"cohort_sha256\":" + quote(binding.cohort_sha256) +
                ",\"financial_run_id\":" + quote(binding.financial_run_id) +
                ",\"kind\":\"terminal-history-v2-control\",\"round\":" +
                std::to_string(round) +
                ",\"schema\":\"kpb-capture-event-channel/v1\"}\n";
            frame(1, bytes(hello));
            const auto meta = "{\"actual_network_execution\":false,"
                "\"actual_receipt\":false,\"amount_observations\":[],"
                "\"cohort_sha256\":" + quote(binding.cohort_sha256) +
                ",\"mode\":\"CONFIGURED0_NETWORK_DISABLED\","
                "\"privacy_measurement_usable\":false,"
                "\"projection_sha256\":" + quote(binding.projection_sha256) +
                ",\"round\":" + std::to_string(round) +
                ",\"schema\":\"kpb-terminal-observer-history/v2\","
                "\"scope\":\"PAYMENT_TERMINAL_STREAM_CONTROL_ONLY\","
                "\"status\":\"UNQUALIFIED_SOURCE_ONLY\"}\n";
            frame(2, bytes(meta));
        } catch (...) { close_noexcept(fd_); throw; }
    }
    ~Writer() { close_noexcept(fd_); }
    void record(const std::string& stream, const std::string& value) {
        const auto row = "{\"stream\":" + quote(stream) +
            ",\"value\":" + value + "}\n";
        frame(3, bytes(row));
    }
    WireClosure complete() {
        need(fd_ >= 0 && !complete_); frame(5, {});
        const int old = fd_; fd_ = -1; need(::close(old) == 0); complete_ = true;
        closure_.record_root = wire_hash_.finish();
        need(!closure_.end_frame.empty());
        return closure_;
    }
private:
    int fd_; bool complete_{};
    HashState wire_hash_;
    WireClosure closure_;
    void frame(unsigned char tag, std::span<const unsigned char> payload) {
        need(fd_ >= 0 && tag >= 1 && tag <= 5 && payload.size() <= (1U << 20));
        std::array<unsigned char, 17> header{};
        std::copy(MAGIC.begin(), MAGIC.end(), header.begin()); header[8] = tag;
        const std::uint64_t size = payload.size();
        for (unsigned index = 0; index < 8; ++index)
            header[9 + index] = static_cast<unsigned char>(
                size >> (8 * (7 - index)));
        try { write_all(fd_, header); write_all(fd_, payload); }
        catch (...) { close_noexcept(fd_); throw; }
        wire_hash_.update(header);
        wire_hash_.update(payload);
        ++closure_.record_count;
        closure_.payload_bytes += payload.size();
        closure_.raw_wire_bytes += header.size() + payload.size();
        if (tag == 5) {
            std::vector<unsigned char> end(header.begin(), header.end());
            end.insert(end.end(), payload.begin(), payload.end());
            closure_.end_frame = hash(end);
        }
    }
};

} // namespace

struct TerminalCaptureV2::Impl {
    Writer writer;
    unsigned round;
    unsigned stage{};
    std::uint64_t sequence{};
    std::uint64_t prior_time{};
    bool has_time{};
    bool mapping{};
    Binding binding;
    std::string candidate;
    std::string case_sha;
    std::string r0;
    std::string native_full;
    std::string final_checkpoint;
    std::string mapping_source_identity;
    std::string txid;
    std::string accepted_head;
    std::string settlement;
    unsigned explicit_owner_mapping_export_count{};
    bool owner_mapping_present{};
    bool grouping_source_complete{};
    bool explicit_owner_mapping_export_source_complete{};
    bool public_continuity_modeled_separately{};

    Impl(int fd, unsigned selected_round, const Binding& selected_binding)
        : writer(fd, selected_round, selected_binding),
          round(selected_round), binding(selected_binding) {}

    void event(const std::string& kind, const std::string& outcome,
               std::uint64_t time) {
        need(!has_time || time >= prior_time);
        const auto value = "{\"accepted_head_hex32\":" + optional(accepted_head) +
            ",\"candidate_sha256\":" + quote(candidate) +
            ",\"case_sha256\":" + quote(case_sha) +
            ",\"final_checkpoint_sha256\":" + optional(final_checkpoint) +
            ",\"kind\":" + quote(kind) +
            ",\"monotonic_ns\":" + std::to_string(time) +
            ",\"native_full_sha256\":" + optional(native_full) +
            ",\"outcome\":" + quote(outcome) +
            ",\"projection_sha256\":" + quote(binding.projection_sha256) +
            ",\"r0_receipt_sha256\":" + optional(r0) +
            ",\"sequence\":" + std::to_string(sequence++) +
            ",\"settlement_sha256\":" + optional(settlement) +
            ",\"transaction_id_hex32\":" + optional(txid) + '}';
        writer.record("event", value); prior_time = time; has_time = true;
    }
};

TerminalCaptureV2::TerminalCaptureV2(int fd, unsigned round,
                                     const Binding& binding)
    : impl_(new Impl(fd, round, binding)) {}
TerminalCaptureV2::~TerminalCaptureV2() = default;

template<class Stage>
void TerminalCaptureV2::consume(Stage& token, unsigned expected_stage) {
    need(token.live_ && token.owner_ == this && impl_->stage == expected_stage);
    token.live_ = false;
}
template<class Stage>
void TerminalCaptureV2::inspect(const Stage& token, unsigned expected_stage) {
    need(token.live_ && token.owner_ == this && impl_->stage == expected_stage);
}

CandidateConstructedV2 TerminalCaptureV2::after_candidate_constructed(
    std::uint64_t time, const std::string& candidate,
    const std::string& case_sha) {
    need(impl_->stage == 0); word(candidate); word(case_sha);
    impl_->candidate = candidate; impl_->case_sha = case_sha;
    impl_->event("candidate-constructed", "ok", time); impl_->stage = 1;
    return CandidateConstructedV2(this);
}
R0VerifiedV2 TerminalCaptureV2::after_r0_verified(
    CandidateConstructedV2&& token, std::uint64_t time,
    const std::string& r0, const std::string& projection) {
    consume(token, 1); word(r0); word(projection);
    need(projection == impl_->binding.projection_sha256);
    impl_->r0 = r0; impl_->event("r0-verified", "ok", time); impl_->stage = 2;
    return R0VerifiedV2(this);
}
NativeFullVerifiedV2 TerminalCaptureV2::after_native_full_verified(
    R0VerifiedV2&& token, std::uint64_t time, const std::string& native_full,
    const std::string& case_sha, const std::string& projection) {
    consume(token, 2); word(native_full); word(case_sha); word(projection);
    need(case_sha == impl_->case_sha &&
         projection == impl_->binding.projection_sha256);
    impl_->native_full = native_full;
    impl_->event("native-full-verified", "ok", time); impl_->stage = 3;
    return NativeFullVerifiedV2(this);
}
DurableFinalV2 TerminalCaptureV2::after_durable_final(
    NativeFullVerifiedV2&& token, std::uint64_t time,
    const std::string& checkpoint) {
    consume(token, 3); word(checkpoint); impl_->final_checkpoint = checkpoint;
    impl_->event("durable-final", "ok", time); impl_->stage = 4;
    return DurableFinalV2(this);
}
void TerminalCaptureV2::after_complete_mapping_source(
        const DurableFinalV2& token,
        native_terminal::NativeTerminalMappingSourceAuthority&& source) {
    inspect(token, 4);
    need(!impl_->mapping && source.live_.exchange(false));
    const auto& evidence = source.evidence_;
    need(evidence.round == impl_->round &&
         evidence.binding.attempt_id == impl_->binding.attempt_id &&
         evidence.binding.cohort_sha256 == impl_->binding.cohort_sha256 &&
         evidence.binding.financial_run_id ==
             impl_->binding.financial_run_id &&
         evidence.binding.capture_identity == impl_->binding.capture_identity &&
         evidence.binding.projection_sha256 ==
             impl_->binding.projection_sha256 &&
         evidence.binding.construction_classification ==
             impl_->binding.construction_classification &&
         evidence.binding.construction_attempt_sha256 ==
             impl_->binding.construction_attempt_sha256 &&
         evidence.binding.capture_plan_sha256 ==
             impl_->binding.capture_plan_sha256 &&
         evidence.grouping_source_complete &&
         evidence.explicit_owner_mapping_export_source_complete &&
         evidence.public_continuity_modeled_separately &&
         evidence.owner_mapping_present != evidence.owner_mapping_absent &&
         ((evidence.classification ==
               kpi::mpc::financial::registered_driver::
                   CaptureClassification::HiddenCandidate &&
           evidence.owner_mapping_absent) ||
          (evidence.classification ==
               kpi::mpc::financial::registered_driver::
                   CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
           evidence.owner_mapping_present)));

    std::array<std::string, 3> nfs{};
    std::array<std::string, 6> tuples{};
    for (unsigned index = 0; index < nfs.size(); ++index)
        nfs[index] = hex(evidence.nullifiers[index]);
    for (unsigned index = 0; index < tuples.size(); ++index)
        tuples[index] = hex(evidence.tuple_hashes[index]);
    const auto source_identity = hex(evidence.source_identity);
    word(source_identity);

    // Group identifiers are derived only from the public projection and the
    // public grouping rows written beside them.  The private mapping-source
    // identity also binds route/intake/process lineage, so emitting it here
    // would turn this stream into a route-linkage oracle.
    const auto candidate_group_id = [&] {
        std::vector<unsigned char> preimage;
        static constexpr std::string_view domain =
            "KPB_NATIVE_TERMINAL_CANDIDATE_GROUP_V1\n";
        preimage.insert(preimage.end(), domain.begin(), domain.end());
        preimage.insert(preimage.end(),
                        impl_->binding.projection_sha256.begin(),
                        impl_->binding.projection_sha256.end());
        for (const auto& value : evidence.nullifiers)
            preimage.insert(preimage.end(), value.begin(), value.end());
        for (const auto& value : evidence.tuple_hashes)
            preimage.insert(preimage.end(), value.begin(), value.end());
        return hash(preimage);
    }();

    if (evidence.owner_mapping_absent) {
        const auto value = "{\"group_id_sha256\":" +
            quote(candidate_group_id) + ",\"nfs_hex32\":" +
            string_array(nfs) +
            ",\"owner_component_absent\":true,"
            "\"privacy_measurement_usable\":false,"
            "\"projection_sha256\":" +
            quote(impl_->binding.projection_sha256) +
            ",\"source_complete\":true,\"tuple_sha256\":" +
            string_array(tuples) + '}';
        impl_->writer.record("group", value);
    } else {
        for (unsigned owner = 0; owner < 3; ++owner) {
            std::vector<unsigned char> preimage;
            static constexpr std::string_view domain =
                "KPB_NATIVE_TERMINAL_BASELINE_GROUP_V1\n";
            preimage.insert(preimage.end(), domain.begin(), domain.end());
            preimage.insert(preimage.end(),
                            impl_->binding.projection_sha256.begin(),
                            impl_->binding.projection_sha256.end());
            preimage.push_back(static_cast<unsigned char>(owner));
            preimage.insert(preimage.end(),
                            evidence.owner_nullifiers[owner].begin(),
                            evidence.owner_nullifiers[owner].end());
            for (const auto& row : evidence.owner_tuple_hashes[owner])
                preimage.insert(preimage.end(), row.begin(), row.end());
            const auto group_id = hash(preimage);
            const std::array<std::string, 1> owner_nf{
                hex(evidence.owner_nullifiers[owner])};
            const std::array<std::string, 2> owner_tuples{
                hex(evidence.owner_tuple_hashes[owner][0]),
                hex(evidence.owner_tuple_hashes[owner][1])};
            const auto value = "{\"group_id_sha256\":" + quote(group_id) +
                ",\"nfs_hex32\":" + string_array(owner_nf) +
                ",\"owner_component\":" + std::to_string(owner) +
                ",\"privacy_measurement_usable\":false,"
                "\"projection_sha256\":" +
                quote(impl_->binding.projection_sha256) +
                ",\"source_complete\":true,\"tuple_sha256\":" +
                string_array(owner_tuples) + '}';
            impl_->writer.record("group", value);
        }
    }
    const auto closure =
        "{\"cross_round_owner_nf_tuple_export_count\":0,"
        "\"cross_round_owner_nf_tuple_exports_source_complete\":true,"
        "\"grouping_source_complete\":true,"
        "\"owner_component_present\":" +
        std::string(evidence.owner_mapping_present ? "true" : "false") +
        ",\"privacy_measurement_usable\":false,"
        "\"public_continuity_modeled_separately\":true}";
    impl_->writer.record("mapping-complete", closure);
    impl_->mapping = true;
    impl_->mapping_source_identity = source_identity;
    impl_->explicit_owner_mapping_export_count = 0;
    impl_->owner_mapping_present = evidence.owner_mapping_present;
    impl_->grouping_source_complete = true;
    impl_->explicit_owner_mapping_export_source_complete = true;
    impl_->public_continuity_modeled_separately = true;
}

PreNetworkTerminalClosedV2
TerminalCaptureV2::after_pre_network_capture_closed(
        DurableFinalV2&& token, std::uint64_t time) {
    consume(token, 4);
    need(impl_->mapping && impl_->grouping_source_complete &&
         impl_->explicit_owner_mapping_export_source_complete &&
         impl_->public_continuity_modeled_separately);
    impl_->event("pre-network-capture-closed", "ok", time);
    const auto wire = impl_->writer.complete();
    impl_->stage = 14;
    return PreNetworkTerminalClosedV2(
        PreNetworkTerminalClosedV2::PrivateEvidence{
            .round = impl_->round,
            .binding = impl_->binding,
            .candidate_sha256 = impl_->candidate,
            .case_sha256 = impl_->case_sha,
            .r0_receipt_sha256 = impl_->r0,
            .native_full_sha256 = impl_->native_full,
            .final_checkpoint_sha256 = impl_->final_checkpoint,
            .mapping_source_identity = impl_->mapping_source_identity,
            .record_root_sha256 = wire.record_root,
            .end_frame_sha256 = wire.end_frame,
            .record_count = wire.record_count,
            .payload_bytes = wire.payload_bytes,
            .raw_wire_bytes = wire.raw_wire_bytes,
            .explicit_owner_mapping_export_count =
                impl_->explicit_owner_mapping_export_count,
            .owner_mapping_present = impl_->owner_mapping_present,
            .grouping_source_complete = impl_->grouping_source_complete,
            .explicit_owner_mapping_export_source_complete =
                impl_->explicit_owner_mapping_export_source_complete,
            .public_continuity_modeled_separately =
                impl_->public_continuity_modeled_separately,
            .end_written = true,
            .writer_closed = true,
        });
}
SubmitAttemptedV2 TerminalCaptureV2::after_testnet_submit_attempted(
    DurableFinalV2&& token, std::uint64_t time, const std::string& txid) {
    consume(token, 4); need(impl_->mapping); word(txid); impl_->txid = txid;
    impl_->event("testnet-submit-attempted", "ok", time); impl_->stage = 5;
    return SubmitAttemptedV2(this);
}
SubmitAcknowledgedV2 TerminalCaptureV2::after_testnet_submit_acknowledged(
    SubmitAttemptedV2&& token, std::uint64_t time, const std::string& txid) {
    consume(token, 5); word(txid); need(txid == impl_->txid);
    impl_->event("testnet-submit-acknowledged", "acknowledged", time);
    impl_->stage = 6; return SubmitAcknowledgedV2(this);
}
void TerminalCaptureV2::after_testnet_submit_unknown(
    SubmitAttemptedV2&& token, std::uint64_t time, const std::string& txid) {
    consume(token, 5); word(txid); need(txid == impl_->txid);
    impl_->event("testnet-submit-unknown", "unknown", time);
    impl_->writer.complete(); impl_->stage = 10;
}
[[noreturn]] void TerminalCaptureV2::after_testnet_submit_rejected(
    SubmitAcknowledgedV2&& token, std::uint64_t time) {
    consume(token, 6); need(!impl_->has_time || time >= impl_->prior_time);
    const auto rejected = "{\"candidate_sha256\":" + quote(impl_->candidate) +
        ",\"case_sha256\":" + quote(impl_->case_sha) +
        ",\"status\":\"rejected\",\"transaction_id_hex32\":" +
        quote(impl_->txid) + '}';
    impl_->writer.record("rejected-or-orphaned", rejected);
    impl_->event("testnet-submit-rejected", "rejected", time);
    impl_->writer.complete(); impl_->stage = 12; refuse();
}
AcceptedCaseV2 TerminalCaptureV2::after_accepted_case(
    SubmitAcknowledgedV2&& token, std::uint64_t time,
    const std::string& case_sha, const std::string& txid,
    const std::string& accepted_head) {
    consume(token, 6); word(case_sha); word(txid); word(accepted_head);
    need(case_sha == impl_->case_sha && txid == impl_->txid);
    impl_->accepted_head = accepted_head;
    impl_->event("accepted-case", "ok", time); impl_->stage = 7;
    return AcceptedCaseV2(this);
}
[[noreturn]] void TerminalCaptureV2::after_accepted_case_reorged(
    AcceptedCaseV2&& token, std::uint64_t time, const std::string& old_head,
    const std::string& new_head, std::uint64_t depth) {
    consume(token, 7); word(old_head); word(new_head);
    need(!impl_->has_time || time >= impl_->prior_time);
    need(old_head == impl_->accepted_head && new_head != old_head && depth > 0);
    const auto reorg = "{\"accepted_head_hex32\":" + quote(impl_->accepted_head) +
        ",\"candidate_sha256\":" + quote(impl_->candidate) +
        ",\"depth\":" + std::to_string(depth) +
        ",\"new_head_hex32\":" + quote(new_head) +
        ",\"old_head_hex32\":" + quote(old_head) +
        ",\"transaction_id_hex32\":" + quote(impl_->txid) + '}';
    impl_->writer.record("reorg", reorg);
    const auto orphaned = "{\"candidate_sha256\":" + quote(impl_->candidate) +
        ",\"case_sha256\":" + quote(impl_->case_sha) +
        ",\"status\":\"orphaned\",\"transaction_id_hex32\":" +
        quote(impl_->txid) + '}';
    impl_->writer.record("rejected-or-orphaned", orphaned);
    impl_->event("accepted-case-orphaned", "orphaned", time);
    impl_->writer.complete(); impl_->stage = 11; refuse();
}
[[noreturn]] void TerminalCaptureV2::after_accepted_case_orphaned(
    AcceptedCaseV2&& token, std::uint64_t time) {
    consume(token, 7); need(!impl_->has_time || time >= impl_->prior_time);
    const auto orphaned = "{\"candidate_sha256\":" + quote(impl_->candidate) +
        ",\"case_sha256\":" + quote(impl_->case_sha) +
        ",\"status\":\"orphaned\",\"transaction_id_hex32\":" +
        quote(impl_->txid) + '}';
    impl_->writer.record("rejected-or-orphaned", orphaned);
    impl_->event("accepted-case-orphaned", "orphaned", time);
    impl_->writer.complete(); impl_->stage = 13; refuse();
}
ResolvedSettlementV2 TerminalCaptureV2::after_durable_settlement_resolved(
    AcceptedCaseV2&& token, std::uint64_t time,
    const std::string& settlement) {
    consume(token, 7); word(settlement); impl_->settlement = settlement;
    impl_->event("durable-settlement-resolved", "ok", time); impl_->stage = 8;
    return ResolvedSettlementV2(this);
}
void TerminalCaptureV2::after_trial_closed(
    ResolvedSettlementV2&& token, std::uint64_t time) {
    consume(token, 8); impl_->event("trial-closed", "ok", time);
    impl_->writer.complete(); impl_->stage = 9;
}

} // namespace kpb::capture

namespace kpb::native_terminal {

NativeTerminalChildEvidenceBridge::Evidence
NativeTerminalChildEvidenceBridge::consume(
        capture::PreNetworkTerminalClosedV2&& token) {
    capture::need(token.live_);
    token.live_ = false;
    const auto& evidence = token.evidence_;
    capture::need(evidence.round >= 1 && evidence.round <= 2 &&
                  evidence.record_count >= 8 &&
                  evidence.payload_bytes > 0 &&
                  evidence.raw_wire_bytes > evidence.payload_bytes &&
                  evidence.grouping_source_complete &&
                  evidence.explicit_owner_mapping_export_source_complete &&
                  evidence.public_continuity_modeled_separately &&
                  evidence.end_written && evidence.writer_closed);
    capture::selected(evidence.binding);
    for (const auto* value : {
             &evidence.candidate_sha256, &evidence.case_sha256,
             &evidence.r0_receipt_sha256,
             &evidence.native_full_sha256,
             &evidence.final_checkpoint_sha256,
             &evidence.mapping_source_identity, &evidence.record_root_sha256,
             &evidence.end_frame_sha256})
        capture::word(*value);
    return Evidence{
        .round = evidence.round,
        .binding = evidence.binding,
        .candidate_sha256 = evidence.candidate_sha256,
        .case_sha256 = evidence.case_sha256,
        .r0_receipt_sha256 = evidence.r0_receipt_sha256,
        .native_full_sha256 = evidence.native_full_sha256,
        .final_checkpoint_sha256 = evidence.final_checkpoint_sha256,
        .mapping_source_identity = evidence.mapping_source_identity,
        .record_root_sha256 = evidence.record_root_sha256,
        .end_frame_sha256 = evidence.end_frame_sha256,
        .record_count = evidence.record_count,
        .payload_bytes = evidence.payload_bytes,
        .raw_wire_bytes = evidence.raw_wire_bytes,
        .explicit_owner_mapping_export_count =
            evidence.explicit_owner_mapping_export_count,
        .owner_mapping_present = evidence.owner_mapping_present,
        .grouping_source_complete = evidence.grouping_source_complete,
        .explicit_owner_mapping_export_source_complete =
            evidence.explicit_owner_mapping_export_source_complete,
        .public_continuity_modeled_separately =
            evidence.public_continuity_modeled_separately,
        .end_written = evidence.end_written,
        .writer_closed = evidence.writer_closed,
    };
}

} // namespace kpb::native_terminal

namespace kpb::capture {

#ifdef KPB_TERMINAL_CAPTURE_V2_TEST_SETUP
void PreNetworkTerminalClosedV2::test_only_consume() {
    (void)native_terminal::NativeTerminalChildEvidenceBridge::consume(
        std::move(*this));
}
#endif

} // namespace kpb::capture
