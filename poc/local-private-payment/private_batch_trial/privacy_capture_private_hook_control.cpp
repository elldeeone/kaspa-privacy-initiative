#include "privacy_capture_private_hook.hpp"

#include <array>
#include <iostream>
#include <iterator>
#include <string>
#include <unistd.h>
#include <vector>

namespace {
using namespace kpb::capture;

std::string repeated(const std::string& pair) {
    std::string result;
    for (unsigned index = 0; index < 32; ++index) result += pair;
    return result;
}

Binding round_one() {
    return Binding{
        .attempt_id = "33333333-3333-4333-8333-333333333333",
        .cohort_sha256 = repeated("31"),
        .financial_run_id = repeated("15"),
        .capture_identity = "22222222-2222-4222-8222-222222222222",
        .projection_sha256 =
            "4a4bc3cecb21d11fcbdd2784f0199d781e266d231942fa6d3bcd25670c237d02",
        .construction_classification = 1,
        .construction_attempt_sha256 = repeated("43"),
        .capture_plan_sha256 = repeated("44"),
    };
}

std::array<std::string, 3> colluder_operations() {
    return {repeated("66"), repeated("88"), repeated("99")};
}

void alias_stdout(int target) {
    if (::dup2(STDOUT_FILENO, target) != target) throw CaptureRefused();
}

std::array<unsigned char, 32> field(unsigned value) {
    std::array<unsigned char, 32> result{};
    result[0] = static_cast<unsigned char>(value);
    return result;
}

template<class Range>
void append(std::vector<unsigned char>& destination, const Range& source) {
    destination.insert(destination.end(), source.begin(), source.end());
}

std::vector<unsigned char> point(unsigned value, std::size_t size) {
    if (size != 65 && size != 129) throw CaptureRefused();
    std::vector<unsigned char> result{1};
    for (std::size_t index = 0; index < (size - 1) / 32; ++index)
        append(result, field(value + index));
    return result;
}

std::vector<unsigned char> authenticated_g1(unsigned value) {
    auto result = point(value, 65);
    append(result, point(value + 2, 65));
    return result;
}

std::vector<unsigned char> authenticated_g2(unsigned value) {
    auto result = point(value, 129);
    append(result, point(value + 4, 129));
    return result;
}

std::vector<unsigned char> authenticated_g1_sequence(
    std::initializer_list<unsigned> values) {
    std::vector<unsigned char> result;
    for (const auto value : values) append(result, authenticated_g1(value));
    return result;
}

std::vector<unsigned char> filled(std::size_t size, unsigned char value) {
    return std::vector<unsigned char>(size, value);
}

const std::array<std::string, 3> NFS{{
    "6500000000000000000000000000000000000000000000000000000000000000",
    "6600000000000000000000000000000000000000000000000000000000000000",
    "6700000000000000000000000000000000000000000000000000000000000000",
}};
const std::array<std::string, 6> TUPLES{{
    "7f478ad54b53ed976f694e0c539b548527196b74cffd2f2abfc2efc6b7af1b65",
    "c946eb7cbae77146751602bf555d66a652d58f592b550c851bd9c18b9c95b036",
    "8bca61d0dab726a0fee5a99f68479f4146e01a0709b461e2b6ddb1dfd961e70e",
    "2a1cb37437186ad27ffb601a0073ccc65e35ff386ee2400f2c68241bfdcc31e6",
    "707645a27ff40346ab6e87438576824cdf1c2f533eaaff2e5ab43d70b03d1303",
    "ac97f6036e3247bb4ed2c2b937dc1ecc7bf337b92b3962b51535975a6d2ef7c6",
}};
const std::array<std::string, 6> CMS{{
    "d69c71be208dd63c585c17bd2f4f43cb8ef8b323e2fde08b2d0511afb67e1f91",
    "a2285050278a30c46a4043e97262b7977fc010fc18525aa4e22d9406545153a9",
    "69bde92d4fe30173a2e300b785b23207dd63a01cc96ccce05d62db53ed29544d",
    "66fc005351de1e50ed85d33da029cdb903067ea4b7aa5b15dd7561bb9e0e71ac",
    "3a8a1830bec818aa4365ca576d1b631f1a94c863c0d46b168fde16bd68dddc98",
    "f44842c35f2000f683fe2d0b1b438a04012d8804871f9717747bc2c76eea85c3",
}};

template<class Hook>
void valid_terminal(Hook& hook, bool finish = true) {
    const auto candidate = repeated("44");
    hook.candidate_constructed(10, candidate);
    hook.native_full(11, candidate);
    hook.trial_closed(12, candidate);
    hook.hidden_group(repeated("55"), NFS, TUPLES);
    if (finish) hook.close_complete();
}

template<class Hook>
void valid_colluder(Hook& hook, bool finish = true) {
    hook.issued_invoice(0, repeated("66"), 25000000);
    hook.accepted_invoice(2, repeated("66"), 30000000);
    hook.original(NFS[1], 100000000, TUPLES[2], 30000000,
                  TUPLES[3], 69000000);
    hook.incoming_receipt(1, 0, TUPLES[0], CMS[0], 25000000);
    hook.change_receipt(2, TUPLES[3], CMS[3], 69000000);
    if (finish) hook.close_complete();
}

template<class Hook>
void valid_corrupt(Hook& hook, const std::vector<unsigned char>& projection,
                   bool leak = false, bool finish = true) {
    for (unsigned owner = 0; owner < 3; ++owner) {
        std::vector<unsigned char> preprocessing;
        for (unsigned index = 0; index < 5; ++index)
            append(preprocessing, field(owner * 5 + index + 1));
        hook.owner_input_preprocessing_share(owner, preprocessing);
        auto offset = field(owner + 7);
        if (leak && owner == 0) offset = field(0x65);
        hook.owner_input_offset(owner, offset);
    }
    const std::array<unsigned char, 6> mascot{{'M', 'A', 'S', 'C', 'O', 'T'}};
    hook.mascot_message(mascot);
    auto mac_key = field(29); hook.mac_key_share(mac_key);
    auto authenticated = field(31); hook.authenticated_share(authenticated);
    auto mac = field(37); hook.mac_share(mac);
    auto randomness = field(41); hook.randomness_share(randomness);
    auto randomness_mac = field(43); hook.randomness_mac(randomness_mac);
    auto opening = field(47); hook.field_opening(opening);

    auto a = authenticated_g1(80);
    auto base_g1 = authenticated_g1_sequence({80, 82, 84, 86});
    auto b2 = authenticated_g2(106);
    hook.authenticated_g1_state(1, base_g1);
    hook.authenticated_g2_state(1, b2);
    auto mixed = authenticated_g1_sequence({88, 90, 92, 94, 96, 98});
    hook.authenticated_g1_state(2, mixed);

    std::vector<unsigned char> masked_field;
    append(masked_field, field(53)); append(masked_field, field(59));
    hook.masked_field_intermediate(masked_field);
    hook.masked_g1_intermediate(filled(130, 61));

    auto products = authenticated_g1_sequence({100, 102});
    hook.authenticated_g1_state(3, products);
    auto final_g1 = a; append(final_g1, authenticated_g1(104));
    hook.authenticated_g1_state(4, final_g1);
    hook.authenticated_g2_state(4, b2);
    hook.final_proof_g1(filled(130, 67));
    hook.final_proof_g2(filled(129, 71));
    hook.public_projection(projection);
    if (finish) hook.close_complete();
}

std::vector<unsigned char> stdin_bytes() {
    return {std::istreambuf_iterator<char>(std::cin), {}};
}

int run(const std::string& scenario) {
    if (scenario == "terminal") {
        alias_stdout(21); TerminalHook<21, 1> hook(round_one());
        valid_terminal(hook); return 0;
    }
    if (scenario == "corrupt" || scenario == "corrupt-leak") {
        alias_stdout(23); auto body = stdin_bytes();
        CorruptServerHook<23, 1> hook(round_one(), repeated("33"));
        valid_corrupt(hook, body, scenario == "corrupt-leak"); return 0;
    }
    if (scenario == "colluder") {
        alias_stdout(24); ColluderWalletHook<24, 1> hook(
            round_one(), colluder_operations());
        valid_colluder(hook); return 0;
    }
    if (scenario == "colluder-retry") {
        alias_stdout(24); ColluderWalletHook<24, 1> hook(
            round_one(), colluder_operations());
        valid_colluder(hook, false);
        hook.retry("changed-cohort", 20, 21, RetryOutcome::Refused);
        hook.close_complete(); return 0;
    }
    if (scenario == "terminal-cross-link") {
        alias_stdout(21); TerminalHook<21, 1> hook(round_one());
        valid_terminal(hook, false);
        hook.cross_round_link(
            NFS[0], 2,
            "7906fcb95e763a1b1a60fdef5e37ab1f649e6560bceb53af0122559620079cac");
        hook.close_complete(); return 0;
    }
    if (scenario == "terminal-missing-close") {
        alias_stdout(21); TerminalHook<21, 1> hook(round_one());
        valid_terminal(hook, false); throw CaptureRefused();
    }
    if (scenario == "terminal-extra-group") {
        alias_stdout(21); TerminalHook<21, 1> hook(round_one());
        valid_terminal(hook, false); hook.hidden_group(repeated("56"), NFS, TUPLES);
        return 0;
    }
    if (scenario == "corrupt-out-of-order") {
        alias_stdout(23); CorruptServerHook<23, 1> hook(
            round_one(), repeated("33"));
        const std::array<unsigned char, 1> payload{{1}};
        hook.mascot_message(payload); return 0;
    }
    if (scenario == "corrupt-early-close") {
        alias_stdout(23); CorruptServerHook<23, 1> hook(
            round_one(), repeated("33"));
        std::vector<unsigned char> preprocessing;
        for (unsigned index = 0; index < 5; ++index)
            append(preprocessing, field(index + 1));
        hook.owner_input_preprocessing_share(0, preprocessing);
        hook.close_complete(); return 0;
    }
    if (scenario == "colluder-extra-original") {
        alias_stdout(24); ColluderWalletHook<24, 1> hook(
            round_one(), colluder_operations());
        hook.issued_invoice(0, repeated("66"), 25000000);
        hook.accepted_invoice(2, repeated("66"), 30000000);
        hook.original(NFS[1], 100000000, TUPLES[2], 30000000,
                      TUPLES[3], 69000000);
        hook.original(NFS[1], 100000000, TUPLES[2], 30000000,
                      TUPLES[3], 69000000); return 0;
    }
    if (scenario == "colluder-out-of-order") {
        alias_stdout(24); ColluderWalletHook<24, 1> hook(
            round_one(), colluder_operations());
        hook.accepted_invoice(2, repeated("66"), 30000000); return 0;
    }
    if (scenario == "colluder-early-close") {
        alias_stdout(24); ColluderWalletHook<24, 1> hook(
            round_one(), colluder_operations());
        hook.issued_invoice(0, repeated("66"), 25000000);
        hook.close_complete(); return 0;
    }
    if (scenario == "wrong-fd") {
        (void)::close(21); TerminalHook<21, 1> hook(round_one());
        (void)hook; return 0;
    }
    if (scenario == "terminal-alternate-history") {
        alias_stdout(21); TerminalHook<21, 1> hook(round_one());
        valid_terminal(hook, false);
        hook.retry("retry-refused", RetryOutcome::Refused, repeated("aa"));
        hook.retry("retry-orphaned", RetryOutcome::Orphaned, repeated("bb"));
        hook.retry("retry-disconnected", RetryOutcome::Disconnected,
                   repeated("cc"));
        hook.rejected_or_orphaned(repeated("aa"), RejectedStatus::Rejected);
        hook.rejected_or_orphaned(repeated("bb"), RejectedStatus::Orphaned);
        hook.reorg(repeated("dd"), repeated("ee"), 1);
        hook.close_complete(); return 0;
    }
    throw CaptureRefused();
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 2) throw CaptureRefused();
        return run(argv[1]);
    } catch (...) {
        static constexpr char message[] =
            "KPB_CAPTURE_PRIVATE_HOOK_REFUSED\n";
        const auto ignored = ::write(
            STDERR_FILENO, message, sizeof(message) - 1);
        (void)ignored;
        return 78;
    }
}
