#include "owner_file_format_v1.hpp"
#include <fstream>
#include <functional>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

using kpi::mpc::financial::load_owner_input_file;
namespace fs = std::filesystem;
static constexpr const char* P = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
static constexpr const char* PM1 = "21888242871839275222246405745257275088548364400416034343698204186575808495616";

int main() {
    char temporary[] = "/tmp/kpb-public-owner-file-controls-XXXXXX";
    const auto* created = ::mkdtemp(temporary);
    if (!created) return 2;
    const fs::path root(created);
    size_t controls = 0;
    const auto field = [](const std::string& text) {
        const std::string modulus(P);
        if (text.size() > modulus.size() || (text.size() == modulus.size() && text >= modulus))
            throw std::runtime_error("public-test-field-range");
        return text;
    };
    const std::string valid = std::string("KPB_OWNER_INPUT_V1\nOWNER owner0\nCOUNT 3\nVALUES\n0\n1\n") + PM1 + "\nEND\n";
    auto write = [&](const std::string& name, const std::string& text, mode_t mode = 0600) {
        const auto path = root / name;
        std::ofstream file(path, std::ios::binary); file << text; file.close();
        if (::chmod(path.c_str(), mode)) throw std::runtime_error("public-test-mode");
        return path;
    };
    auto reject = [&](const std::string& name, const std::function<void()>& call) {
        bool refused = false;
        try { call(); } catch (const std::exception&) { refused = true; }
        if (!refused) throw std::runtime_error("public-negative-not-refused:" + name);
        ++controls;
    };
    try {
        const auto baseline = write("public-valid.txt", valid);
        const auto values = load_owner_input_file(baseline, 0, 3, field);
        if (values.size() != 3 || values[0] != "0" || values[1] != "1" || values[2] != PM1)
            throw std::runtime_error("public-positive-fields");
        ++controls;
        auto malformed = [&](const std::string& name, std::string text) {
            const auto path = write(name, text);
            reject(name, [&] { (void)load_owner_input_file(path, 0, 3, field); });
        };
        malformed("wrong-version", "KPB_OWNER_INPUT_V2 OWNER owner0 COUNT 3 VALUES 0 1 2 END");
        malformed("wrong-role", "KPB_OWNER_INPUT_V1 OWNER owner1 COUNT 3 VALUES 0 1 2 END");
        malformed("role-alias", "KPB_OWNER_INPUT_V1 OWNER owner00 COUNT 3 VALUES 0 1 2 END");
        malformed("count-alias", "KPB_OWNER_INPUT_V1 OWNER owner0 COUNT 03 VALUES 0 1 2 END");
        malformed("wrong-count", "KPB_OWNER_INPUT_V1 OWNER owner0 COUNT 4 VALUES 0 1 2 3 END");
        malformed("overflow-count", "KPB_OWNER_INPUT_V1 OWNER owner0 COUNT 18446744073709551616 VALUES 0 1 2 END");
        malformed("truncated-header", "KPB_OWNER_INPUT_V1 OWNER owner0 COUNT");
        malformed("truncated-values", "KPB_OWNER_INPUT_V1 OWNER owner0 COUNT 3 VALUES 0 1");
        malformed("excess-values", "KPB_OWNER_INPUT_V1 OWNER owner0 COUNT 3 VALUES 0 1 2 3 END");
        malformed("missing-end", "KPB_OWNER_INPUT_V1 OWNER owner0 COUNT 3 VALUES 0 1 2");
        malformed("trailing-token", valid + "extra");
        malformed("negative-field", "KPB_OWNER_INPUT_V1 OWNER owner0 COUNT 3 VALUES 0 -1 2 END");
        malformed("field-alias", "KPB_OWNER_INPUT_V1 OWNER owner0 COUNT 3 VALUES 0 01 2 END");
        malformed("signed-field", "KPB_OWNER_INPUT_V1 OWNER owner0 COUNT 3 VALUES 0 +1 2 END");
        malformed("decimal-field", "KPB_OWNER_INPUT_V1 OWNER owner0 COUNT 3 VALUES 0 1.0 2 END");
        malformed("Fr-P-alias", std::string("KPB_OWNER_INPUT_V1 OWNER owner0 COUNT 3 VALUES 0 1 ") + P + " END");
        malformed("huge-field", "KPB_OWNER_INPUT_V1 OWNER owner0 COUNT 3 VALUES 0 1 " + std::string(129, '9') + " END");
        const auto broad = write("public-broad.txt", valid, 0644);
        reject("broad-mode", [&] { (void)load_owner_input_file(broad, 0, 3, field); });
        const auto symlink = root / "public-symlink"; fs::create_symlink(baseline, symlink);
        reject("symlink", [&] { (void)load_owner_input_file(symlink, 0, 3, field); });
        const auto directory_link = root / "directory-link"; fs::create_directory_symlink(root, directory_link);
        reject("parent-symlink", [&] { (void)load_owner_input_file(directory_link / "public-valid.txt", 0, 3, field); });
        const auto hardlink = root / "public-hardlink"; fs::create_hard_link(baseline, hardlink);
        reject("hardlink", [&] { (void)load_owner_input_file(hardlink, 0, 3, field); });
        fs::remove(hardlink);
        const auto fifo = root / "public-fifo";
        if (::mkfifo(fifo.c_str(), 0600)) throw std::runtime_error("public-fifo-create");
        reject("fifo-nonblocking-refusal", [&] { (void)load_owner_input_file(fifo, 0, 3, field); });
        reject("selected-role-refusal", [&] { (void)load_owner_input_file(baseline, 3, 3, field); });
        reject("selected-count-refusal", [&] { (void)load_owner_input_file(baseline, 0, 0, field); });
        const auto mutation = write("public-mutation.txt", valid);
        bool changed = false;
        reject("mutated-during-read", [&] {
            (void)load_owner_input_file(mutation, 0, 3, [&](const std::string& text) {
                if (!changed) { std::ofstream append(mutation, std::ios::app); append << '\n'; changed = true; }
                return field(text);
            });
        });
        fs::remove_all(root);
        std::cout << "{\"scope\":\"PUBLIC_FILE_GRAMMAR_CONTROLS_ONLY\",\"controls\":" << controls
                  << ",\"status\":\"PASS\",\"private_wallet_or_network_used\":false}\n";
        return 0;
    } catch (...) {
        fs::remove_all(root);
        std::cerr << "{\"status\":\"PUBLIC_OWNER_FILE_CONTROL_FAILURE\"}\n";
        return 1;
    }
}
