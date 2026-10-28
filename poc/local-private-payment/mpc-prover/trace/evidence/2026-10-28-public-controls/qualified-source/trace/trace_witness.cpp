#include "trace_witness.hpp"
#include "bit_add.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unordered_map>
#ifdef KPI_TRACE_PUBLIC_CONTROLS
#include "public_reference.hpp"
#endif

namespace kpi::mpc {
namespace {

[[noreturn]] void refuse(const char* category) {
    throw std::runtime_error(category);
}

bool hex_digest(const std::string& value) {
    return value.size() == 64 &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

struct PublicTerm {
    Fr coefficient;
    size_t column;
};
using Linear = std::vector<PublicTerm>;

struct Operation {
    enum Kind { LinearOp, MulAdd, AddBits, AssertZero, RandomBit } kind;
    size_t target = 0;
    Linear a, b, c;
    size_t width = 0;
    size_t words = 0;
    std::vector<size_t> outputs;
    std::vector<Linear> bits;
};

std::string token(std::istream& input) {
    std::string value;
    if (!(input >> value))
        refuse("trace-unexpected-end");
    return value;
}

void label(std::istream& input, const char* expected) {
    if (token(input) != expected)
        refuse("trace-tag-or-order");
}

size_t natural(std::istream& input) {
    const auto value = token(input);
    if (value.empty() || (value.size() > 1 && value[0] == '0') ||
        !std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return c >= '0' && c <= '9';
        }))
        refuse("trace-noncanonical-integer");
    size_t result = 0;
    for (auto c : value) {
        const auto digit = static_cast<size_t>(c - '0');
        if (result > (std::numeric_limits<size_t>::max() - digit) / 10)
            refuse("trace-integer-overflow");
        result = result * 10 + digit;
    }
    return result;
}

std::string digest_token(std::istream& input) {
    auto result = token(input);
    if (!hex_digest(result))
        refuse("trace-digest-encoding");
    return result;
}

struct stat file_metadata(const std::filesystem::path& path) {
    struct stat result {};
    if (lstat(path.c_str(), &result) != 0 || !S_ISREG(result.st_mode) ||
        result.st_size < 0)
        refuse("trace-public-file-type");
    return result;
}

bool same_metadata(const struct stat& first, const struct stat& second) {
    return first.st_dev == second.st_dev && first.st_ino == second.st_ino &&
           first.st_size == second.st_size &&
           first.st_mtim.tv_sec == second.st_mtim.tv_sec &&
           first.st_mtim.tv_nsec == second.st_mtim.tv_nsec;
}

std::string digest_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input)
        refuse("trace-public-file-open");
    using Digest = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Digest context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
        refuse("trace-hash-initialization");
    std::array<char, 65536> buffer;
    while (input) {
        input.read(buffer.data(), buffer.size());
        if (input.gcount() &&
            EVP_DigestUpdate(context.get(), buffer.data(), input.gcount()) != 1)
            refuse("trace-hash-update");
    }
    if (!input.eof())
        refuse("trace-public-file-read");
    std::array<unsigned char, EVP_MAX_MD_SIZE> bytes;
    unsigned length = 0;
    if (EVP_DigestFinal_ex(context.get(), bytes.data(), &length) != 1 || length != 32)
        refuse("trace-hash-finalization");
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (size_t i = 0; i < length; ++i) {
        result += digits[bytes[i] >> 4];
        result += digits[bytes[i] & 15];
    }
    return result;
}

TraceHeader header(std::istream& input, size_t bytes, const TraceBinding& expected) {
    label(input, "KPB_TRACE_V1");
    label(input, "FIELD");
    if (token(input) != FR_MODULUS)
        refuse("trace-field");
    TraceHeader result;
    label(input, "SOURCE_SHA256"); result.source_sha256 = digest_token(input);
    label(input, "MODEL_SHA256"); result.model_sha256 = digest_token(input);
    label(input, "LAYOUT_SHA256"); result.layout_sha256 = digest_token(input);
    label(input, "MODEL_VARIABLES"); result.model_variables = natural(input);
    label(input, "VARIABLES"); result.variables = natural(input);
    label(input, "INSTANCES"); result.instances = natural(input);
    if (result.source_sha256 != expected.source_sha256 ||
        result.model_sha256 != expected.model_sha256 ||
        result.layout_sha256 != expected.layout_sha256 ||
        result.model_variables != expected.model_variables ||
        result.instances != expected.instances || result.model_variables == 0 ||
        result.instances == 0 || result.instances > result.model_variables ||
        result.variables < result.model_variables ||
        result.variables - result.model_variables > bytes)
        refuse("trace-binding-or-shape");
    label(input, "INPUTS");
    const auto count = natural(input);
    if (count >= result.variables || count > bytes / 2)
        refuse("trace-input-shape");
    result.input_columns.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const auto column = natural(input);
        if (column == 0 || column >= result.variables ||
            (i && column <= result.input_columns.back()))
            refuse("trace-input-column");
        result.input_columns.push_back(column);
    }
    label(input, "OPS"); result.operations = natural(input);
    if (result.operations > bytes)
        refuse("trace-operation-count");
    return result;
}

std::vector<TraceOwnerLayout> owner_layout(const TraceBinding& expected) {
    if (!std::is_sorted(expected.owner_roles.begin(), expected.owner_roles.end()) ||
        std::adjacent_find(expected.owner_roles.begin(), expected.owner_roles.end()) != expected.owner_roles.end() ||
        std::any_of(expected.owner_roles.begin(), expected.owner_roles.end(), [](int role) { return role < 0; }))
        refuse("trace-expected-owner-roles");
    const auto before = file_metadata(expected.layout_path);
    if (digest_file(expected.layout_path) != expected.layout_sha256)
        refuse("trace-layout-file-digest");
    std::ifstream input(expected.layout_path);
    if (!input)
        refuse("trace-layout-open");
    label(input, "KPB_TRACE_LAYOUT_V1");
    label(input, "MODEL_VARIABLES");
    if (natural(input) != expected.model_variables)
        refuse("trace-layout-model-variables");
    label(input, "INSTANCES");
    if (natural(input) != expected.instances)
        refuse("trace-layout-instances");
    label(input, "OWNERS");
    const auto count = natural(input);
    if (count != expected.owner_roles.size())
        refuse("trace-layout-owner-count");
    std::vector<unsigned char> used_columns(expected.model_variables, 0);
    std::vector<TraceOwnerLayout> result;
    for (size_t owner = 0; owner < count; ++owner) {
        label(input, "OWNER");
        // The public layout names ownerN; N is the exact authenticated DDNNT
        // role, not a separately remappable display label.
        const auto role = token(input);
        if (role != "owner" + std::to_string(expected.owner_roles[owner]))
            refuse("trace-layout-owner-role");
        const auto columns = natural(input);
        if (columns == 0 || columns > expected.model_variables ||
            columns > static_cast<size_t>(before.st_size) / 2)
            refuse("trace-layout-owner-input-count");
        TraceOwnerLayout selected{expected.owner_roles[owner], {}};
        selected.columns.reserve(columns);
        for (size_t i = 0; i < columns; ++i) {
            const auto column = natural(input);
            // Derived instance/digest slots and scratch can never be supplied
            // by an owner. Public constants are explicit LINEAR recipes.
            if (column < expected.instances || column >= expected.model_variables ||
                (i && column <= selected.columns.back()) || used_columns[column])
                refuse("trace-layout-owner-column");
            used_columns[column] = 1;
            selected.columns.push_back(column);
        }
        result.push_back(std::move(selected));
    }
    label(input, "END");
    std::string extra;
    if (input >> extra)
        refuse("trace-layout-trailing-data");
    if (!input.eof())
        refuse("trace-layout-read");
    if (!same_metadata(before, file_metadata(expected.layout_path)))
        refuse("trace-layout-file-changed");
    return result;
}

Linear linear(std::istream& input, size_t variables, size_t bytes) {
    const auto count = natural(input);
    if (count > variables || count > bytes / 4)
        refuse("trace-linear-arity");
    Linear result;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        auto coefficient = parse_fr(token(input));
        const auto column = natural(input);
        if (coefficient == Fr(0) || column >= variables ||
            (i && column <= result.back().column))
            refuse("trace-linear-canonicality");
        result.push_back({coefficient, column});
    }
    return result;
}

Operation operation(std::istream& input, size_t variables, size_t model_variables, size_t bytes) {
    Operation result;
    const auto name = token(input);
    if (name == "LINEAR" || name == "MULADD") {
        result.kind = name == "LINEAR" ? Operation::LinearOp : Operation::MulAdd;
        result.target = natural(input);
        if (result.target == 0 || result.target >= variables)
            refuse("trace-output-column");
        result.a = linear(input, variables, bytes);
        if (result.kind == Operation::MulAdd) {
            result.b = linear(input, variables, bytes);
            result.c = linear(input, variables, bytes);
        }
    } else if (name == "ADD_BITS") {
        result.kind = Operation::AddBits;
        result.width = natural(input);
        if (result.width == 0 || result.width > 256)
            refuse("trace-add-width");
        for (size_t i = 0; i < result.width; ++i) {
            const auto column = natural(input);
            if (column == 0 || column >= variables)
                refuse("trace-output-column");
            result.outputs.push_back(column);
        }
        result.words = natural(input);
        if (result.words == 0 ||
            result.words > std::numeric_limits<size_t>::max() / result.width ||
            result.words * result.width > bytes / 2)
            refuse("trace-add-arity");
        for (size_t i = 0; i < result.words * result.width; ++i)
            result.bits.push_back(linear(input, variables, bytes));
        // Inputs are BIT expressions, not packed secret field elements. Their
        // bitness is part of the SAME complete R1CS validity check. Public zero
        // padding yields a value-independent upper bound on the exact sum.
        bigint maximum(0);
        for (size_t word = 0; word < result.words; ++word)
            for (size_t bit = 0; bit < result.width; ++bit) {
                const auto& lc = result.bits[word * result.width + bit];
                if (lc.size() == 1 && lc[0].column == 0 && lc[0].coefficient != Fr(1))
                    refuse("trace-nonbit-constant");
                if (!lc.empty())
                    maximum += bigint(1) << bit;
            }
        if (maximum >= (bigint(1) << result.width))
            refuse("trace-add-overflow-shape");
    } else if (name == "ASSERT_ZERO") {
        result.kind = Operation::AssertZero;
        result.a = linear(input, variables, bytes);
    } else if (name == "RANDOM_BIT") {
        result.kind = Operation::RandomBit;
        result.target = natural(input);
        if (result.target < model_variables || result.target >= variables)
            refuse("trace-random-bit-not-scratch");
    } else {
        refuse("trace-unknown-operation");
    }
    return result;
}

void defined(const Linear& lc, const std::vector<unsigned char>& assigned) {
    for (const auto& term : lc)
        if (!assigned[term.column])
            refuse("trace-undefined-reference");
}

void new_output(size_t target, std::vector<unsigned char>& assigned) {
    if (assigned[target])
        refuse("trace-duplicate-assignment");
    assigned[target] = 1;
}

void inspect_operation(const Operation& op, std::vector<unsigned char>& assigned) {
    defined(op.a, assigned); defined(op.b, assigned); defined(op.c, assigned);
    for (const auto& bits : op.bits)
        defined(bits, assigned);
    if (op.kind == Operation::LinearOp || op.kind == Operation::MulAdd || op.kind == Operation::RandomBit)
        new_output(op.target, assigned);
    else if (op.kind == Operation::AddBits)
        for (const auto column : op.outputs)
            new_output(column, assigned);
}

template<class Function>
void references(const Operation& op, Function visit) {
    for (const auto* lc : {&op.a, &op.b, &op.c})
        for (const auto& term : *lc)
            visit(term.column);
    for (const auto& lc : op.bits)
        for (const auto& term : lc)
            visit(term.column);
}

template<class Function>
void destinations(const Operation& op, Function visit) {
    if (op.kind == Operation::LinearOp || op.kind == Operation::MulAdd || op.kind == Operation::RandomBit)
        visit(op.target);
    else if (op.kind == Operation::AddBits)
        for (auto column : op.outputs)
            visit(column);
}

void end(std::istream& input) {
    label(input, "END");
    std::string extra;
    if (input >> extra)
        refuse("trace-trailing-data");
    if (!input.eof())
        refuse("trace-public-file-read");
}

void require_same_header(const TraceHeader& first, const TraceHeader& second) {
    if (first.source_sha256 != second.source_sha256 ||
        first.model_sha256 != second.model_sha256 ||
        first.layout_sha256 != second.layout_sha256 ||
        first.model_variables != second.model_variables ||
        first.variables != second.variables || first.instances != second.instances ||
        first.input_columns != second.input_columns || first.operations != second.operations)
        refuse("trace-header-changed");
}

struct AuthenticatedTraceContext {
    MascotContext& context;
    AuthScalar public_constant(const Fr& value) { return context.public_constant(value); }
    std::vector<AuthScalar> multiply_batch(std::span<const AuthScalar> left,
                                           std::span<const AuthScalar> right) {
        return context.multiply_batch(left, right);
    }
    AuthScalar random_bit() { return context.protocols().preprocessing.get_bit(); }
    void check_field_pending() { context.check_field_pending(); }
};

template<class Scalar>
struct ScheduledResult {
    size_t model_variables;
    std::vector<Scalar> wires;
    std::vector<Scalar> private_checks;
};

template<class Context, class Scalar>
class Executor {
    Context& context_;
    const TraceProgram& program_;
    size_t batch_;
    ScheduledResult<Scalar> result_;
    std::vector<unsigned char> assigned_;
    std::vector<Scalar> left_, right_, add_;
    std::vector<size_t> targets_;
    std::unordered_map<size_t, Scalar> scratch_;

    const Scalar& wire(size_t column) const {
        if (column < result_.model_variables)
            return result_.wires[column];
        const auto found = scratch_.find(column);
        if (found == scratch_.end())
            refuse("trace-scratch-storage");
        return found->second;
    }

    void write(size_t column, Scalar value) {
        if (column < result_.model_variables)
            result_.wires[column] = std::move(value);
        else if (!scratch_.emplace(column, std::move(value)).second)
            refuse("trace-scratch-overwrite");
    }

    void flush() {
        if (targets_.empty())
            return;
        const auto products = context_.multiply_batch(left_, right_);
        for (size_t i = 0; i < targets_.size(); ++i) {
            write(targets_[i], products[i] + add_[i]);
            assigned_[targets_[i]] = 1;
        }
        left_.clear(); right_.clear(); add_.clear(); targets_.clear();
    }

    Scalar evaluate(const Linear& lc) {
        for (const auto& term : lc)
            if (assigned_[term.column] == 2) {
                flush();
                break;
            }
        auto value = context_.public_constant(Fr(0));
        for (const auto& term : lc) {
            if (assigned_[term.column] != 1)
                refuse("trace-undefined-runtime-reference");
            value += wire(term.column) * term.coefficient;
        }
        return value;
    }

    void target(size_t column) {
        if (column == 0 || column >= assigned_.size() || assigned_[column])
            refuse("trace-runtime-duplicate-assignment");
    }

public:
    Executor(Context& context, const TraceProgram& program,
             const std::vector<TraceOwnerLayout>& layout,
             std::vector<std::pair<int, std::vector<Scalar>>> inputs, size_t batch)
        : context_(context), program_(program), batch_(batch),
          result_{program.header.model_variables, std::vector<Scalar>(program.header.model_variables), {}},
          assigned_(program.header.variables, 0) {
        if (inputs.size() != layout.size())
            refuse("trace-input-owner-count");
        result_.wires[0] = context_.public_constant(Fr(1));
        assigned_[0] = 1;
        for (size_t owner = 0; owner < inputs.size(); ++owner) {
            if (inputs[owner].first != layout[owner].owner_role ||
                inputs[owner].second.size() != layout[owner].columns.size())
                refuse("trace-input-owner-or-order");
            for (size_t i = 0; i < inputs[owner].second.size(); ++i) {
                const auto column = layout[owner].columns[i];
                result_.wires[column] = std::move(inputs[owner].second[i]);
                assigned_[column] = 1;
            }
            // Large received owner buffers can be released before joint work.
            std::vector<Scalar>().swap(inputs[owner].second);
        }
    }

    void apply(const Operation& op, size_t assertion_slot) {
        if (op.kind == Operation::AssertZero) {
            if (assertion_slot >= result_.private_checks.size())
                refuse("trace-assertion-slot");
            result_.private_checks[assertion_slot] = evaluate(op.a);
        } else if (op.kind == Operation::RandomBit) {
            flush();
            target(op.target);
            // Established actively authenticated MP-SPDZ preprocessing. This
            // is not local RNG, a clear dealer bit or a reduced field sample.
            write(op.target, context_.random_bit());
            assigned_[op.target] = 1;
        } else if (op.kind == Operation::LinearOp) {
            target(op.target);
            write(op.target, evaluate(op.a));
            assigned_[op.target] = 1;
        } else if (op.kind == Operation::MulAdd) {
            target(op.target);
            const auto a = evaluate(op.a), b = evaluate(op.b), c = evaluate(op.c);
            left_.push_back(a); right_.push_back(b); add_.push_back(c);
            targets_.push_back(op.target); assigned_[op.target] = 2;
            if (targets_.size() >= batch_)
                flush();
        } else {
            flush();
            for (auto column : op.outputs)
                target(column);
            std::vector<Scalar> total;
            for (size_t word = 0; word < op.words; ++word) {
                std::vector<Scalar> bits;
                for (size_t bit = 0; bit < op.width; ++bit)
                    bits.push_back(evaluate(op.bits[word * op.width + bit]));
                total = word == 0 ? std::move(bits) : trace_detail::add_words(context_, total, bits);
            }
            for (size_t i = 0; i < op.width; ++i) {
                write(op.outputs[i], total[i]);
                assigned_[op.outputs[i]] = 1;
            }
        }
    }

    bool ready(const Operation& op) const {
        bool result = true;
        references(op, [&](size_t column) { result = result && assigned_[column] == 1; });
        return result;
    }

    // Public dataflow, not secret values, determines this fixed lookahead
    // schedule. Interleaved per-bit SHA xor/select recipes can share one
    // multiplication layer without changing any Ark column or expression.
    void window(const std::vector<Operation>& ops, size_t final_ordinal) {
        std::vector<unsigned char> complete(ops.size(), 0);
        // Polynomial batching binds assertions in canonical recipe order,
        // independently of the public dependency scheduler's completion order.
        std::vector<size_t> assertion_slots(ops.size(), std::numeric_limits<size_t>::max());
        for (size_t i = 0; i < ops.size(); ++i)
            if (ops[i].kind == Operation::AssertZero) {
                assertion_slots[i] = result_.private_checks.size();
                result_.private_checks.emplace_back();
            }
        size_t remaining = ops.size();
        while (remaining) {
            size_t progress = 0;
            for (size_t i = 0; i < ops.size(); ++i) {
                if (complete[i] || ops[i].kind == Operation::AddBits || !ready(ops[i]))
                    continue;
                apply(ops[i], assertion_slots[i]);
                complete[i] = 1; --remaining; ++progress;
            }
            const bool had_products = !targets_.empty();
            flush();
            if (had_products)
                continue;
            bool added_bits = false;
            for (size_t i = 0; i < ops.size(); ++i)
                if (!complete[i] && ops[i].kind == Operation::AddBits && ready(ops[i])) {
                    apply(ops[i], assertion_slots[i]);
                    complete[i] = 1; --remaining; ++progress;
                    added_bits = true;
                    break;
                }
            if (!progress && !added_bits)
                refuse("trace-public-dataflow-stalled");
        }
        flush();
        std::vector<size_t> touched;
        for (const auto& op : ops) {
            const auto collect = [&](size_t column) {
                if (column >= result_.model_variables)
                    touched.push_back(column);
            };
            references(op, collect); destinations(op, collect);
        }
        std::sort(touched.begin(), touched.end());
        touched.erase(std::unique(touched.begin(), touched.end()), touched.end());
        for (auto column : touched) {
            const auto at = column - result_.model_variables;
            const auto last = program_.scratch_last_use32.empty()
                ? program_.scratch_last_use_wide.at(at)
                : static_cast<size_t>(program_.scratch_last_use32.at(at));
            if (last <= final_ordinal && assigned_[column] == 1) {
                if (scratch_.erase(column) != 1)
                    refuse("trace-scratch-retirement");
                assigned_[column] = 3;
            }
        }
    }

    ScheduledResult<Scalar> finish() {
        flush();
        for (size_t column = 0; column < assigned_.size(); ++column)
            if ((column < result_.model_variables && assigned_[column] != 1) ||
                (column >= result_.model_variables && assigned_[column] != 3))
                refuse("trace-incomplete-runtime-assignment");
        if (!scratch_.empty())
            refuse("trace-live-scratch-after-completion");
        context_.check_field_pending();
        return std::move(result_);
    }
};

}  // namespace

std::span<const AuthScalar> TraceExecution::model_assignment() const {
    if (model_variables > wires.size())
        refuse("trace-model-prefix");
    return {wires.data(), model_variables};
}

TraceProgram inspect_trace(const std::filesystem::path& path,
                           const TraceBinding& expected) {
    if (!hex_digest(expected.trace_sha256) || !hex_digest(expected.source_sha256) ||
        !hex_digest(expected.model_sha256) || !hex_digest(expected.layout_sha256))
        refuse("trace-expected-digest");
    if (expected.instances == 0 || expected.model_variables < expected.instances)
        refuse("trace-expected-model-shape");
    auto layout = owner_layout(expected);
    const auto before = file_metadata(path);
    if (digest_file(path) != expected.trace_sha256)
        refuse("trace-file-digest");
    std::ifstream input(path);
    if (!input)
        refuse("trace-public-file-open");
    auto h = header(input, before.st_size, expected);
    // Merge the few already-sorted owner lists without allocating another
    // multi-million-column copy or a per-column tree node.
    size_t expected_count = 0;
    for (const auto& owner : layout) {
        if (expected_count > std::numeric_limits<size_t>::max() - owner.columns.size())
            refuse("trace-layout-input-count-overflow");
        expected_count += owner.columns.size();
    }
    if (h.input_columns.size() != expected_count)
        refuse("trace-input-layout-union");
    std::vector<size_t> positions(layout.size(), 0);
    for (const auto input_column : h.input_columns) {
        size_t selected_owner = layout.size();
        size_t selected_column = std::numeric_limits<size_t>::max();
        for (size_t owner = 0; owner < layout.size(); ++owner)
            if (positions[owner] < layout[owner].columns.size() &&
                layout[owner].columns[positions[owner]] < selected_column) {
                selected_owner = owner;
                selected_column = layout[owner].columns[positions[owner]];
            }
        if (selected_owner == layout.size() || selected_column != input_column)
            refuse("trace-input-layout-union");
        ++positions[selected_owner];
    }
    std::vector<unsigned char> assigned(h.variables, 0);
    std::vector<uint32_t> last_use32;
    std::vector<size_t> last_use_wide;
    if (h.operations <= std::numeric_limits<uint32_t>::max())
        last_use32.resize(h.variables - h.model_variables, 0);
    else
        last_use_wide.resize(h.variables - h.model_variables, 0);
    assigned[0] = 1;
    for (auto column : h.input_columns)
        assigned[column] = 1;
    size_t assertion_count = 0;
    for (size_t i = 0; i < h.operations; ++i) {
        const auto op = operation(input, h.variables, h.model_variables, before.st_size);
        if (op.kind == Operation::AssertZero)
            ++assertion_count;
        inspect_operation(op, assigned);
        references(op, [&](size_t column) {
            if (column >= h.model_variables) {
                if (!last_use32.empty())
                    last_use32[column - h.model_variables] = static_cast<uint32_t>(i + 1);
                else
                    last_use_wide[column - h.model_variables] = i + 1;
            }
        });
    }
    end(input);
    if (std::any_of(assigned.begin(), assigned.end(), [](auto state) { return state != 1; }))
        refuse("trace-incomplete-assignment-shape");
    const auto after = file_metadata(path);
    if (!same_metadata(before, after))
        refuse("trace-file-changed");
    return {path, expected, std::move(h), std::move(layout), static_cast<size_t>(before.st_size),
            static_cast<uint64_t>(before.st_dev), static_cast<uint64_t>(before.st_ino),
            before.st_mtim.tv_sec, before.st_mtim.tv_nsec, assertion_count,
            std::move(last_use32), std::move(last_use_wide)};
}

void agree_trace(MascotContext& context, const TraceProgram& program,
                 size_t multiplication_batch) {
    if (multiplication_batch == 0)
        refuse("trace-zero-batch");
    auto binding = std::string("KPB_TRACE_V1\n") + program.binding.trace_sha256 + "\n" +
        program.binding.source_sha256 + "\n" + program.binding.model_sha256 + "\n" +
        program.binding.layout_sha256 + "\n" + std::to_string(program.header.model_variables) + "\n" +
        std::to_string(program.header.variables) + "\n" + std::to_string(program.header.instances) + "\n" +
        std::to_string(program.expected_private_checks) + "\n" +
        std::to_string(multiplication_batch) + "\n";
    for (const auto& owner : program.owner_layout) {
        binding += std::to_string(owner.owner_role) + ":";
        for (auto column : owner.columns)
            binding += std::to_string(column) + ",";
        binding += "\n";
    }
    context.agree_public_bytes("private-witness-trace", {
        reinterpret_cast<const unsigned char*>(binding.data()), binding.size()});
}

TraceExecution execute_trace(MascotContext& context, const TraceProgram& program,
                             std::vector<OwnerTraceInput> inputs,
                             size_t multiplication_batch) {
    const auto metadata = file_metadata(program.path);
    if (static_cast<uint64_t>(metadata.st_dev) != program.device ||
        static_cast<uint64_t>(metadata.st_ino) != program.inode ||
        static_cast<size_t>(metadata.st_size) != program.encoded_bytes ||
        metadata.st_mtim.tv_sec != program.mtime_seconds ||
        metadata.st_mtim.tv_nsec != program.mtime_nanoseconds)
        refuse("trace-selected-file-metadata");
    agree_trace(context, program, multiplication_batch);
    std::ifstream input(program.path);
    if (!input)
        refuse("trace-public-file-open");
    const auto h = header(input, program.encoded_bytes, program.binding);
    require_same_header(program.header, h);
    std::vector<std::pair<int, std::vector<AuthScalar>>> routed;
    for (auto& owner : inputs)
        routed.emplace_back(owner.owner_role, std::move(owner.values));
    AuthenticatedTraceContext arithmetic{context};
    Executor<AuthenticatedTraceContext, AuthScalar> executor(
        arithmetic, program, program.owner_layout, std::move(routed), multiplication_batch);
    for (size_t first = 0; first < h.operations;) {
        const auto count = std::min(multiplication_batch, h.operations - first);
        std::vector<Operation> window;
        window.reserve(count);
        for (size_t i = 0; i < count; ++i)
            window.push_back(operation(input, h.variables, h.model_variables, program.encoded_bytes));
        executor.window(window, first + count);
        first += count;
    }
    end(input);
    const auto after = file_metadata(program.path);
    if (!same_metadata(metadata, after))
        refuse("trace-file-changed-during-execution");
    auto result = executor.finish();
    if (result.private_checks.size() != program.expected_private_checks)
        refuse("trace-private-check-count");
    return {result.model_variables, std::move(result.wires), std::move(result.private_checks)};
}

AuthScalar trace_private_checks_hold(MascotContext& context,
                                     std::span<const AuthScalar> checks) {
    if (checks.empty())
        return context.public_constant(Fr(1));
    const bigint exponent(fr_modulus() - 1);
    std::vector<AuthScalar> powers(checks.begin(), checks.end());
    std::vector<AuthScalar> nonzero(checks.size(), context.public_constant(Fr(1)));
    const auto bits = mpz_sizeinbase(exponent.get_mpz_t(), 2);
    for (size_t bit = 0; bit < bits; ++bit) {
        if (mpz_tstbit(exponent.get_mpz_t(), bit))
            nonzero = context.multiply_batch(nonzero, powers);
        if (bit + 1 < bits)
            powers = context.multiply_batch(powers, powers);
    }
    for (auto& flag : nonzero)
        flag = context.public_constant(Fr(1)) - flag;
    while (nonzero.size() > 1) {
        std::vector<AuthScalar> left, right;
        for (size_t i = 0; i + 1 < nonzero.size(); i += 2) {
            left.push_back(nonzero[i]); right.push_back(nonzero[i + 1]);
        }
        auto next = context.multiply_batch(left, right);
        if (nonzero.size() % 2)
            next.push_back(nonzero.back());
        nonzero = std::move(next);
    }
    return nonzero[0];
}

#ifdef KPI_TRACE_PUBLIC_CONTROLS
PublicTraceReference evaluate_public_trace_for_controls(
    const TraceProgram& program,
    std::vector<std::pair<int, std::vector<Fr>>> inputs,
    size_t window_size) {
    struct PublicContext {
        Fr public_constant(const Fr& value) { return value; }
        std::vector<Fr> multiply_batch(std::span<const Fr> left, std::span<const Fr> right) {
            if (left.size() != right.size())
                refuse("public-trace-multiplication-arity");
            std::vector<Fr> result;
            for (size_t i = 0; i < left.size(); ++i)
                result.push_back(left[i] * right[i]);
            return result;
        }
        Fr random_bit() { refuse("public-reference-random-bit-forbidden"); }
        void check_field_pending() {}
    } arithmetic;
    if (!window_size)
        refuse("public-reference-zero-window");
    std::ifstream input(program.path);
    const auto h = header(input, program.encoded_bytes, program.binding);
    require_same_header(program.header, h);
    Executor<PublicContext, Fr> executor(arithmetic, program, program.owner_layout,
                                       std::move(inputs), window_size);
    for (size_t first = 0; first < h.operations;) {
        const auto count = std::min(window_size, h.operations - first);
        std::vector<Operation> window;
        for (size_t i = 0; i < count; ++i)
            window.push_back(operation(input, h.variables, h.model_variables, program.encoded_bytes));
        executor.window(window, first + count);
        first += count;
    }
    end(input);
    auto result = executor.finish();
    if (result.private_checks.size() != program.expected_private_checks)
        refuse("public-reference-private-check-count");
    return {std::move(result.wires), std::move(result.private_checks)};
}
#endif

}  // namespace kpi::mpc
