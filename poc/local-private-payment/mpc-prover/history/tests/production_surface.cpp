#include "../epoch_journal.hpp"
using namespace kpi::mpc::history;
template<class T> concept HasSetup = requires {
    T::initialize_fresh_unfunded(std::filesystem::path{},std::filesystem::path{},EpochKey{},Digest{});
};
template<class T> concept HasBoolResolve = requires(T& value) { value.resolve(true); };
template<class T> concept HasTxidAccept = requires(T& value) { value.accept(std::string{}); };
template<class T> concept HasReset = requires(T& value) { value.reset(); };
static_assert(!HasSetup<EpochJournal> && !HasBoolResolve<EpochJournal>
    && !HasTxidAccept<EpochJournal> && !HasReset<EpochJournal>);
int main() {}
