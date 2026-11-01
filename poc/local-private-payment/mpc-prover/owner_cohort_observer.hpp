#pragma once

#include <cstddef>

namespace kpi::mpc {

// Owner labels are visible only to this role-private observer. Implementations
// must not route them into public phases, filenames, output slots, or release
// paths. Exceptions are fatal to the enclosing registered attempt.
class PrivateOwnerCohortObserver {
public:
    virtual ~PrivateOwnerCohortObserver() = default;
    virtual void owner_authenticated(unsigned owner) = 0;
    // Physical fixed-size masked frame arrived. This is not an admission or
    // success signal; later agreement/unpack can still poison the attempt.
    virtual void owner_upload_complete(unsigned owner,
                                       std::size_t fixed_frame_bytes) = 0;
};

} // namespace kpi::mpc
