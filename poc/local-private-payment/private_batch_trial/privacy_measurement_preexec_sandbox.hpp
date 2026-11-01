#pragma once

#include "privacy_measurement_runtime_types.hpp"

namespace kpb::measurement::runtime_bridge::detail {

// Installs the irreversible bootstrap filter immediately before the one
// sealed static worker exec.  The runtime descriptor must be close-on-exec;
// successful exec therefore removes the only execveat capability before any
// worker code runs.  The worker later stacks its role-specific sandbox.
bool install_measurement_preexec_sandbox(
    int exact_runtime_fd, const char* exact_empty_path,
    RuntimeChildRole role) noexcept;

} // namespace kpb::measurement::runtime_bridge::detail
