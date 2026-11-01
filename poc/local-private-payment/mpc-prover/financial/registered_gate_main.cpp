// The canonical registered entry point is deliberately inert until one
// reviewed immutable service/driver selection is compiled in. In particular,
// this branch does not initialize fields/groups, parse argv, inspect the
// environment, open files, create sockets, acquire a head, start owner
// listeners, or construct an MPC context.
#include "registered_service_selection.hpp"

#if KPI_REGISTERED_FINANCIAL_CONFIGURED == 0

#include <unistd.h>

int main() {
    static constexpr char message[] =
        "KPI_REGISTERED_FINANCIAL_UNCONFIGURED_REFUSED\n";
    // STDERR_FILENO is inherited. This is the only application operation
    // before returning EX_CONFIG; no path or endpoint can influence it.
    if (::write(STDERR_FILENO, message, sizeof(message) - 1) < 0)
        return 78;
    return 78;
}

#elif KPI_REGISTERED_FINANCIAL_CONFIGURED == 1

// A configured build must replace the selection header with a reviewed,
// ROOT-owned selection that defines this header macro. The selected header
// owns the complete driver and exposes only this no-runtime-configuration
// entry point:
//
//   int kpi::mpc::financial::selected_registered_financial_main();
//
// argv and the environment are intentionally not forwarded across the trust
// boundary. Fresh attempt identifiers and role-local paths are derived by the
// selected driver below its immutable configuration.
#ifndef KPI_REGISTERED_FINANCIAL_DRIVER_HEADER
#error "Configured registered financial build requires a selected driver header"
#endif
#include KPI_REGISTERED_FINANCIAL_DRIVER_HEADER

int main() {
    return kpi::mpc::financial::selected_registered_financial_main();
}

#else
#error "KPI_REGISTERED_FINANCIAL_CONFIGURED must be exactly 0 or 1"
#endif
