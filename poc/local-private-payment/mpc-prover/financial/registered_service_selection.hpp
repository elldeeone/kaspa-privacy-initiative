#pragma once

// ROOT-owned build selection. This deliberately has no usable default. A
// deployment must replace this PUBLIC input as part of a reviewed immutable
// source/build selection, with the same registered roster and stores used by
// the authenticated transport and public continuation service. Runtime CLI,
// environment variables and imported receipts cannot configure this boundary.
#define KPI_REGISTERED_FINANCIAL_CONFIGURED 0
