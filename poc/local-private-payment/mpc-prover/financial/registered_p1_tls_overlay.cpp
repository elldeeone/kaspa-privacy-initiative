// The registered build materializes and authenticates this include tree before
// compilation. Compiling the patched TU into the executable interposes the
// pinned shared-library copy without mutating the admitted vendor directory.
#include "Networking/CryptoPlayer.cpp"

#ifndef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
#error "registered P1 TLS overlay is not selected"
#endif
