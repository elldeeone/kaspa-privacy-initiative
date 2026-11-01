#include "Protocols/MAC_Check.hpp"
#include "Math/gfp.h"

// Compile the exact patched upstream template for the selected prime-field
// MAC-check shape. This deliberately performs no networking or protocol run.
template void MAC_Check_<Share<gfp>>::Check(const Player&);

int main() {
    return 0;
}
