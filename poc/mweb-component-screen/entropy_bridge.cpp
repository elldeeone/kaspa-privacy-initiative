// Local unfunded test entropy bridge; no protocol or validation modification.
#include <random.h>
#include <openssl/rand.h>
#include <cstdlib>
void GetStrongRandBytes(unsigned char* output, int count) noexcept {
    if (count < 0 || RAND_bytes(output, count) != 1) std::abort();
}
