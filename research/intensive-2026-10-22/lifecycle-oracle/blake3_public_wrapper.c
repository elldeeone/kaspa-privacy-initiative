#include "blake3.h"

/* Public byte hashing only; no transaction, wallet, proof or ledger API. */
void kpi_public_keyed_hash(const unsigned char key[32],
                          const unsigned char *input, size_t len,
                          unsigned char output[32]) {
  blake3_hasher hasher;
  blake3_hasher_init_keyed(&hasher, key);
  blake3_hasher_update(&hasher, input, len);
  blake3_hasher_finalize(&hasher, output, 32);
}
