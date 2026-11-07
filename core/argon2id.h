#ifndef VAULT_ARGON2ID_H
#define VAULT_ARGON2ID_H

#include <stdint.h>

#if defined(_WIN32)
#define VAULT_API __declspec(dllexport)
#elif defined(__GNUC__)
#define VAULT_API __attribute__((visibility("default")))
#else
#define VAULT_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Argon2id v1.3. Returns 0 on success, 1 for invalid parameters, 2 on allocation failure.
 * Buffer sizes are in bytes; memory_kib is the TOTAL memory budget across all lanes.
 * A NULL input is permitted only with its length equal to zero. output must be writable
 * for output_len bytes. Caller owns all input/output buffers. No threads are created.
 * This minimal implementation does not promise constant time or secret-memory erasure.
 */
VAULT_API int vault_argon2id(
    const uint8_t *password, uint32_t password_len, const uint8_t *salt, uint32_t salt_len,
    uint32_t memory_kib, uint32_t iterations, uint32_t lanes, uint8_t *output, uint32_t output_len,
    const uint8_t *secret, uint32_t secret_len, const uint8_t *ad, uint32_t ad_len);

#ifdef __cplusplus
}
#endif

#endif
