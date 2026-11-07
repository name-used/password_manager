/* Direct C translation of this project's native Python BLAKE2b / Argon2id.
 * RFC 7693 and RFC 9106 v1.3; no external cryptographic implementation.
 * Fixed-width unsigned arithmetic; explicit little-endian input/output.
 * Lanes execute sequentially in slice order. No CPU-specific instructions or threads.
 */
#include "argon2id.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t h[8], count;
    uint8_t buffer[128];
    size_t used;
    uint32_t length;
} blake_state;

typedef struct { uint64_t words[128]; } block;

static const uint64_t iv[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b), UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f), UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
};
static const uint8_t sigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
};

static uint64_t rotate(uint64_t value, unsigned count) {
    return (value >> count) | (value << (64 - count));
}

static uint64_t load64(const uint8_t *data) {
    uint64_t result = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) result |= (uint64_t)data[i] << (8 * i);
    return result;
}

static void store32(uint8_t *data, uint32_t value) {
    unsigned i;
    for (i = 0; i < 4; ++i) data[i] = (uint8_t)(value >> (8 * i));
}

static void store64(uint8_t *data, uint64_t value) {
    unsigned i;
    for (i = 0; i < 8; ++i) data[i] = (uint8_t)(value >> (8 * i));
}

static void blake_mix(uint64_t *v, unsigned a, unsigned b, unsigned c, unsigned d, uint64_t x, uint64_t y) {
    v[a] += v[b] + x; v[d] = rotate(v[d] ^ v[a], 32);
    v[c] += v[d]; v[b] = rotate(v[b] ^ v[c], 24);
    v[a] += v[b] + y; v[d] = rotate(v[d] ^ v[a], 16);
    v[c] += v[d]; v[b] = rotate(v[b] ^ v[c], 63);
}

static void blake_compress(blake_state *state, int last) {
    uint64_t v[16], message[16];
    unsigned i, round;
    for (i = 0; i < 8; ++i) { v[i] = state->h[i]; v[i + 8] = iv[i]; }
    for (i = 0; i < 16; ++i) message[i] = load64(state->buffer + 8 * i);
    /* This API's aggregate input length is below 2^35, so the high counter word is zero. */
    v[12] ^= state->count;
    if (last) v[14] = ~v[14];
    for (round = 0; round < 12; ++round) {
        const uint8_t *s = sigma[round % 10];
        blake_mix(v, 0, 4, 8, 12, message[s[0]], message[s[1]]);
        blake_mix(v, 1, 5, 9, 13, message[s[2]], message[s[3]]);
        blake_mix(v, 2, 6, 10, 14, message[s[4]], message[s[5]]);
        blake_mix(v, 3, 7, 11, 15, message[s[6]], message[s[7]]);
        blake_mix(v, 0, 5, 10, 15, message[s[8]], message[s[9]]);
        blake_mix(v, 1, 6, 11, 12, message[s[10]], message[s[11]]);
        blake_mix(v, 2, 7, 8, 13, message[s[12]], message[s[13]]);
        blake_mix(v, 3, 4, 9, 14, message[s[14]], message[s[15]]);
    }
    for (i = 0; i < 8; ++i) state->h[i] ^= v[i] ^ v[i + 8];
}

static void blake_init(blake_state *state, uint32_t length) {
    memcpy(state->h, iv, sizeof iv);
    state->h[0] ^= UINT64_C(0x01010000) ^ length;
    state->count = 0;
    state->used = 0;
    state->length = length;
}

static void blake_update(blake_state *state, const uint8_t *data, size_t length) {
    while (length) {
        size_t take;
        if (state->used == 128) {
            state->count += 128;
            blake_compress(state, 0);
            state->used = 0;
        }
        take = 128 - state->used;
        if (take > length) take = length;
        memcpy(state->buffer + state->used, data, take);
        state->used += take;
        data += take;
        length -= take;
    }
}

static void blake_final(blake_state *state, uint8_t *output) {
    uint8_t digest[64];
    unsigned i;
    state->count += state->used;
    memset(state->buffer + state->used, 0, 128 - state->used);
    blake_compress(state, 1);
    for (i = 0; i < 8; ++i) store64(digest + 8 * i, state->h[i]);
    memcpy(output, digest, state->length);
}

static void blake_hash(const uint8_t *data, size_t length, uint8_t *output, uint32_t output_len) {
    blake_state state;
    blake_init(&state, output_len);
    blake_update(&state, data, length);
    blake_final(&state, output);
}

static void hash_u32(blake_state *state, uint32_t value) {
    uint8_t data[4];
    store32(data, value);
    blake_update(state, data, sizeof data);
}

static void long_hash(const uint8_t *data, size_t length, uint8_t *output, uint32_t output_len) {
    blake_state state;
    uint8_t value[64];
    blake_init(&state, output_len <= 64 ? output_len : 64);
    hash_u32(&state, output_len);
    blake_update(&state, data, length);
    if (output_len <= 64) { blake_final(&state, output); return; }
    blake_final(&state, value);
    while (output_len > 64) {
        memcpy(output, value, 32);
        output += 32;
        output_len -= 32;
        if (output_len > 64) blake_hash(value, 64, value, 64);
    }
    blake_hash(value, 64, output, output_len);
}

static uint64_t blamka(uint64_t x, uint64_t y) {
    return x + y + UINT64_C(2) * (uint32_t)x * (uint32_t)y;
}

static void argon_mix(uint64_t *v, unsigned a, unsigned b, unsigned c, unsigned d) {
    v[a] = blamka(v[a], v[b]); v[d] = rotate(v[d] ^ v[a], 32);
    v[c] = blamka(v[c], v[d]); v[b] = rotate(v[b] ^ v[c], 24);
    v[a] = blamka(v[a], v[b]); v[d] = rotate(v[d] ^ v[a], 16);
    v[c] = blamka(v[c], v[d]); v[b] = rotate(v[b] ^ v[c], 63);
}

static void argon_permute(uint64_t *v) {
    argon_mix(v, 0, 4, 8, 12); argon_mix(v, 1, 5, 9, 13);
    argon_mix(v, 2, 6, 10, 14); argon_mix(v, 3, 7, 11, 15);
    argon_mix(v, 0, 5, 10, 15); argon_mix(v, 1, 6, 11, 12);
    argon_mix(v, 2, 7, 8, 13); argon_mix(v, 3, 4, 9, 14);
}

static void argon_compress(const uint64_t *previous, const uint64_t *reference, uint64_t *output, int xor_old) {
    uint64_t combined[128], work[128], column[16];
    unsigned i, j;
    for (i = 0; i < 128; ++i) combined[i] = work[i] = previous[i] ^ reference[i];
    for (i = 0; i < 8; ++i) argon_permute(work + 16 * i);
    for (i = 0; i < 8; ++i) {
        for (j = 0; j < 8; ++j) { column[2 * j] = work[16 * j + 2 * i]; column[2 * j + 1] = work[16 * j + 2 * i + 1]; }
        argon_permute(column);
        for (j = 0; j < 8; ++j) { work[16 * j + 2 * i] = column[2 * j]; work[16 * j + 2 * i + 1] = column[2 * j + 1]; }
    }
    for (i = 0; i < 128; ++i) output[i] = combined[i] ^ work[i] ^ (xor_old ? output[i] : 0);
}

VAULT_API int vault_argon2id(
    const uint8_t *password, uint32_t password_len, const uint8_t *salt, uint32_t salt_len,
    uint32_t memory_kib, uint32_t iterations, uint32_t lanes, uint8_t *output, uint32_t output_len,
    const uint8_t *secret, uint32_t secret_len, const uint8_t *ad, uint32_t ad_len) {
    blake_state hash;
    uint8_t seed[72], encoded[1024];
    uint64_t zero[128] = {0}, address_input[128], addresses[128], final[128] = {0};
    uint32_t block_count, lane_length, segment_length, lane, pass, slice, i, j;
    block *memory;

    if (!output || output_len < 4 || !lanes || lanes >= (UINT32_C(1) << 24) || !iterations || memory_kib < 8 * lanes) return 1;
    if ((!password && password_len) || (!salt && salt_len) || (!secret && secret_len) || (!ad && ad_len)) return 1;
    block_count = memory_kib / (4 * lanes) * (4 * lanes);
    if ((uint64_t)block_count * sizeof(block) > SIZE_MAX) return 1;
    lane_length = block_count / lanes;
    segment_length = lane_length / 4;
    memory = (block *)malloc((size_t)block_count * sizeof(block));
    if (!memory) return 2;

    /* H0 retains the requested memory size, even if the allocation is rounded down. */
    blake_init(&hash, 64);
    hash_u32(&hash, lanes); hash_u32(&hash, output_len); hash_u32(&hash, memory_kib);
    hash_u32(&hash, iterations); hash_u32(&hash, 0x13); hash_u32(&hash, 2);
    hash_u32(&hash, password_len); blake_update(&hash, password, password_len);
    hash_u32(&hash, salt_len); blake_update(&hash, salt, salt_len);
    hash_u32(&hash, secret_len); blake_update(&hash, secret, secret_len);
    hash_u32(&hash, ad_len); blake_update(&hash, ad, ad_len);
    blake_final(&hash, seed);
    for (lane = 0; lane < lanes; ++lane) {
        for (i = 0; i < 2; ++i) {
            uint64_t *words = memory[(size_t)lane * lane_length + i].words;
            store32(seed + 64, i); store32(seed + 68, lane);
            long_hash(seed, sizeof seed, encoded, sizeof encoded);
            for (j = 0; j < 128; ++j) words[j] = load64(encoded + 8 * j);
        }
    }

    for (pass = 0; pass < iterations; ++pass) {
        for (slice = 0; slice < 4; ++slice) {
            for (lane = 0; lane < lanes; ++lane) {
                int independent = pass == 0 && slice < 2;
                uint32_t first = pass == 0 && slice == 0 ? 2 : 0;
                size_t lane_start = (size_t)lane * lane_length;
                if (independent) {
                    memset(address_input, 0, sizeof address_input);
                    address_input[0] = pass; address_input[1] = lane; address_input[2] = slice;
                    address_input[3] = block_count; address_input[4] = iterations; address_input[5] = 2;
                    if (first) {
                        ++address_input[6];
                        argon_compress(zero, address_input, addresses, 0);
                        argon_compress(zero, addresses, addresses, 0);
                    }
                }
                for (i = first; i < segment_length; ++i) {
                    uint32_t column = slice * segment_length + i, reference_lane, area, start_column;
                    size_t previous = lane_start + (column ? column - 1 : lane_length - 1), reference;
                    uint64_t random, relative;
                    if (independent) {
                        if (i % 128 == 0) {
                            ++address_input[6];
                            argon_compress(zero, address_input, addresses, 0);
                            argon_compress(zero, addresses, addresses, 0);
                        }
                        random = addresses[i % 128];
                    } else random = memory[previous].words[0];
                    reference_lane = (uint32_t)(random >> 32) % lanes;
                    if (pass == 0 && slice == 0) reference_lane = lane;
                    area = pass == 0 ? slice * segment_length : lane_length - segment_length;
                    if (reference_lane == lane) area = area + i - 1;
                    else if (i == 0) --area;
                    relative = (uint64_t)(uint32_t)random * (uint32_t)random >> 32;
                    relative = area - 1 - ((uint64_t)area * relative >> 32);
                    start_column = pass == 0 || slice == 3 ? 0 : (slice + 1) * segment_length;
                    reference = (size_t)reference_lane * lane_length + (size_t)((start_column + relative) % lane_length);
                    argon_compress(memory[previous].words, memory[reference].words, memory[lane_start + column].words, pass != 0);
                }
            }
        }
    }
    for (lane = 0; lane < lanes; ++lane) {
        const uint64_t *words = memory[(size_t)(lane + 1) * lane_length - 1].words;
        for (i = 0; i < 128; ++i) final[i] ^= words[i];
    }
    for (i = 0; i < 128; ++i) store64(encoded + 8 * i, final[i]);
    long_hash(encoded, sizeof encoded, output, output_len);
    free(memory);
    return 0;
}
