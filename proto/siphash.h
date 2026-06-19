/* SipHash-2-4: fast short-input PRF.
 * Reference implementation by Jean-Philippe Aumasson and Daniel J. Bernstein.
 * Public domain. https://131002.net/siphash/
 */
#ifndef SIPHASH_H
#define SIPHASH_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define ROTL64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
#define SIP_ROUND(v0,v1,v2,v3) \
    v0 += v1; v1 = ROTL64(v1,13); v1 ^= v0; v0 = ROTL64(v0,32); \
    v2 += v3; v3 = ROTL64(v3,16); v3 ^= v2;                       \
    v0 += v3; v3 = ROTL64(v3,21); v3 ^= v0;                       \
    v2 += v1; v1 = ROTL64(v1,17); v1 ^= v2; v2 = ROTL64(v2,32)

static inline uint64_t siphash24(const uint8_t key[16], const void *in, size_t inlen)
{
    uint64_t k0, k1;
    memcpy(&k0, key,     8);
    memcpy(&k1, key + 8, 8);

    uint64_t v0 = k0 ^ UINT64_C(0x736f6d6570736575);
    uint64_t v1 = k1 ^ UINT64_C(0x646f72616e646f6d);
    uint64_t v2 = k0 ^ UINT64_C(0x6c7967656e657261);
    uint64_t v3 = k1 ^ UINT64_C(0x7465646279746573);

    const uint8_t *p = (const uint8_t *)in;
    const uint8_t *end = p + (inlen & ~(size_t)7);

    for (; p < end; p += 8) {
        uint64_t m; memcpy(&m, p, 8);
        v3 ^= m;
        SIP_ROUND(v0,v1,v2,v3); SIP_ROUND(v0,v1,v2,v3);
        v0 ^= m;
    }

    size_t left = inlen & 7;
    uint64_t b = (uint64_t)inlen << 56;
    switch (left) {
        case 7: b |= (uint64_t)p[6] << 48; /* fall through */
        case 6: b |= (uint64_t)p[5] << 40; /* fall through */
        case 5: b |= (uint64_t)p[4] << 32; /* fall through */
        case 4: b |= (uint64_t)p[3] << 24; /* fall through */
        case 3: b |= (uint64_t)p[2] << 16; /* fall through */
        case 2: b |= (uint64_t)p[1] <<  8; /* fall through */
        case 1: b |= (uint64_t)p[0];
    }
    v3 ^= b;
    SIP_ROUND(v0,v1,v2,v3); SIP_ROUND(v0,v1,v2,v3);
    v0 ^= b;
    v2 ^= 0xff;
    SIP_ROUND(v0,v1,v2,v3); SIP_ROUND(v0,v1,v2,v3);
    SIP_ROUND(v0,v1,v2,v3); SIP_ROUND(v0,v1,v2,v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

#undef ROTL64
#undef SIP_ROUND
#endif /* SIPHASH_H */
