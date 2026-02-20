/* cmk_compat_endian.h - substitute for endian.h on systems that lack it
 *
 * Provides (prefixed):
 *   cmk_htole32, cmk_htole64, cmk_le32toh, cmk_le64toh, cmk_htobe32, cmk_be32toh
 *
 * Also, if the *unprefixed* names are missing, defines them to the cmk_ versions:
 *   htole32, htole64, le32toh, le64toh, htobe32, be32toh
 *
 */

#ifndef CMK_COMPAT_ENDIAN_H
#define CMK_COMPAT_ENDIAN_H

#include <stdint.h>

/* ---- pure-C byteswap helpers (no intrinsics / builtins required) ---- */

static inline uint32_t cmk_bswap32_u(uint32_t x)
{
    return ((x & 0x000000FFu) << 24) |
           ((x & 0x0000FF00u) <<  8) |
           ((x & 0x00FF0000u) >>  8) |
           ((x & 0xFF000000u) >> 24);
}

static inline uint64_t cmk_bswap64_u(uint64_t x)
{
    return ((x & 0x00000000000000FFull) << 56) |
           ((x & 0x000000000000FF00ull) << 40) |
           ((x & 0x0000000000FF0000ull) << 24) |
           ((x & 0x00000000FF000000ull) <<  8) |
           ((x & 0x000000FF00000000ull) >>  8) |
           ((x & 0x0000FF0000000000ull) >> 24) |
           ((x & 0x00FF000000000000ull) >> 40) |
           ((x & 0xFF00000000000000ull) >> 56);
}

/* ---- endianness detection ----
 * Prefer compile-time macros when present; otherwise use a tiny runtime probe.
 */

#if defined(_WIN32) || defined(__i386__) || defined(__x86_64__) || defined(__LITTLE_ENDIAN__) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) || \
    (defined(BYTE_ORDER) && defined(LITTLE_ENDIAN) && (BYTE_ORDER == LITTLE_ENDIAN))
  #define CMK_LITTLE_ENDIAN 1
#elif defined(__BIG_ENDIAN__) || \
      (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)) || \
      (defined(BYTE_ORDER) && defined(BIG_ENDIAN) && (BYTE_ORDER == BIG_ENDIAN))
  #define CMK_BIG_ENDIAN 1
#endif

static inline int cmk_is_little_endian(void)
{
#if defined(CMK_LITTLE_ENDIAN)
    return 1;
#elif defined(CMK_BIG_ENDIAN)
    return 0;
#else
    const uint16_t one = 1;
    return *((const uint8_t *)&one) == 1;
#endif
}

/* ---- prefixed API (always provided) ---- */

static inline uint32_t cmk_htole32(uint32_t x)
{
#if defined(CMK_LITTLE_ENDIAN)
    return x;
#elif defined(CMK_BIG_ENDIAN)
    return cmk_bswap32_u(x);
#else
    return cmk_is_little_endian() ? x : cmk_bswap32_u(x);
#endif
}

static inline uint64_t cmk_htole64(uint64_t x)
{
#if defined(CMK_LITTLE_ENDIAN)
    return x;
#elif defined(CMK_BIG_ENDIAN)
    return cmk_bswap64_u(x);
#else
    return cmk_is_little_endian() ? x : cmk_bswap64_u(x);
#endif
}

static inline uint32_t cmk_le32toh(uint32_t x)
{
    return cmk_htole32(x);
}

static inline uint64_t cmk_le64toh(uint64_t x)
{
    return cmk_htole64(x);
}

static inline uint32_t cmk_htobe32(uint32_t x)
{
#if defined(CMK_BIG_ENDIAN)
    return x;
#elif defined(CMK_LITTLE_ENDIAN)
    return cmk_bswap32_u(x);
#else
    return cmk_is_little_endian() ? cmk_bswap32_u(x) : x;
#endif
}

static inline uint32_t cmk_be32toh(uint32_t x)
{
    return cmk_htobe32(x);
}

/* ---- optional unprefixed aliases (only if missing) ----
 * Many systems provide these as macros; #ifndef catches that too.
 */

#ifndef htole32
  #define htole32(x) cmk_htole32((uint32_t)(x))
#endif

#ifndef htole64
  #define htole64(x) cmk_htole64((uint64_t)(x))
#endif

#ifndef le32toh
  #define le32toh(x) cmk_le32toh((uint32_t)(x))
#endif

#ifndef le64toh
  #define le64toh(x) cmk_le64toh((uint64_t)(x))
#endif

#ifndef htobe32
  #define htobe32(x) cmk_htobe32((uint32_t)(x))
#endif

#ifndef be32toh
  #define be32toh(x) cmk_be32toh((uint32_t)(x))
#endif

#endif /* CMK_COMPAT_ENDIAN_H */
