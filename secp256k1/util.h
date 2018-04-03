/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HNS_SECP256K1_UTIL_H
#define HNS_SECP256K1_UTIL_H

#if defined HAVE_CONFIG_H
#include "hns_config.h"
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
    void (*fn)(const char *text, void* data);
    const void* data;
} hns_secp256k1_callback;

static HNS_SECP256K1_INLINE void hns_secp256k1_callback_call(const hns_secp256k1_callback * const cb, const char * const text) {
    cb->fn(text, (void*)cb->data);
}

#ifdef DETERMINISTIC
#define TEST_FAILURE(msg) do { \
    fprintf(stderr, "%s\n", msg); \
    abort(); \
} while(0);
#else
#define TEST_FAILURE(msg) do { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, msg); \
    abort(); \
} while(0)
#endif

#ifdef HAVE_BUILTIN_EXPECT
#define EXPECT(x,c) __builtin_expect((x),(c))
#else
#define EXPECT(x,c) (x)
#endif

#ifdef DETERMINISTIC
#define CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        TEST_FAILURE("test condition failed"); \
    } \
} while(0)
#else
#define CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        TEST_FAILURE("test condition failed: " #cond); \
    } \
} while(0)
#endif

/* Like assert(), but when VERIFY is defined, and side-effect safe. */
#if defined(COVERAGE)
#define VERIFY_CHECK(check)
#define VERIFY_SETUP(stmt)
#elif defined(VERIFY)
#define VERIFY_CHECK CHECK
#define VERIFY_SETUP(stmt) do { stmt; } while(0)
#else
#define VERIFY_CHECK(cond) do { (void)(cond); } while(0)
#define VERIFY_SETUP(stmt)
#endif

static HNS_SECP256K1_INLINE void *checked_malloc(const hns_secp256k1_callback* cb, size_t size) {
    void *ret = malloc(size);
    if (ret == NULL) {
        hns_secp256k1_callback_call(cb, "Out of memory");
    }
    return ret;
}

static HNS_SECP256K1_INLINE void *checked_realloc(const hns_secp256k1_callback* cb, void *ptr, size_t size) {
    void *ret = realloc(ptr, size);
    if (ret == NULL) {
        hns_secp256k1_callback_call(cb, "Out of memory");
    }
    return ret;
}

/* Macro for restrict, when available and not in a VERIFY build. */
#if defined(HNS_BUILDING_LIBRARY) && defined(VERIFY)
# define HNS_SECP256K1_RESTRICT
#else
# if (!defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L) )
#  if HNS_SECP256K1_GNUC_PREREQ(3,0)
#   define HNS_SECP256K1_RESTRICT __restrict__
#  elif (defined(_MSC_VER) && _MSC_VER >= 1400)
#   define HNS_SECP256K1_RESTRICT __restrict
#  else
#   define HNS_SECP256K1_RESTRICT
#  endif
# else
#  define HNS_SECP256K1_RESTRICT restrict
# endif
#endif

#if defined(_WIN32)
# define I64FORMAT "I64d"
# define I64uFORMAT "I64u"
#else
# define I64FORMAT "lld"
# define I64uFORMAT "llu"
#endif

#if defined(HAVE___INT128)
# if defined(__GNUC__)
#  define HNS_SECP256K1_GNUC_EXT __extension__
# else
#  define HNS_SECP256K1_GNUC_EXT
# endif
HNS_SECP256K1_GNUC_EXT typedef unsigned __int128 uint128_t;
#endif

#endif /* HNS_SECP256K1_UTIL_H */
