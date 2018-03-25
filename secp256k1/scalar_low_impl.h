/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef ARES_SECP256K1_SCALAR_REPR_IMPL_H
#define ARES_SECP256K1_SCALAR_REPR_IMPL_H

#include "scalar.h"

#include <string.h>

ARES_SECP256K1_INLINE static int ares_secp256k1_scalar_is_even(const ares_secp256k1_scalar *a) {
    return !(*a & 1);
}

ARES_SECP256K1_INLINE static void ares_secp256k1_scalar_clear(ares_secp256k1_scalar *r) { *r = 0; }
ARES_SECP256K1_INLINE static void ares_secp256k1_scalar_set_int(ares_secp256k1_scalar *r, unsigned int v) { *r = v; }

ARES_SECP256K1_INLINE static unsigned int ares_secp256k1_scalar_get_bits(const ares_secp256k1_scalar *a, unsigned int offset, unsigned int count) {
    if (offset < 32)
        return ((*a >> offset) & ((((uint32_t)1) << count) - 1));
    else
        return 0;
}

ARES_SECP256K1_INLINE static unsigned int ares_secp256k1_scalar_get_bits_var(const ares_secp256k1_scalar *a, unsigned int offset, unsigned int count) {
    return ares_secp256k1_scalar_get_bits(a, offset, count);
}

ARES_SECP256K1_INLINE static int ares_secp256k1_scalar_check_overflow(const ares_secp256k1_scalar *a) { return *a >= EXHAUSTIVE_TEST_ORDER; }

static int ares_secp256k1_scalar_add(ares_secp256k1_scalar *r, const ares_secp256k1_scalar *a, const ares_secp256k1_scalar *b) {
    *r = (*a + *b) % EXHAUSTIVE_TEST_ORDER;
    return *r < *b;
}

static void ares_secp256k1_scalar_cadd_bit(ares_secp256k1_scalar *r, unsigned int bit, int flag) {
    if (flag && bit < 32)
        *r += (1 << bit);
#ifdef VERIFY
    VERIFY_CHECK(ares_secp256k1_scalar_check_overflow(r) == 0);
#endif
}

static void ares_secp256k1_scalar_set_b32(ares_secp256k1_scalar *r, const unsigned char *b32, int *overflow) {
    const int base = 0x100 % EXHAUSTIVE_TEST_ORDER;
    int i;
    *r = 0;
    for (i = 0; i < 32; i++) {
       *r = ((*r * base) + b32[i]) % EXHAUSTIVE_TEST_ORDER;
    }
    /* just deny overflow, it basically always happens */
    if (overflow) *overflow = 0;
}

static void ares_secp256k1_scalar_get_b32(unsigned char *bin, const ares_secp256k1_scalar* a) {
    memset(bin, 0, 32);
    bin[28] = *a >> 24; bin[29] = *a >> 16; bin[30] = *a >> 8; bin[31] = *a;
}

ARES_SECP256K1_INLINE static int ares_secp256k1_scalar_is_zero(const ares_secp256k1_scalar *a) {
    return *a == 0;
}

static void ares_secp256k1_scalar_negate(ares_secp256k1_scalar *r, const ares_secp256k1_scalar *a) {
    if (*a == 0) {
        *r = 0;
    } else {
        *r = EXHAUSTIVE_TEST_ORDER - *a;
    }
}

ARES_SECP256K1_INLINE static int ares_secp256k1_scalar_is_one(const ares_secp256k1_scalar *a) {
    return *a == 1;
}

static int ares_secp256k1_scalar_is_high(const ares_secp256k1_scalar *a) {
    return *a > EXHAUSTIVE_TEST_ORDER / 2;
}

static int ares_secp256k1_scalar_cond_negate(ares_secp256k1_scalar *r, int flag) {
    if (flag) ares_secp256k1_scalar_negate(r, r);
    return flag ? -1 : 1;
}

static void ares_secp256k1_scalar_mul(ares_secp256k1_scalar *r, const ares_secp256k1_scalar *a, const ares_secp256k1_scalar *b) {
    *r = (*a * *b) % EXHAUSTIVE_TEST_ORDER;
}

static int ares_secp256k1_scalar_shr_int(ares_secp256k1_scalar *r, int n) {
    int ret;
    VERIFY_CHECK(n > 0);
    VERIFY_CHECK(n < 16);
    ret = *r & ((1 << n) - 1);
    *r >>= n;
    return ret;
}

static void ares_secp256k1_scalar_sqr(ares_secp256k1_scalar *r, const ares_secp256k1_scalar *a) {
    *r = (*a * *a) % EXHAUSTIVE_TEST_ORDER;
}

static void ares_secp256k1_scalar_split_128(ares_secp256k1_scalar *r1, ares_secp256k1_scalar *r2, const ares_secp256k1_scalar *a) {
    *r1 = *a;
    *r2 = 0;
}

ARES_SECP256K1_INLINE static int ares_secp256k1_scalar_eq(const ares_secp256k1_scalar *a, const ares_secp256k1_scalar *b) {
    return *a == *b;
}

#endif /* ARES_SECP256K1_SCALAR_REPR_IMPL_H */
