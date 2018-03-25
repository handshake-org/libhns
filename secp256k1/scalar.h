/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef ARES_SECP256K1_SCALAR_H
#define ARES_SECP256K1_SCALAR_H

#include "num.h"

#if defined HAVE_CONFIG_H
#include "ares_config.h"
#endif

#if defined(EXHAUSTIVE_TEST_ORDER)
#include "scalar_low.h"
#elif defined(USE_SCALAR_4X64)
#include "scalar_4x64.h"
#elif defined(USE_SCALAR_8X32)
#include "scalar_8x32.h"
#else
#error "Please select scalar implementation"
#endif

/** Clear a scalar to prevent the leak of sensitive data. */
static void ares_secp256k1_scalar_clear(ares_secp256k1_scalar *r);

/** Access bits from a scalar. All requested bits must belong to the same 32-bit limb. */
static unsigned int ares_secp256k1_scalar_get_bits(const ares_secp256k1_scalar *a, unsigned int offset, unsigned int count);

/** Access bits from a scalar. Not constant time. */
static unsigned int ares_secp256k1_scalar_get_bits_var(const ares_secp256k1_scalar *a, unsigned int offset, unsigned int count);

/** Set a scalar from a big endian byte array. */
static void ares_secp256k1_scalar_set_b32(ares_secp256k1_scalar *r, const unsigned char *bin, int *overflow);

/** Set a scalar to an unsigned integer. */
static void ares_secp256k1_scalar_set_int(ares_secp256k1_scalar *r, unsigned int v);

/** Convert a scalar to a byte array. */
static void ares_secp256k1_scalar_get_b32(unsigned char *bin, const ares_secp256k1_scalar* a);

/** Add two scalars together (modulo the group order). Returns whether it overflowed. */
static int ares_secp256k1_scalar_add(ares_secp256k1_scalar *r, const ares_secp256k1_scalar *a, const ares_secp256k1_scalar *b);

/** Conditionally add a power of two to a scalar. The result is not allowed to overflow. */
static void ares_secp256k1_scalar_cadd_bit(ares_secp256k1_scalar *r, unsigned int bit, int flag);

/** Multiply two scalars (modulo the group order). */
static void ares_secp256k1_scalar_mul(ares_secp256k1_scalar *r, const ares_secp256k1_scalar *a, const ares_secp256k1_scalar *b);

/** Shift a scalar right by some amount strictly between 0 and 16, returning
 *  the low bits that were shifted off */
static int ares_secp256k1_scalar_shr_int(ares_secp256k1_scalar *r, int n);

/** Compute the square of a scalar (modulo the group order). */
static void ares_secp256k1_scalar_sqr(ares_secp256k1_scalar *r, const ares_secp256k1_scalar *a);

/** Compute the inverse of a scalar (modulo the group order). */
static void ares_secp256k1_scalar_inverse(ares_secp256k1_scalar *r, const ares_secp256k1_scalar *a);

/** Compute the inverse of a scalar (modulo the group order), without constant-time guarantee. */
static void ares_secp256k1_scalar_inverse_var(ares_secp256k1_scalar *r, const ares_secp256k1_scalar *a);

/** Compute the complement of a scalar (modulo the group order). */
static void ares_secp256k1_scalar_negate(ares_secp256k1_scalar *r, const ares_secp256k1_scalar *a);

/** Check whether a scalar equals zero. */
static int ares_secp256k1_scalar_is_zero(const ares_secp256k1_scalar *a);

/** Check whether a scalar equals one. */
static int ares_secp256k1_scalar_is_one(const ares_secp256k1_scalar *a);

/** Check whether a scalar, considered as an nonnegative integer, is even. */
static int ares_secp256k1_scalar_is_even(const ares_secp256k1_scalar *a);

/** Check whether a scalar is higher than the group order divided by 2. */
static int ares_secp256k1_scalar_is_high(const ares_secp256k1_scalar *a);

/** Conditionally negate a number, in constant time.
 * Returns -1 if the number was negated, 1 otherwise */
static int ares_secp256k1_scalar_cond_negate(ares_secp256k1_scalar *a, int flag);

/** Compare two scalars. */
static int ares_secp256k1_scalar_eq(const ares_secp256k1_scalar *a, const ares_secp256k1_scalar *b);

#ifdef USE_ENDOMORPHISM
/** Find r1 and r2 such that r1+r2*2^128 = a. */
static void ares_secp256k1_scalar_split_128(ares_secp256k1_scalar *r1, ares_secp256k1_scalar *r2, const ares_secp256k1_scalar *a);
/** Find r1 and r2 such that r1+r2*lambda = a, and r1 and r2 are maximum 128 bits long (see ares_secp256k1_gej_mul_lambda). */
static void ares_secp256k1_scalar_split_lambda(ares_secp256k1_scalar *r1, ares_secp256k1_scalar *r2, const ares_secp256k1_scalar *a);
#endif

/** Multiply a and b (without taking the modulus!), divide by 2**shift, and round to the nearest integer. Shift must be at least 256. */
static void ares_secp256k1_scalar_mul_shift_var(ares_secp256k1_scalar *r, const ares_secp256k1_scalar *a, const ares_secp256k1_scalar *b, unsigned int shift);

#endif /* ARES_SECP256K1_SCALAR_H */
