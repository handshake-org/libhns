/**********************************************************************
 * Copyright (c) 2013, 2014, 2017 Pieter Wuille, Andrew Poelstra      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HNS_SECP256K1_ECMULT_H
#define HNS_SECP256K1_ECMULT_H

#include "num.h"
#include "group.h"
#include "scalar.h"
#include "scratch.h"

typedef struct {
    /* For accelerating the computation of a*P + b*G: */
    hns_secp256k1_ge_storage (*pre_g)[];    /* odd multiples of the generator */
#ifdef USE_ENDOMORPHISM
    hns_secp256k1_ge_storage (*pre_g_128)[]; /* odd multiples of 2^128*generator */
#endif
} hns_secp256k1_ecmult_context;

static void hns_secp256k1_ecmult_context_init(hns_secp256k1_ecmult_context *ctx);
static void hns_secp256k1_ecmult_context_build(hns_secp256k1_ecmult_context *ctx, const hns_secp256k1_callback *cb);
static void hns_secp256k1_ecmult_context_clone(hns_secp256k1_ecmult_context *dst,
                                           const hns_secp256k1_ecmult_context *src, const hns_secp256k1_callback *cb);
static void hns_secp256k1_ecmult_context_clear(hns_secp256k1_ecmult_context *ctx);
static int hns_secp256k1_ecmult_context_is_built(const hns_secp256k1_ecmult_context *ctx);

/** Double multiply: R = na*A + ng*G */
static void hns_secp256k1_ecmult(const hns_secp256k1_ecmult_context *ctx, hns_secp256k1_gej *r, const hns_secp256k1_gej *a, const hns_secp256k1_scalar *na, const hns_secp256k1_scalar *ng);

typedef int (hns_secp256k1_ecmult_multi_callback)(hns_secp256k1_scalar *sc, hns_secp256k1_ge *pt, size_t idx, void *data);

/**
 * Multi-multiply: R = inp_g_sc * G + sum_i ni * Ai.
 * Chooses the right algorithm for a given number of points and scratch space
 * size. Resets and overwrites the given scratch space. If the points do not
 * fit in the scratch space the algorithm is repeatedly run with batches of
 * points.
 * Returns: 1 on success (including when inp_g_sc is NULL and n is 0)
 *          0 if there is not enough scratch space for a single point or
 *          callback returns 0
 */
static int hns_secp256k1_ecmult_multi_var(const hns_secp256k1_ecmult_context *ctx, hns_secp256k1_scratch *scratch, hns_secp256k1_gej *r, const hns_secp256k1_scalar *inp_g_sc, hns_secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n);

#endif /* HNS_SECP256K1_ECMULT_H */
