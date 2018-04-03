/**********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HNS_SECP256K1_ECMULT_GEN_IMPL_H
#define HNS_SECP256K1_ECMULT_GEN_IMPL_H

#include "scalar.h"
#include "group.h"
#include "ecmult_gen.h"
#include "hash_impl.h"
#ifdef USE_ECMULT_STATIC_PRECOMPUTATION
#include "ecmult_static_context.h"
#endif
static void hns_secp256k1_ecmult_gen_context_init(hns_secp256k1_ecmult_gen_context *ctx) {
    ctx->prec = NULL;
}

static void hns_secp256k1_ecmult_gen_context_build(hns_secp256k1_ecmult_gen_context *ctx, const hns_secp256k1_callback* cb) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    hns_secp256k1_ge prec[1024];
    hns_secp256k1_gej gj;
    hns_secp256k1_gej nums_gej;
    int i, j;
#endif

    if (ctx->prec != NULL) {
        return;
    }
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    ctx->prec = (hns_secp256k1_ge_storage (*)[64][16])checked_malloc(cb, sizeof(*ctx->prec));

    /* get the generator */
    hns_secp256k1_gej_set_ge(&gj, &hns_secp256k1_ge_const_g);

    /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
    {
        static const unsigned char nums_b32[33] = "The scalar for this x is unknown";
        hns_secp256k1_fe nums_x;
        hns_secp256k1_ge nums_ge;
        int r;
        r = hns_secp256k1_fe_set_b32(&nums_x, nums_b32);
        (void)r;
        VERIFY_CHECK(r);
        r = hns_secp256k1_ge_set_xo_var(&nums_ge, &nums_x, 0);
        (void)r;
        VERIFY_CHECK(r);
        hns_secp256k1_gej_set_ge(&nums_gej, &nums_ge);
        /* Add G to make the bits in x uniformly distributed. */
        hns_secp256k1_gej_add_ge_var(&nums_gej, &nums_gej, &hns_secp256k1_ge_const_g, NULL);
    }

    /* compute prec. */
    {
        hns_secp256k1_gej precj[1024]; /* Jacobian versions of prec. */
        hns_secp256k1_gej gbase;
        hns_secp256k1_gej numsbase;
        gbase = gj; /* 16^j * G */
        numsbase = nums_gej; /* 2^j * nums. */
        for (j = 0; j < 64; j++) {
            /* Set precj[j*16 .. j*16+15] to (numsbase, numsbase + gbase, ..., numsbase + 15*gbase). */
            precj[j*16] = numsbase;
            for (i = 1; i < 16; i++) {
                hns_secp256k1_gej_add_var(&precj[j*16 + i], &precj[j*16 + i - 1], &gbase, NULL);
            }
            /* Multiply gbase by 16. */
            for (i = 0; i < 4; i++) {
                hns_secp256k1_gej_double_var(&gbase, &gbase, NULL);
            }
            /* Multiply numbase by 2. */
            hns_secp256k1_gej_double_var(&numsbase, &numsbase, NULL);
            if (j == 62) {
                /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                hns_secp256k1_gej_neg(&numsbase, &numsbase);
                hns_secp256k1_gej_add_var(&numsbase, &numsbase, &nums_gej, NULL);
            }
        }
        hns_secp256k1_ge_set_all_gej_var(prec, precj, 1024, cb);
    }
    for (j = 0; j < 64; j++) {
        for (i = 0; i < 16; i++) {
            hns_secp256k1_ge_to_storage(&(*ctx->prec)[j][i], &prec[j*16 + i]);
        }
    }
#else
    (void)cb;
    ctx->prec = (hns_secp256k1_ge_storage (*)[64][16])hns_secp256k1_ecmult_static_context;
#endif
    hns_secp256k1_ecmult_gen_blind(ctx, NULL);
}

static int hns_secp256k1_ecmult_gen_context_is_built(const hns_secp256k1_ecmult_gen_context* ctx) {
    return ctx->prec != NULL;
}

static void hns_secp256k1_ecmult_gen_context_clone(hns_secp256k1_ecmult_gen_context *dst,
                                               const hns_secp256k1_ecmult_gen_context *src, const hns_secp256k1_callback* cb) {
    if (src->prec == NULL) {
        dst->prec = NULL;
    } else {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
        dst->prec = (hns_secp256k1_ge_storage (*)[64][16])checked_malloc(cb, sizeof(*dst->prec));
        memcpy(dst->prec, src->prec, sizeof(*dst->prec));
#else
        (void)cb;
        dst->prec = src->prec;
#endif
        dst->initial = src->initial;
        dst->blind = src->blind;
    }
}

static void hns_secp256k1_ecmult_gen_context_clear(hns_secp256k1_ecmult_gen_context *ctx) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    free(ctx->prec);
#endif
    hns_secp256k1_scalar_clear(&ctx->blind);
    hns_secp256k1_gej_clear(&ctx->initial);
    ctx->prec = NULL;
}

static void hns_secp256k1_ecmult_gen(const hns_secp256k1_ecmult_gen_context *ctx, hns_secp256k1_gej *r, const hns_secp256k1_scalar *gn) {
    hns_secp256k1_ge add;
    hns_secp256k1_ge_storage adds;
    hns_secp256k1_scalar gnb;
    int bits;
    int i, j;
    memset(&adds, 0, sizeof(adds));
    *r = ctx->initial;
    /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
    hns_secp256k1_scalar_add(&gnb, gn, &ctx->blind);
    add.infinity = 0;
    for (j = 0; j < 64; j++) {
        bits = hns_secp256k1_scalar_get_bits(&gnb, j * 4, 4);
        for (i = 0; i < 16; i++) {
            /** This uses a conditional move to avoid any secret data in array indexes.
             *   _Any_ use of secret indexes has been demonstrated to result in timing
             *   sidechannels, even when the cache-line access patterns are uniform.
             *  See also:
             *   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
             *    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
             *   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
             *    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
             *    (http://www.tau.ac.il/~tromer/papers/cache.pdf)
             */
            hns_secp256k1_ge_storage_cmov(&adds, &(*ctx->prec)[j][i], i == bits);
        }
        hns_secp256k1_ge_from_storage(&add, &adds);
        hns_secp256k1_gej_add_ge(r, r, &add);
    }
    bits = 0;
    hns_secp256k1_ge_clear(&add);
    hns_secp256k1_scalar_clear(&gnb);
}

/* Setup blinding values for hns_secp256k1_ecmult_gen. */
static void hns_secp256k1_ecmult_gen_blind(hns_secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32) {
    hns_secp256k1_scalar b;
    hns_secp256k1_gej gb;
    hns_secp256k1_fe s;
    unsigned char nonce32[32];
    hns_secp256k1_rfc6979_hmac_sha256 rng;
    int retry;
    unsigned char keydata[64] = {0};
    if (seed32 == NULL) {
        /* When seed is NULL, reset the initial point and blinding value. */
        hns_secp256k1_gej_set_ge(&ctx->initial, &hns_secp256k1_ge_const_g);
        hns_secp256k1_gej_neg(&ctx->initial, &ctx->initial);
        hns_secp256k1_scalar_set_int(&ctx->blind, 1);
    }
    /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
    hns_secp256k1_scalar_get_b32(nonce32, &ctx->blind);
    /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
     *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
     *   asking the caller for blinding values directly and expecting them to retry on failure.
     */
    memcpy(keydata, nonce32, 32);
    if (seed32 != NULL) {
        memcpy(keydata + 32, seed32, 32);
    }
    hns_secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, seed32 ? 64 : 32);
    memset(keydata, 0, sizeof(keydata));
    /* Retry for out of range results to achieve uniformity. */
    do {
        hns_secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        retry = !hns_secp256k1_fe_set_b32(&s, nonce32);
        retry |= hns_secp256k1_fe_is_zero(&s);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > Fp. */
    /* Randomize the projection to defend against multiplier sidechannels. */
    hns_secp256k1_gej_rescale(&ctx->initial, &s);
    hns_secp256k1_fe_clear(&s);
    do {
        hns_secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        hns_secp256k1_scalar_set_b32(&b, nonce32, &retry);
        /* A blinding value of 0 works, but would undermine the projection hardening. */
        retry |= hns_secp256k1_scalar_is_zero(&b);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > order. */
    hns_secp256k1_rfc6979_hmac_sha256_finalize(&rng);
    memset(nonce32, 0, 32);
    hns_secp256k1_ecmult_gen(ctx, &gb, &b);
    hns_secp256k1_scalar_negate(&b, &b);
    ctx->blind = b;
    ctx->initial = gb;
    hns_secp256k1_scalar_clear(&b);
    hns_secp256k1_gej_clear(&gb);
}

#endif /* HNS_SECP256K1_ECMULT_GEN_IMPL_H */
