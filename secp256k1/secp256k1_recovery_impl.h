/**********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef ARES_SECP256K1_MODULE_RECOVERY_MAIN_H
#define ARES_SECP256K1_MODULE_RECOVERY_MAIN_H

#include "secp256k1_recovery.h"

static void ares_secp256k1_ecdsa_recoverable_signature_load(const ares_secp256k1_context* ctx, ares_secp256k1_scalar* r, ares_secp256k1_scalar* s, int* recid, const ares_secp256k1_ecdsa_recoverable_signature* sig) {
    (void)ctx;
    if (sizeof(ares_secp256k1_scalar) == 32) {
        /* When the ares_secp256k1_scalar type is exactly 32 byte, use its
         * representation inside ares_secp256k1_ecdsa_signature, as conversion is very fast.
         * Note that ares_secp256k1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        ares_secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
        ares_secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
    }
    *recid = sig->data[64];
}

static void ares_secp256k1_ecdsa_recoverable_signature_save(ares_secp256k1_ecdsa_recoverable_signature* sig, const ares_secp256k1_scalar* r, const ares_secp256k1_scalar* s, int recid) {
    if (sizeof(ares_secp256k1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        ares_secp256k1_scalar_get_b32(&sig->data[0], r);
        ares_secp256k1_scalar_get_b32(&sig->data[32], s);
    }
    sig->data[64] = recid;
}

int ares_secp256k1_ecdsa_recoverable_signature_parse_compact(const ares_secp256k1_context* ctx, ares_secp256k1_ecdsa_recoverable_signature* sig, const unsigned char *input64, int recid) {
    ares_secp256k1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    (void)ctx;
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);
    ARG_CHECK(recid >= 0 && recid <= 3);

    ares_secp256k1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    ares_secp256k1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        ares_secp256k1_ecdsa_recoverable_signature_save(sig, &r, &s, recid);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int ares_secp256k1_ecdsa_recoverable_signature_serialize_compact(const ares_secp256k1_context* ctx, unsigned char *output64, int *recid, const ares_secp256k1_ecdsa_recoverable_signature* sig) {
    ares_secp256k1_scalar r, s;

    (void)ctx;
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(recid != NULL);

    ares_secp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, recid, sig);
    ares_secp256k1_scalar_get_b32(&output64[0], &r);
    ares_secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

int ares_secp256k1_ecdsa_recoverable_signature_convert(const ares_secp256k1_context* ctx, ares_secp256k1_ecdsa_signature* sig, const ares_secp256k1_ecdsa_recoverable_signature* sigin) {
    ares_secp256k1_scalar r, s;
    int recid;

    (void)ctx;
    ARG_CHECK(sig != NULL);
    ARG_CHECK(sigin != NULL);

    ares_secp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, sigin);
    ares_secp256k1_ecdsa_signature_save(sig, &r, &s);
    return 1;
}

static int ares_secp256k1_ecdsa_sig_recover(const ares_secp256k1_ecmult_context *ctx, const ares_secp256k1_scalar *sigr, const ares_secp256k1_scalar* sigs, ares_secp256k1_ge *pubkey, const ares_secp256k1_scalar *message, int recid) {
    unsigned char brx[32];
    ares_secp256k1_fe fx;
    ares_secp256k1_ge x;
    ares_secp256k1_gej xj;
    ares_secp256k1_scalar rn, u1, u2;
    ares_secp256k1_gej qj;
    int r;

    if (ares_secp256k1_scalar_is_zero(sigr) || ares_secp256k1_scalar_is_zero(sigs)) {
        return 0;
    }

    ares_secp256k1_scalar_get_b32(brx, sigr);
    r = ares_secp256k1_fe_set_b32(&fx, brx);
    (void)r;
    VERIFY_CHECK(r); /* brx comes from a scalar, so is less than the order; certainly less than p */
    if (recid & 2) {
        if (ares_secp256k1_fe_cmp_var(&fx, &ares_secp256k1_ecdsa_const_p_minus_order) >= 0) {
            return 0;
        }
        ares_secp256k1_fe_add(&fx, &ares_secp256k1_ecdsa_const_order_as_fe);
    }
    if (!ares_secp256k1_ge_set_xo_var(&x, &fx, recid & 1)) {
        return 0;
    }
    ares_secp256k1_gej_set_ge(&xj, &x);
    ares_secp256k1_scalar_inverse_var(&rn, sigr);
    ares_secp256k1_scalar_mul(&u1, &rn, message);
    ares_secp256k1_scalar_negate(&u1, &u1);
    ares_secp256k1_scalar_mul(&u2, &rn, sigs);
    ares_secp256k1_ecmult(ctx, &qj, &xj, &u2, &u1);
    ares_secp256k1_ge_set_gej_var(pubkey, &qj);
    return !ares_secp256k1_gej_is_infinity(&qj);
}

int ares_secp256k1_ecdsa_sign_recoverable(const ares_secp256k1_context* ctx, ares_secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msg32, const unsigned char *seckey, ares_secp256k1_nonce_function noncefp, const void* noncedata) {
    ares_secp256k1_scalar r, s;
    ares_secp256k1_scalar sec, non, msg;
    int recid;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(ares_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);
    if (noncefp == NULL) {
        noncefp = ares_secp256k1_nonce_function_default;
    }

    ares_secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (!overflow && !ares_secp256k1_scalar_is_zero(&sec)) {
        unsigned char nonce32[32];
        unsigned int count = 0;
        ares_secp256k1_scalar_set_b32(&msg, msg32, NULL);
        while (1) {
            ret = noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
            if (!ret) {
                break;
            }
            ares_secp256k1_scalar_set_b32(&non, nonce32, &overflow);
            if (!ares_secp256k1_scalar_is_zero(&non) && !overflow) {
                if (ares_secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, &r, &s, &sec, &msg, &non, &recid)) {
                    break;
                }
            }
            count++;
        }
        memset(nonce32, 0, 32);
        ares_secp256k1_scalar_clear(&msg);
        ares_secp256k1_scalar_clear(&non);
        ares_secp256k1_scalar_clear(&sec);
    }
    if (ret) {
        ares_secp256k1_ecdsa_recoverable_signature_save(signature, &r, &s, recid);
    } else {
        memset(signature, 0, sizeof(*signature));
    }
    return ret;
}

int ares_secp256k1_ecdsa_recover(const ares_secp256k1_context* ctx, ares_secp256k1_pubkey *pubkey, const ares_secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msg32) {
    ares_secp256k1_ge q;
    ares_secp256k1_scalar r, s;
    ares_secp256k1_scalar m;
    int recid;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(ares_secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(pubkey != NULL);

    ares_secp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, signature);
    VERIFY_CHECK(recid >= 0 && recid < 4);  /* should have been caught in parse_compact */
    ares_secp256k1_scalar_set_b32(&m, msg32, NULL);
    if (ares_secp256k1_ecdsa_sig_recover(&ctx->ecmult_ctx, &r, &s, &q, &m, recid)) {
        ares_secp256k1_pubkey_save(pubkey, &q);
        return 1;
    } else {
        memset(pubkey, 0, sizeof(*pubkey));
        return 0;
    }
}

#endif /* ARES_SECP256K1_MODULE_RECOVERY_MAIN_H */
