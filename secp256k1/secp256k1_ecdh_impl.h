/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef ARES_SECP256K1_MODULE_ECDH_MAIN_H
#define ARES_SECP256K1_MODULE_ECDH_MAIN_H

#include "secp256k1_ecdh.h"
#include "ecmult_const_impl.h"

int ares_secp256k1_ecdh(const ares_secp256k1_context* ctx, unsigned char *result, const ares_secp256k1_pubkey *point, const unsigned char *scalar) {
    int ret = 0;
    int overflow = 0;
    ares_secp256k1_gej res;
    ares_secp256k1_ge pt;
    ares_secp256k1_scalar s;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(result != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);

    ares_secp256k1_pubkey_load(ctx, &pt, point);
    ares_secp256k1_scalar_set_b32(&s, scalar, &overflow);
    if (overflow || ares_secp256k1_scalar_is_zero(&s)) {
        ret = 0;
    } else {
        unsigned char x[32];
        unsigned char y[1];
        ares_secp256k1_sha256 sha;

        ares_secp256k1_ecmult_const(&res, &pt, &s);
        ares_secp256k1_ge_set_gej(&pt, &res);
        /* Compute a hash of the point in compressed form
         * Note we cannot use ares_secp256k1_eckey_pubkey_serialize here since it does not
         * expect its output to be secret and has a timing sidechannel. */
        ares_secp256k1_fe_normalize(&pt.x);
        ares_secp256k1_fe_normalize(&pt.y);
        ares_secp256k1_fe_get_b32(x, &pt.x);
        y[0] = 0x02 | ares_secp256k1_fe_is_odd(&pt.y);

        ares_secp256k1_sha256_initialize(&sha);
        ares_secp256k1_sha256_write(&sha, y, sizeof(y));
        ares_secp256k1_sha256_write(&sha, x, sizeof(x));
        ares_secp256k1_sha256_finalize(&sha, result);
        ret = 1;
    }

    ares_secp256k1_scalar_clear(&s);
    return ret;
}

#endif /* ARES_SECP256K1_MODULE_ECDH_MAIN_H */
