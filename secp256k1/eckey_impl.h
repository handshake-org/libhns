/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HNS_SECP256K1_ECKEY_IMPL_H
#define HNS_SECP256K1_ECKEY_IMPL_H

#include "eckey.h"

#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult_gen.h"

static int hns_secp256k1_eckey_pubkey_parse(hns_secp256k1_ge *elem, const unsigned char *pub, size_t size) {
    if (size == 33 && (pub[0] == HNS_SECP256K1_TAG_PUBKEY_EVEN || pub[0] == HNS_SECP256K1_TAG_PUBKEY_ODD)) {
        hns_secp256k1_fe x;
        return hns_secp256k1_fe_set_b32(&x, pub+1) && hns_secp256k1_ge_set_xo_var(elem, &x, pub[0] == HNS_SECP256K1_TAG_PUBKEY_ODD);
    } else if (size == 65 && (pub[0] == 0x04 || pub[0] == 0x06 || pub[0] == 0x07)) {
        hns_secp256k1_fe x, y;
        if (!hns_secp256k1_fe_set_b32(&x, pub+1) || !hns_secp256k1_fe_set_b32(&y, pub+33)) {
            return 0;
        }
        hns_secp256k1_ge_set_xy(elem, &x, &y);
        if ((pub[0] == HNS_SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == HNS_SECP256K1_TAG_PUBKEY_HYBRID_ODD) &&
            hns_secp256k1_fe_is_odd(&y) != (pub[0] == HNS_SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
            return 0;
        }
        return hns_secp256k1_ge_is_valid_var(elem);
    } else {
        return 0;
    }
}

static int hns_secp256k1_eckey_pubkey_serialize(hns_secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed) {
    if (hns_secp256k1_ge_is_infinity(elem)) {
        return 0;
    }
    hns_secp256k1_fe_normalize_var(&elem->x);
    hns_secp256k1_fe_normalize_var(&elem->y);
    hns_secp256k1_fe_get_b32(&pub[1], &elem->x);
    if (compressed) {
        *size = 33;
        pub[0] = hns_secp256k1_fe_is_odd(&elem->y) ? HNS_SECP256K1_TAG_PUBKEY_ODD : HNS_SECP256K1_TAG_PUBKEY_EVEN;
    } else {
        *size = 65;
        pub[0] = HNS_SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
        hns_secp256k1_fe_get_b32(&pub[33], &elem->y);
    }
    return 1;
}

static int hns_secp256k1_eckey_privkey_tweak_add(hns_secp256k1_scalar *key, const hns_secp256k1_scalar *tweak) {
    hns_secp256k1_scalar_add(key, key, tweak);
    if (hns_secp256k1_scalar_is_zero(key)) {
        return 0;
    }
    return 1;
}

static int hns_secp256k1_eckey_pubkey_tweak_add(const hns_secp256k1_ecmult_context *ctx, hns_secp256k1_ge *key, const hns_secp256k1_scalar *tweak) {
    hns_secp256k1_gej pt;
    hns_secp256k1_scalar one;
    hns_secp256k1_gej_set_ge(&pt, key);
    hns_secp256k1_scalar_set_int(&one, 1);
    hns_secp256k1_ecmult(ctx, &pt, &pt, &one, tweak);

    if (hns_secp256k1_gej_is_infinity(&pt)) {
        return 0;
    }
    hns_secp256k1_ge_set_gej(key, &pt);
    return 1;
}

static int hns_secp256k1_eckey_privkey_tweak_mul(hns_secp256k1_scalar *key, const hns_secp256k1_scalar *tweak) {
    if (hns_secp256k1_scalar_is_zero(tweak)) {
        return 0;
    }

    hns_secp256k1_scalar_mul(key, key, tweak);
    return 1;
}

static int hns_secp256k1_eckey_pubkey_tweak_mul(const hns_secp256k1_ecmult_context *ctx, hns_secp256k1_ge *key, const hns_secp256k1_scalar *tweak) {
    hns_secp256k1_scalar zero;
    hns_secp256k1_gej pt;
    if (hns_secp256k1_scalar_is_zero(tweak)) {
        return 0;
    }

    hns_secp256k1_scalar_set_int(&zero, 0);
    hns_secp256k1_gej_set_ge(&pt, key);
    hns_secp256k1_ecmult(ctx, &pt, &pt, tweak, &zero);
    hns_secp256k1_ge_set_gej(key, &pt);
    return 1;
}

#endif /* HNS_SECP256K1_ECKEY_IMPL_H */
