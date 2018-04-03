/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HNS_SECP256K1_ECKEY_H
#define HNS_SECP256K1_ECKEY_H

#include <stddef.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int hns_secp256k1_eckey_pubkey_parse(hns_secp256k1_ge *elem, const unsigned char *pub, size_t size);
static int hns_secp256k1_eckey_pubkey_serialize(hns_secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed);

static int hns_secp256k1_eckey_privkey_tweak_add(hns_secp256k1_scalar *key, const hns_secp256k1_scalar *tweak);
static int hns_secp256k1_eckey_pubkey_tweak_add(const hns_secp256k1_ecmult_context *ctx, hns_secp256k1_ge *key, const hns_secp256k1_scalar *tweak);
static int hns_secp256k1_eckey_privkey_tweak_mul(hns_secp256k1_scalar *key, const hns_secp256k1_scalar *tweak);
static int hns_secp256k1_eckey_pubkey_tweak_mul(const hns_secp256k1_ecmult_context *ctx, hns_secp256k1_ge *key, const hns_secp256k1_scalar *tweak);

#endif /* HNS_SECP256K1_ECKEY_H */
