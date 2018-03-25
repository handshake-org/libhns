/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef ARES_SECP256K1_ECKEY_H
#define ARES_SECP256K1_ECKEY_H

#include <stddef.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int ares_secp256k1_eckey_pubkey_parse(ares_secp256k1_ge *elem, const unsigned char *pub, size_t size);
static int ares_secp256k1_eckey_pubkey_serialize(ares_secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed);

static int ares_secp256k1_eckey_privkey_tweak_add(ares_secp256k1_scalar *key, const ares_secp256k1_scalar *tweak);
static int ares_secp256k1_eckey_pubkey_tweak_add(const ares_secp256k1_ecmult_context *ctx, ares_secp256k1_ge *key, const ares_secp256k1_scalar *tweak);
static int ares_secp256k1_eckey_privkey_tweak_mul(ares_secp256k1_scalar *key, const ares_secp256k1_scalar *tweak);
static int ares_secp256k1_eckey_pubkey_tweak_mul(const ares_secp256k1_ecmult_context *ctx, ares_secp256k1_ge *key, const ares_secp256k1_scalar *tweak);

#endif /* ARES_SECP256K1_ECKEY_H */
