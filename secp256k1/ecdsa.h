/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HNS_SECP256K1_ECDSA_H
#define HNS_SECP256K1_ECDSA_H

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int hns_secp256k1_ecdsa_sig_parse(hns_secp256k1_scalar *r, hns_secp256k1_scalar *s, const unsigned char *sig, size_t size);
static int hns_secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const hns_secp256k1_scalar *r, const hns_secp256k1_scalar *s);
static int hns_secp256k1_ecdsa_sig_verify(const hns_secp256k1_ecmult_context *ctx, const hns_secp256k1_scalar* r, const hns_secp256k1_scalar* s, const hns_secp256k1_ge *pubkey, const hns_secp256k1_scalar *message);
static int hns_secp256k1_ecdsa_sig_sign(const hns_secp256k1_ecmult_gen_context *ctx, hns_secp256k1_scalar* r, hns_secp256k1_scalar* s, const hns_secp256k1_scalar *seckey, const hns_secp256k1_scalar *message, const hns_secp256k1_scalar *nonce, int *recid);

#endif /* HNS_SECP256K1_ECDSA_H */
