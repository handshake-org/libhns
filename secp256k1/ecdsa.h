/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef ARES_SECP256K1_ECDSA_H
#define ARES_SECP256K1_ECDSA_H

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int ares_secp256k1_ecdsa_sig_parse(ares_secp256k1_scalar *r, ares_secp256k1_scalar *s, const unsigned char *sig, size_t size);
static int ares_secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const ares_secp256k1_scalar *r, const ares_secp256k1_scalar *s);
static int ares_secp256k1_ecdsa_sig_verify(const ares_secp256k1_ecmult_context *ctx, const ares_secp256k1_scalar* r, const ares_secp256k1_scalar* s, const ares_secp256k1_ge *pubkey, const ares_secp256k1_scalar *message);
static int ares_secp256k1_ecdsa_sig_sign(const ares_secp256k1_ecmult_gen_context *ctx, ares_secp256k1_scalar* r, ares_secp256k1_scalar* s, const ares_secp256k1_scalar *seckey, const ares_secp256k1_scalar *message, const ares_secp256k1_scalar *nonce, int *recid);

#endif /* ARES_SECP256K1_ECDSA_H */
