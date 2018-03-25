/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef ARES_SECP256K1_ECMULT_CONST_H
#define ARES_SECP256K1_ECMULT_CONST_H

#include "scalar.h"
#include "group.h"

static void ares_secp256k1_ecmult_const(ares_secp256k1_gej *r, const ares_secp256k1_ge *a, const ares_secp256k1_scalar *q);

#endif /* ARES_SECP256K1_ECMULT_CONST_H */
