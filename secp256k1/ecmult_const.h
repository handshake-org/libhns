/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HNS_SECP256K1_ECMULT_CONST_H
#define HNS_SECP256K1_ECMULT_CONST_H

#include "scalar.h"
#include "group.h"

static void hns_secp256k1_ecmult_const(hns_secp256k1_gej *r, const hns_secp256k1_ge *a, const hns_secp256k1_scalar *q);

#endif /* HNS_SECP256K1_ECMULT_CONST_H */
