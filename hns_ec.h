#ifndef HEADER_HNS_EC_H
#define HEADER_HNS_EC_H

#include <stdlib.h>

#include "secp256k1.h"

typedef hns_secp256k1_context hns_ec_t;

hns_ec_t *
hns_ec_alloc(void);

hns_ec_t *
hns_ec_clone(hns_ec_t *ec);

void
hns_ec_free(hns_ec_t *ec);

int
hns_ec_randomize(hns_ec_t *ec, unsigned char *seed);

int
hns_ec_verify_pubkey(hns_ec_t *ec, unsigned char *key);

int
hns_ec_verify_msg(
  hns_ec_t *ec,
  unsigned char *pubkey,
  unsigned char *msg,
  unsigned char *sig
);
#endif
