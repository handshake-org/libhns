#ifndef HEADER_CARES_EC_H
#define HEADER_CARES_EC_H

#include <stdlib.h>

#include "secp256k1/include/secp256k1.h"

typedef secp256k1_context ares_ec_t;

ares_ec_t *
ares_ec_alloc(void);

ares_ec_t *
ares_ec_clone(ares_ec_t *ec);

void
ares_ec_free(ares_ec_t *ec);

int
ares_ec_randomize(ares_ec_t *ec, unsigned char *seed);

int
ares_ec_verify_privkey(ares_ec_t *ec, unsigned char *key);

int
ares_ec_verify_pubkey(ares_ec_t *ec, unsigned char *key);

int
ares_ec_create_pubkey(ares_ec_t *ec, unsigned char *key, unsigned char *pubkey);

int
ares_ec_sign_msg(
  ares_ec_t *ec,
  unsigned char *key,
  unsigned char *msg,
  unsigned char *sig,
  int *rec
);

int
ares_ec_verify_msg(
  ares_ec_t *ec,
  unsigned char *pubkey,
  unsigned char *msg,
  unsigned char *sig
);

int
ares_ec_recover(
  ares_ec_t *ec,
  unsigned char *msg,
  unsigned char *sig,
  int rec,
  unsigned char *pubkey
);
#endif
