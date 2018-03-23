#ifndef HEADER_CARES_SIG0_H
#define HEADER_CARES_SIG0_H

#include <stdlib.h>

#include "ares_ec.h"

#define ARES_SIG0_RR_SIZE 94
#define ARES_SIG0_RD_SIZE 83

#define ARES_SIG0_TYPE 24
#define ARES_SIG0_CLASS 255
#define ARES_SIG0_ZERO 0
#define ARES_SIG0_ALG 253

int
ares_sig0_has_sig(unsigned char *wire, size_t wire_len);

int
ares_sig0_get_sig(
  unsigned char *wire,
  size_t wire_len,
  unsigned char *sig,
  unsigned int *tag
);

int
ares_sig0_sighash(unsigned char *wire, size_t wire_len, unsigned char *hash);

int
ares_sig0_verify(
  ares_ec_t *ec,
  unsigned char *pubkey,
  unsigned char *wire,
  size_t wire_len
);
#endif
