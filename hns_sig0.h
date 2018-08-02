#ifndef HEADER_HNS_SIG0_H
#define HEADER_HNS_SIG0_H

#include <stdlib.h>

#include "hns_ec.h"

#define HNS_SIG0_RR_SIZE 94
#define HNS_SIG0_RD_SIZE 83

#define HNS_SIG0_TYPE 24
#define HNS_SIG0_CLASS 255
#define HNS_SIG0_ZERO 0
#define HNS_SIG0_ALG 253

int
hns_sig0_has_sig(const unsigned char *wire, size_t wire_len);

int
hns_sig0_get_sig(
  const unsigned char *wire,
  size_t wire_len,
  unsigned char *sig,
  unsigned int *tag
);

int
hns_sig0_sighash(
  const unsigned char *wire,
  size_t wire_len,
  unsigned char *hash
);

int
hns_sig0_verify(
  hns_ec_t *ec,
  const unsigned char *pubkey,
  const unsigned char *wire,
  size_t wire_len
);
#endif
