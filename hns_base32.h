#ifndef HEADER_HNS_BASE32_H
#define HEADER_HNS_BASE32_H

#include <stdlib.h>

int
hns_base32_encode(
  const unsigned char *data,
  size_t data_len,
  char *out,
  int pad
);

int
hns_base32_encode_hex(
  const unsigned char *data,
  size_t data_len,
  char *out,
  int pad
);

int
hns_base32_encode_size(const unsigned char *data, size_t data_len, int pad);

int
hns_base32_encode_hex_size(const unsigned char *data, size_t data_len, int pad);

int
hns_base32_decode(const char *str, unsigned char *out, int unpad);

int
hns_base32_decode_hex(const char *str, unsigned char *out, int unpad);

int
hns_base32_decode_size(const char *str);

int
hns_base32_decode_hex_size(const char *str, unsigned char *out);

int
hns_base32_test(const char *str, int unpad);

int
hns_base32_test_hex(const char *str, int unpad);
#endif
