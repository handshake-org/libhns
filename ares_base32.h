#ifndef HEADER_CARES_BASE32_H
#define HEADER_CARES_BASE32_H

#include <stdlib.h>

int
ares_base32_encode(unsigned char *data, size_t data_len, char *out, int pad);

int
ares_base32_encode_hex(
  unsigned char *data,
  size_t data_len,
  char *out,
  int pad
);

int
ares_base32_encode_size(unsigned char *data, size_t data_len, int pad);

int
ares_base32_encode_hex_size(unsigned char *data, size_t data_len, int pad);

int
ares_base32_decode(char *str, unsigned char *out, int unpad);

int
ares_base32_decode_hex(char *str, unsigned char *out, int unpad);

int
ares_base32_decode_size(char *str);

int
ares_base32_decode_hex_size(char *str, unsigned char *out);

int
ares_base32_test(char *str, int unpad);

int
ares_base32_test_hex(char *str, int unpad);
#endif
