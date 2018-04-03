/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/
#ifndef HEADER_HNS_BLAKE2B_H
#define HEADER_HNS_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#define HNS_BLAKE2_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define HNS_BLAKE2_PACKED(x) x __attribute__((packed))
#endif

#if defined(__cplusplus)
extern "C" {
#endif
  enum hns_blake2b_constant
  {
    HNS_BLAKE2B_BLOCKBYTES = 128,
    HNS_BLAKE2B_OUTBYTES   = 64,
    HNS_BLAKE2B_KEYBYTES   = 64,
    HNS_BLAKE2B_SALTBYTES  = 16,
    HNS_BLAKE2B_PERSONALBYTES = 16
  };

  typedef struct hns_blake2b_ctx__
  {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[HNS_BLAKE2B_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
  } hns_blake2b_ctx;

  HNS_BLAKE2_PACKED(struct hns_blake2b_param__
  {
    uint8_t  digest_length; /* 1 */
    uint8_t  key_length;    /* 2 */
    uint8_t  fanout;        /* 3 */
    uint8_t  depth;         /* 4 */
    uint32_t leaf_length;   /* 8 */
    uint32_t node_offset;   /* 12 */
    uint32_t xof_length;    /* 16 */
    uint8_t  node_depth;    /* 17 */
    uint8_t  inner_length;  /* 18 */
    uint8_t  reserved[14];  /* 32 */
    uint8_t  salt[HNS_BLAKE2B_SALTBYTES]; /* 48 */
    uint8_t  personal[HNS_BLAKE2B_PERSONALBYTES];  /* 64 */
  });

  typedef struct hns_blake2b_param__ hns_blake2b_param;

  /* Padded structs result in a compile-time error */
  enum {
    HNS_BLAKE2_DUMMY_1 = 1/(sizeof(hns_blake2b_param) == HNS_BLAKE2B_OUTBYTES)
  };

  /* Streaming API */
  int hns_blake2b_init( hns_blake2b_ctx *S, size_t outlen );
  int hns_blake2b_init_key( hns_blake2b_ctx *S, size_t outlen, const void *key, size_t keylen );
  int hns_blake2b_init_param( hns_blake2b_ctx *S, const hns_blake2b_param *P );
  int hns_blake2b_update( hns_blake2b_ctx *S, const void *in, size_t inlen );
  int hns_blake2b_final( hns_blake2b_ctx *S, void *out, size_t outlen );

  /* Simple API */
  int hns_blake2b( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

#if defined(__cplusplus)
}
#endif

#endif
