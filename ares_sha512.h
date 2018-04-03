/* sha.h sha512 and sha384 hash functions */
#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define sha512_block_size 128
#define sha512_hash_size  64
#define sha384_hash_size  48

/* algorithm context */
typedef struct hns_sha512_ctx
{
	uint64_t message[16];   /* 1024-bit buffer for leftovers */
	uint64_t length;        /* number of processed bytes */
	uint64_t hash[8];       /* 512-bit algorithm internal hashing state */
	unsigned digest_length; /* length of the algorithm digest in bytes */
} hns_sha512_ctx;

void hns_sha384_init(hns_sha512_ctx *ctx);
void hns_sha512_init(hns_sha512_ctx *ctx);
void hns_sha512_update(hns_sha512_ctx *ctx, const unsigned char* data, size_t length);
void hns_sha512_final(hns_sha512_ctx *ctx, unsigned char* result);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SHA512_H */
