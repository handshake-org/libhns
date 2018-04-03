/* sha1.h */
#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define sha1_block_size 64
#define sha1_hash_size  20

/* algorithm context */
typedef struct hns_sha1_ctx
{
	unsigned char message[sha1_block_size]; /* 512-bit buffer for leftovers */
	uint64_t length;   /* number of processed bytes */
	unsigned hash[5];  /* 160-bit algorithm internal hashing state */
} hns_sha1_ctx;

/* hash functions */

void hns_sha1_init(hns_sha1_ctx *ctx);
void hns_sha1_update(hns_sha1_ctx *ctx, const unsigned char* msg, size_t size);
void hns_sha1_final(hns_sha1_ctx *ctx, unsigned char* result);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SHA1_H */
