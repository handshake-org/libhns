#ifndef HEADER_HNS_SHA256_H
#define HEADER_HNS_SHA256_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define hns_sha256_block_size 64
#define hns_sha256_hash_size  32

/* algorithm context */
typedef struct hns_sha256_ctx
{
	unsigned message[16];   /* 512-bit buffer for leftovers */
	uint64_t length;        /* number of processed bytes */
	unsigned hash[8];       /* 256-bit algorithm internal hashing state */
	unsigned digest_length; /* length of the algorithm digest in bytes */
} hns_sha256_ctx;

void hns_sha256_init(hns_sha256_ctx *ctx);
void hns_sha256_update(hns_sha256_ctx *ctx, const unsigned char* data, size_t length);
void hns_sha256_final(hns_sha256_ctx *ctx, unsigned char result[32]);

#ifdef __cplusplus
}
#endif

#endif
