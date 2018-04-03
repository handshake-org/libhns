
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2009 by Jakub Hrozek <jhrozek@redhat.com>
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "ares_setup.h"
#include "ares.h"
#include "ares_private.h"
#include "ares_sha1.h"
#include "ares_sha256.h"

int
ares_sshfp_verify(
  struct ares_sshfp_reply *sshfp_reply,
  unsigned char *key,
  size_t key_len
) {
  if (sshfp_reply == NULL || key == NULL)
    return 0;

  unsigned char buf[32];
  unsigned char *hash = NULL;
  size_t hash_len = 0;

  switch (sshfp_reply->digest_type) {
    case 1: { /* SHA1 */
      ares_sha1_ctx ctx;
      ares_sha1_init(&ctx);
      ares_sha1_update(&ctx, key, key_len);
      ares_sha1_final(&ctx, &buf[0]);
      hash = &buf[0];
      hash_len = 20;
      break;
    }
    case 2: { /* SHA256 */
      ares_sha256_ctx ctx;
      ares_sha256_init(&ctx);
      ares_sha256_update(&ctx, key, key_len);
      ares_sha256_final(&ctx, &buf[0]);
      hash = &buf[0];
      hash_len = 32;
      break;
    }
  }

  if (!hash)
    return 0;

  if (hash_len != sshfp_reply->fingerprint_len)
    return 0;

  return memcmp(hash, sshfp_reply->fingerprint, hash_len) == 0;
}
