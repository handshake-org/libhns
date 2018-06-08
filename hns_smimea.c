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

#include <assert.h>
#include "hns_setup.h"
#include "hns.h"
#include "hns_private.h"
#include "hns_dane.h"
#include "hns_sha256.h"

static char
to_char(uint8_t n) {
  if (n >= 0x00 && n <= 0x09)
    return n + '0';

  if (n >= 0x0a && n <= 0x0f)
    return (n - 10) + 'a';

  return -1;
}

static int
encode_hex(unsigned char *data, size_t data_len, char *str) {
  if (data == NULL && data_len != 0)
    return 0;

  if (str == NULL)
    return 0;

  size_t size = data_len << 1;

  int i;
  int p = 0;
  char ch;

  for (i = 0; i < size; i++) {
    if (i & 1) {
      ch = to_char(data[p] & 15);
      p += 1;
    } else {
      ch = to_char(data[p] >> 4);
    }

    if (ch == -1)
      return 0;

    str[i] = ch;
  }

  str[i] = '\0';

  return 1;
}

int
hns_smimea_encode_name(
  const char *name,
  const char *email,
  char *out,
  size_t out_len
) {
  if (name == NULL || email == NULL)
    return 0;

  size_t size = hns_smimea_name_size(name, email);

  if (size > out_len)
    return 0;

  unsigned char hash[32];
  char hex[57];

  hns_sha256_ctx ctx;
  hns_sha256_init(&ctx);
  hns_sha256_update(&ctx, email, strlen(email));
  hns_sha256_final(&ctx, hash);

  assert(encode_hex(hash, 28, hex) == 1);

  return sprintf(out, "%s._smimea.%s", hex, name);
}

size_t
hns_smimea_name_size(const char *name, const char *email) {
  return 56 + 1 + 1 + 6 + 1 + strlen(name);
}

int
hns_smimea_verify(
  struct hns_smimea_reply *smimea_reply,
  unsigned char *cert,
  size_t cert_len
) {
  return hns_dane_verify(smimea_reply, cert, cert_len);
}
