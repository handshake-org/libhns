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
#include "ares_dane.h"
#include "ares_sha256.h"

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
ares_smimea_encode_name(
  const char *name,
  const char *email,
  char *out,
  size_t out_len
) {
  char hex[57];

  if (out) {
    size_t size = ares_smimea_encode_name(name, email, NULL, 0);

    if (size > out_len)
      return 0;

    unsigned char hash[32];

    ares_sha256_ctx ctx;
    ares_sha256_init(&ctx);
    ares_sha256_update(&ctx, email, strlen(email));
    ares_sha256_final(&ctx, hash);

    encode_hex(hash, 28, hex);
  } else {
    memset(hex, '0', sizeof(hex) - 1);
    hex[56] = '\0';
  }

  return sprintf(out, "_%s._smimea.%s", hex, name);
}

size_t
ares_smimea_name_size(
  const char *name,
  const char *email
) {
  return ares_smimea_encode_name(name, email, NULL, 0);
}

int
ares_smimea_verify(
  struct ares_smimea_reply *smimea_reply,
  unsigned char *cert,
  size_t cert_len
) {
  return ares_dane_verify(smimea_reply, cert, cert_len);
}
