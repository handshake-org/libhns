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

#include "hns_setup.h"
#include "hns.h"
#include "hns_private.h"
#include "hns_dane.h"

int
hns_tlsa_encode_name(
  const char *name,
  const char *protocol,
  unsigned int port,
  char *out,
  size_t out_len
) {
  if (name == NULL || protocol == NULL || out == NULL)
    return 0;

  size_t size = hns_tlsa_name_size(name, protocol, port);

  if (size > out_len)
    return 0;

  if (strlen(protocol) > 62)
    return 0;

  port &= 0xffff;

  return sprintf(out, "_%u._%s.%s", port, protocol, name);
}

size_t
hns_tlsa_name_size(const char *name, const char *protocol, unsigned int port) {
  size_t size = 5;

  port &= 0xffff;

  if (port < 10)
    size = 1;
  else if (port < 100)
    size = 2;
  else if (port < 1000)
    size = 3;
  else if (port < 10000)
    size = 4;

  return 1 + size + 1 + 1 + strlen(protocol) + 1 + strlen(name);
}

int
hns_tlsa_verify(
  struct hns_tlsa_reply *tlsa_reply,
  const unsigned char *cert,
  size_t cert_len
) {
  return hns_dane_verify(tlsa_reply, cert, cert_len);
}
