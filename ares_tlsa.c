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

int
ares_tlsa_encode_name(
  const char *name,
  const char *protocol,
  unsigned int port,
  char *out,
  size_t out_len
) {
  size_t size = ares_tlsa_name_size(name, protocol, port);

  if (size > out_len)
    return 0;

  return sprintf(out, "_%u._%s.%s", port, protocol, name);
}

size_t
ares_tlsa_name_size(const char *name, const char *protocol, unsigned int port) {
  return 1 + 5 + 1 + 1 + strlen(protocol) + 1 + strlen(name);
}

int
ares_tlsa_verify(
  struct ares_tlsa_reply *tlsa_reply,
  unsigned char *cert,
  size_t cert_len
) {
  return ares_dane_verify(tlsa_reply, cert, cert_len);
}
