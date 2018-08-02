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
hns_smimea_encode_email(
  const char *email,
  char *out,
  size_t out_len
) {
  return hns_dane_encode_email("smimecert", email, out, out_len);
}

int
hns_smimea_encode_name(
  const char *name,
  const char *local,
  char *out,
  size_t out_len
) {
  return hns_dane_encode_name("smimecert", name, local, out, out_len);
}

size_t
hns_smimea_email_size(const char *email) {
  return hns_dane_email_size("smimecert", email);
}

size_t
hns_smimea_name_size(const char *name) {
  return hns_dane_name_size("smimecert", name);
}

int
hns_smimea_verify(
  struct hns_smimea_reply *smimea_reply,
  const unsigned char *cert,
  size_t cert_len
) {
  return hns_dane_verify(smimea_reply, cert, cert_len);
}
