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

#ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
#else
#  include "nameser.h"
#endif
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#  include <arpa/nameser_compat.h>
#endif

#include "hns.h"
#include "hns_private.h"
#include "hns_dane.h"

/* AIX portability check */
#ifndef T_TLSA
#  define T_TLSA 52
#endif

int
hns_parse_tlsa_reply (const unsigned char *abuf, int alen,
                      struct hns_tlsa_reply **tlsa_out)
{
  return hns_parse_dane_reply(abuf, alen, tlsa_out, T_TLSA);
}
