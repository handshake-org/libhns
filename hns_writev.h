#ifndef HEADER_HNS_WRITEV_H
#define HEADER_HNS_WRITEV_H


/* Copyright 1998 by the Massachusetts Institute of Technology.
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

#ifndef HAVE_WRITEV

/* Structure for scatter/gather I/O. */
struct iovec
{
  void *iov_base;  /* Pointer to data. */
  size_t iov_len;  /* Length of data.  */
};

extern hns_ssize_t hns_writev(hns_socket_t s, const struct iovec *iov, int iovcnt);

#endif

#endif /* HEADER_HNS_WRITEV_H */