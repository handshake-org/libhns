

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

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#include "hns.h"
#include "hns_private.h"

#ifndef HAVE_WRITEV
hns_ssize_t hns_writev(hns_socket_t s, const struct iovec *iov, int iovcnt)
{
  char *buffer, *bp;
  int i;
  size_t bytes = 0;
  hns_ssize_t result;

  /* Validate iovcnt */
  if (iovcnt <= 0)
  {
    SET_ERRNO(EINVAL);
    return (-1);
  }

  /* Validate and find the sum of the iov_len values in the iov array */
  for (i = 0; i < iovcnt; i++)
  {
    if (iov[i].iov_len > INT_MAX - bytes)
    {
      SET_ERRNO(EINVAL);
      return (-1);
    }
    bytes += iov[i].iov_len;
  }

  if (bytes == 0)
    return (0);

  /* Allocate a temporary buffer to hold the data */
  buffer = hns_malloc(bytes);
  if (!buffer)
  {
    SET_ERRNO(ENOMEM);
    return (-1);
  }

  /* Copy the data into buffer */
  for (bp = buffer, i = 0; i < iovcnt; ++i)
  {
    memcpy (bp, iov[i].iov_base, iov[i].iov_len);
    bp += iov[i].iov_len;
  }

  /* Send buffer contents */
  result = swrite(s, buffer, bytes);

  hns_free(buffer);

  return (result);
}
#endif

