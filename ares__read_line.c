
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
#include "hns_nowarn.h"
#include "hns_private.h"

/* This is an internal function.  Its contract is to read a line from
 * a file into a dynamically allocated buffer, zeroing the trailing
 * newline if there is one.  The calling routine may call
 * hns__read_line multiple times with the same buf and bufsize
 * pointers; *buf will be reallocated and *bufsize adjusted as
 * appropriate.  The initial value of *buf should be NULL.  After the
 * calling routine is done reading lines, it should free *buf.
 */
int hns__read_line(FILE *fp, char **buf, size_t *bufsize)
{
  char *newbuf;
  size_t offset = 0;
  size_t len;

  if (*buf == NULL)
    {
      *buf = hns_malloc(128);
      if (!*buf)
        return HNS_ENOMEM;
      *bufsize = 128;
    }

  for (;;)
    {
      int bytestoread = hnsx_uztosi(*bufsize - offset);

      if (!fgets(*buf + offset, bytestoread, fp))
        return (offset != 0) ? 0 : (ferror(fp)) ? HNS_EFILE : HNS_EOF;
      len = offset + strlen(*buf + offset);
      if ((*buf)[len - 1] == '\n')
        {
          (*buf)[len - 1] = 0;
          break;
        }
      offset = len;
      if(len < *bufsize - 1)
        continue;

      /* Allocate more space. */
      newbuf = hns_realloc(*buf, *bufsize * 2);
      if (!newbuf)
        {
          hns_free(*buf);
          *buf = NULL;
          return HNS_ENOMEM;
        }
      *buf = newbuf;
      *bufsize *= 2;
    }
  return HNS_SUCCESS;
}
